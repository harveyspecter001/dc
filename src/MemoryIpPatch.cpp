#include "MemoryIpPatch.h"

#if defined(Q_OS_WIN)


#include <algorithm>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <shlobj.h>

bool winIsElevatedAdministrator()
{
    return IsUserAnAdmin() != FALSE;
}

namespace {

constexpr SIZE_T kReadChunkBytes = 2 * 1024 * 1024;

/// Cualquier región COMMIT salvo guard/noaccess (más permisivo: intenta leer también tipos raros de Win10/11).
bool protectInteresting(DWORD prot)
{
    if (prot & PAGE_GUARD) {
        return false;
    }
    const DWORD t = prot & 0xFFU;
    if (t == PAGE_NOACCESS) {
        return false;
    }
    return true;
}

void readRegionChunk(HANDLE proc, uintptr_t regionBase, SIZE_T regionSize, int overlap,
                     QVector<quintptr>* hits, const quint8* needle, int needleLen)
{
    if (needleLen < 1 || overlap < 0) {
        return;
    }
    QVector<char> buf;
    for (SIZE_T chunkStart = 0; chunkStart < regionSize; chunkStart += static_cast<SIZE_T>(kReadChunkBytes - static_cast<SIZE_T>(overlap))) {
        const SIZE_T maxRead = regionSize - chunkStart;
        const SIZE_T want = (maxRead < kReadChunkBytes) ? maxRead : kReadChunkBytes;
        const int bi = static_cast<int>(want);
        if (bi < needleLen) {
            break;
        }
        buf.resize(bi);
        SIZE_T got = 0;
        if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(regionBase + chunkStart), buf.data(),
                               static_cast<SIZE_T>(bi), &got)
            || got < static_cast<SIZE_T>(needleLen)) {
            break;
        }
        const int limit = static_cast<int>(got) - needleLen;
        for (int i = 0; i <= limit; ++i) {
            const unsigned char* p = reinterpret_cast<const unsigned char*>(buf.constData() + i);
            bool match = true;
            for (int k = 0; k < needleLen; ++k) {
                if (p[static_cast<unsigned>(k)] != needle[static_cast<unsigned>(k)]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                hits->push_back(regionBase + chunkStart + static_cast<quintptr>(i));
            }
        }
    }
}

void collectHitsForPattern(HANDLE proc, const quint8* needle, int needleLen, QVector<quintptr>* hits)
{
    const int overlap = needleLen > 1 ? needleLen - 1 : 0;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t addr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    const uintptr_t vmax = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    while (addr < vmax) {
        MEMORY_BASIC_INFORMATION mbi{};
        const SIZE_T q = VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
        if (q == 0) {
            break;
        }
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress)
            + static_cast<quintptr>(mbi.RegionSize);
        if (mbi.State == MEM_COMMIT && protectInteresting(mbi.Protect) && mbi.RegionSize > 0) {
            const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            readRegionChunk(proc, base, static_cast<SIZE_T>(mbi.RegionSize), overlap, hits, needle, needleLen);
        }
        if (next <= addr) {
            break;
        }
        addr = next;
    }
}

bool patchAt(HANDLE proc, uintptr_t hitAddr, const quint8 replacement[4], QByteArray* prevOut, QString* err)
{
    uchar cur[4]{};
    SIZE_T got = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(hitAddr), cur, 4, &got) || got != 4) {
        if (err) {
            *err = QStringLiteral("ReadProcessMemory falló al leer antes de parchear.");
        }
        return false;
    }
    *prevOut = QByteArray(reinterpret_cast<const char*>(cur), 4);

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(hitAddr), &mbi, sizeof(mbi)) == 0) {
        if (err) {
            *err = QStringLiteral("VirtualQueryEx falló en la dirección del parche.");
        }
        return false;
    }

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const SIZE_T psz = si.dwPageSize;
    const uintptr_t pageBase = hitAddr & ~(static_cast<uintptr_t>(psz) - 1U);

    DWORD oldProt = 0;
    if (!VirtualProtectEx(proc, reinterpret_cast<LPVOID>(pageBase), psz, PAGE_EXECUTE_READWRITE, &oldProt)) {
        if (err) {
            *err = QStringLiteral("VirtualProtectEx (pre-escritura) falló: %1")
                       .arg(QString::number(static_cast<qulonglong>(GetLastError())));
        }
        return false;
    }

    SIZE_T written = 0;
    const bool ok =
        WriteProcessMemory(proc, reinterpret_cast<LPVOID>(hitAddr), replacement, 4, &written) && written == 4;

    DWORD ignored = 0;
    VirtualProtectEx(proc, reinterpret_cast<LPVOID>(pageBase), psz, oldProt, &ignored);

    if (!ok && err) {
        *err = QStringLiteral("WriteProcessMemory falló: %1")
                   .arg(QString::number(static_cast<qulonglong>(GetLastError())));
    }
    return ok;
}

bool restoreAt(HANDLE proc, uintptr_t hitAddr, const QByteArray& original, QString* err)
{
    if (original.size() != 4) {
        if (err) {
            *err = QStringLiteral("Entrada de restauración inválida (no son 4 bytes).");
        }
        return false;
    }

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const SIZE_T psz = si.dwPageSize;
    const uintptr_t pageBase = hitAddr & ~(static_cast<uintptr_t>(psz) - 1U);

    DWORD oldProt = 0;
    if (!VirtualProtectEx(proc, reinterpret_cast<LPVOID>(pageBase), psz, PAGE_EXECUTE_READWRITE, &oldProt)) {
        if (err) {
            *err = QStringLiteral("VirtualProtectEx (restauración) falló.");
        }
        return false;
    }

    SIZE_T written = 0;
    const bool ok = WriteProcessMemory(proc, reinterpret_cast<LPVOID>(hitAddr), original.constData(), 4, &written)
                    && written == 4;

    DWORD ignored = 0;
    VirtualProtectEx(proc, reinterpret_cast<LPVOID>(pageBase), psz, oldProt, &ignored);

    if (!ok && err) {
        *err = QStringLiteral("WriteProcessMemory al restaurar falló.");
    }
    return ok;
}

} // namespace

bool memoryIpv4PatchesApply(quint32 pid, const quint8 targetIpv4[4], const quint8 replacementIpv4[4],
                            quint16 relatedPortLittleEndian, QVector<QPair<quintptr, QByteArray>>* undoOut,
                            QString* errorMessage)
{
    if (undoOut == nullptr) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("undoOut es nulo.");
        }
        return false;
    }
    undoOut->clear();

    HANDLE proc =
        OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE,
                    static_cast<DWORD>(pid));
    if (!proc) {
        if (errorMessage) {
            *errorMessage =
                QStringLiteral("OpenProcess falló (PID %1). Ejecuta como administrador ¿y bitness correcto (x86/x64)? "
                               "Error: %2")
                    .arg(pid)
                    .arg(QString::number(static_cast<qulonglong>(GetLastError())));
        }
        return false;
    }

    quint8 revTgt[4]{
        targetIpv4[3], targetIpv4[2], targetIpv4[1], targetIpv4[0],
    };
    quint8 revRep[4]{
        replacementIpv4[3],
        replacementIpv4[2],
        replacementIpv4[1],
        replacementIpv4[0],
    };

    QVector<quintptr> hits;
    collectHitsForPattern(proc, targetIpv4, 4, &hits);
    collectHitsForPattern(proc, revTgt, 4, &hits);

    if (relatedPortLittleEndian != 0) {
        quint8 ipPortLe[6];
        for (int i = 0; i < 4; ++i) {
            ipPortLe[i] = targetIpv4[static_cast<unsigned>(i)];
        }
        ipPortLe[4] = static_cast<quint8>(relatedPortLittleEndian & 0xffU);
        ipPortLe[5] = static_cast<quint8>((relatedPortLittleEndian >> 8) & 0xffU);
        collectHitsForPattern(proc, ipPortLe, 6, &hits);

        quint8 ipPortBe[6];
        for (int i = 0; i < 4; ++i) {
            ipPortBe[i] = targetIpv4[static_cast<unsigned>(i)];
        }
        ipPortBe[4] = static_cast<quint8>((relatedPortLittleEndian >> 8) & 0xffU);
        ipPortBe[5] = static_cast<quint8>(relatedPortLittleEndian & 0xffU);
        collectHitsForPattern(proc, ipPortBe, 6, &hits);

        /* sockaddr_in: sin_port (network order) inmediatamente delante de sin_addr (orden de octetos Windows). */
        quint8 portThenIpv4[6];
        portThenIpv4[0] = static_cast<quint8>((relatedPortLittleEndian >> 8) & 0xffU);
        portThenIpv4[1] = static_cast<quint8>(relatedPortLittleEndian & 0xffU);
        for (int i = 0; i < 4; ++i) {
            portThenIpv4[2 + static_cast<unsigned>(i)] = targetIpv4[static_cast<unsigned>(i)];
        }
        QVector<quintptr> sockaddrHits;
        collectHitsForPattern(proc, portThenIpv4, 6, &sockaddrHits);
        for (uintptr_t h : sockaddrHits) {
            hits.push_back(h + 2);
        }
    }

    std::sort(hits.begin(), hits.end());
    hits.erase(std::unique(hits.begin(), hits.end()), hits.end());

    if (hits.isEmpty()) {
        CloseHandle(proc);
        undoOut->clear();
        if (errorMessage) {
            *errorMessage = QStringLiteral("Ninguna coincidencia en RAM para patrones IPv4/puerto de este servidor.");
        }
        return false;
    }

    QVector<QPair<quintptr, QByteArray>> staged;
    staged.reserve(hits.size());
    QString lastErr;

    auto bytesEqual4 = [](const uchar* a, const quint8* b) {
        return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
    };

    for (uintptr_t hitAddr : hits) {
        uchar cur[4]{};
        SIZE_T got = 0;
        if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(hitAddr), cur, 4, &got) || got != 4) {
            continue;
        }

        const quint8* replBytes = nullptr;
        if (bytesEqual4(cur, targetIpv4)) {
            replBytes = replacementIpv4;
        } else if (bytesEqual4(cur, revTgt)) {
            replBytes = revRep;
        } else {
            continue;
        }

        QByteArray prev;
        if (!patchAt(proc, hitAddr, replBytes, &prev, &lastErr)) {
            for (auto it = staged.crbegin(); it != staged.crend(); ++it) {
                QString ign;
                restoreAt(proc, it->first, it->second, &ign);
            }
            CloseHandle(proc);
            if (errorMessage) {
                *errorMessage = lastErr;
            }
            undoOut->clear();
            return false;
        }
        staged.append(qMakePair(static_cast<quintptr>(hitAddr), prev));
    }

    if (staged.isEmpty()) {
        CloseHandle(proc);
        undoOut->clear();
        if (errorMessage) {
            *errorMessage =
                QStringLiteral("Hubo direcciones candidatas pero ninguna coincidía con la IPv4/puerto buscados.");
        }
        return false;
    }

    CloseHandle(proc);
    *undoOut = std::move(staged);
    return true;
}

bool memoryIpv4PatchesRestore(quint32 pid, const QVector<QPair<quintptr, QByteArray>>& undo, QString* errorMessage)
{
    if (undo.isEmpty()) {
        return true;
    }

    HANDLE proc =
        OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE,
                    static_cast<DWORD>(pid));
    if (!proc) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("OpenProcess al restaurar falló (¿proceso terminado?): %1")
                                .arg(QString::number(static_cast<qulonglong>(GetLastError())));
        }
        return false;
    }

    QString lastErr;
    bool allOk = true;
    for (const auto& e : undo) {
        if (!restoreAt(proc, e.first, e.second, &lastErr)) {
            allOk = false;
        }
    }
    CloseHandle(proc);
    if (!allOk && errorMessage) {
        *errorMessage = lastErr;
    }
    return allOk;
}

bool memoryReadIpv4QuadAt(quint32 pid, quintptr address, quint8 outOctets[4], QString* errorMessage)
{
    if (outOctets == nullptr) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Salida nula.");
        }
        return false;
    }

    HANDLE proc =
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!proc) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("OpenProcess (solo lectura) PID %1: %2")
                                .arg(pid)
                                .arg(QString::number(static_cast<qulonglong>(GetLastError())));
        }
        return false;
    }

    UCHAR buf[4]{};
    SIZE_T got = 0;
    const bool ok =
        ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(address), buf, sizeof(buf), &got) && got == 4;
    CloseHandle(proc);
    if (!ok) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("ReadProcessMemory falló.");
        }
        return false;
    }

    outOctets[0] = static_cast<quint8>(buf[0]);
    outOctets[1] = static_cast<quint8>(buf[1]);
    outOctets[2] = static_cast<quint8>(buf[2]);
    outOctets[3] = static_cast<quint8>(buf[3]);
    return true;
}

QString memoryIpv4PatchesReadbackSummary(quint32 pid, const QVector<QPair<quintptr, QByteArray>>& sites,
                                           QString* errorMessage)
{
    if (sites.isEmpty()) {
        return QStringLiteral("— Sin sitios registrados.");
    }

    HANDLE proc =
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!proc) {
        if (errorMessage) {
            *errorMessage =
                QStringLiteral("OpenProcess PID %1: %2")
                    .arg(pid)
                    .arg(QString::number(static_cast<qulonglong>(GetLastError())));
        }
        return QStringLiteral("— No se pudo abrir proceso.");
    }

    auto siteLooksLikeLoopback = [](const UCHAR cur[4]) -> bool {
        if (cur[0] == 127 && cur[1] == 0 && cur[2] == 0 && cur[3] == 1) {
            return true;
        }
        // Muchos clientes guardan IPv4 como uint32 LE: 127.0.0.1 → bytes 01 00 00 7F (antes «1.0.0.127»).
        return cur[0] == 1 && cur[1] == 0 && cur[2] == 0 && cur[3] == static_cast<UCHAR>(127);
    };

    auto humanIpFromRam = [&](const UCHAR cur[4]) -> QString {
        if (siteLooksLikeLoopback(cur)) {
            return QStringLiteral("127.0.0.1");
        }
        return QStringLiteral("%1.%2.%3.%4")
            .arg(cur[0])
            .arg(cur[1])
            .arg(cur[2])
            .arg(cur[3]);
    };

    int okMatches = 0;
    QString sampleRead;

    for (const auto& slot : sites) {
        UCHAR cur[4]{};
        SIZE_T got = 0;
        const bool rr = ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(slot.first), cur, sizeof(cur), &got)
                        && got == 4;
        if (!rr) {
            continue;
        }
        const QString ipv4txt = humanIpFromRam(cur);
        if (sampleRead.isEmpty()) {
            sampleRead = ipv4txt;
        }
        if (siteLooksLikeLoopback(cur)) {
            ++okMatches;
        }
    }

    CloseHandle(proc);

    const int total = sites.size();
    if (total == 0) {
        return QStringLiteral("—");
    }

    const QString samp = sampleRead.isEmpty() ? QStringLiteral("(no leíble)") : sampleRead;

    if (okMatches == total && total > 0) {
        return QStringLiteral("<b>%1</b> — coherente (127.0.0.1) en los %2 sitios leídos.").arg(samp).arg(total);
    }

    return QStringLiteral("<b>%1</b> — loopback coherentes %2/%3 (resto distinto o no leídos).")
        .arg(samp)
        .arg(okMatches)
        .arg(total);
}

#endif // Q_OS_WIN
