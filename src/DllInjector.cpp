#include "DllInjector.h"

#if defined(Q_OS_WIN)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <shlobj.h>

#include <QDir>
#include <QFileInfo>

namespace {

QString formatWin32Error(DWORD e)
{
    if (e == 0) {
        return QString();
    }
    wchar_t* buf = nullptr;
    const DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
                                       | FORMAT_MESSAGE_IGNORE_INSERTS,
                                   nullptr, e, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                   reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    QString out;
    if (n != 0 && buf != nullptr) {
        out = QString::fromWCharArray(buf).trimmed();
    }
    if (buf != nullptr) {
        LocalFree(buf);
    }
    return out.isEmpty() ? QStringLiteral("(sin descripción Win32)") : out;
}

} // namespace

bool winIsElevatedAdministrator()
{
    return IsUserAnAdmin() != FALSE;
}

quint32 winFindPidByExeName(const QString& exeFileName)
{
    if (exeFileName.isEmpty()) {
        return 0;
    }
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    quint32 found = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (QString::fromWCharArray(pe.szExeFile).compare(exeFileName, Qt::CaseInsensitive) == 0) {
                found = static_cast<quint32>(pe.th32ProcessID);
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

bool winInjectDllIntoProcess(quint32 pid, const QString& dllAbsolutePath, QString* errorOut)
{
    if (errorOut != nullptr) {
        errorOut->clear();
    }
    if (pid == 0) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("PID inválido.");
        }
        return false;
    }
    const QString norm = QDir::toNativeSeparators(QFileInfo(dllAbsolutePath).absoluteFilePath());
    if (norm.isEmpty() || !QFileInfo::exists(norm)) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("La ruta de la DLL no existe: ") + dllAbsolutePath;
        }
        return false;
    }

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION
                                   | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, static_cast<DWORD>(pid));
    if (hProc == nullptr) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("OpenProcess falló (¿administrador?). Código: %1")
                            .arg(QString::number(static_cast<qulonglong>(GetLastError())));
        }
        return false;
    }

    const std::wstring wpath = norm.toStdWString();
    const QFileInfo dllFi(norm);
    const QString dllDir = dllFi.absolutePath();

    // No cargar la DLL aquí: instala hooks en este proceso y un FreeLibrary rápido deja trampas ↔
    // «DofusRedirect.dll_unloaded» en dofus_process_sniffer.exe.

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (k32 == nullptr) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("kernel32.dll no mapeado.");
        }
        CloseHandle(hProc);
        return false;
    }
    auto* const pLoadLibraryW =
        reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(k32, "LoadLibraryW"));
    if (pLoadLibraryW == nullptr) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("GetProcAddress(LoadLibraryW) falló.");
        }
        CloseHandle(hProc);
        return false;
    }

    auto remoteLoadLibraryW = [&](const std::wstring& modulePath, DWORD* exitCodeOut) -> bool {
        if (exitCodeOut != nullptr) {
            *exitCodeOut = 0;
        }
        const SIZE_T sz = (modulePath.size() + 1U) * sizeof(wchar_t);
        void* remote = VirtualAllocEx(hProc, nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (remote == nullptr) {
            return false;
        }
        if (!WriteProcessMemory(hProc, remote, modulePath.data(), sz, nullptr)) {
            VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
            return false;
        }
        HANDLE thr = CreateRemoteThread(hProc, nullptr, 0, pLoadLibraryW, remote, 0, nullptr);
        if (thr == nullptr) {
            VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
            return false;
        }
        WaitForSingleObject(thr, 15000);
        DWORD exitCode = 0;
        GetExitCodeThread(thr, &exitCode);
        CloseHandle(thr);
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        if (exitCodeOut != nullptr) {
            *exitCodeOut = exitCode;
        }
        return true;
    };

    // Precarga runtime MinGW junto a la DLL objetivo para evitar error 126 en remoto.
    const QStringList runtimeDlls = {QStringLiteral("libgcc_s_seh-1.dll"),
                                     QStringLiteral("libstdc++-6.dll"),
                                     QStringLiteral("libwinpthread-1.dll")};
    QStringList depWarnings;
    for (const QString& depName : runtimeDlls) {
        const QString depPath = QDir(dllDir).absoluteFilePath(depName);
        if (!QFileInfo::exists(depPath)) {
            continue;
        }
        const std::wstring wdep = QDir::toNativeSeparators(depPath).toStdWString();
        DWORD depExit = 0;
        if (!remoteLoadLibraryW(wdep, &depExit)) {
            depWarnings << QStringLiteral("[INJECT] AVISO: no se pudo precargar dependencia remota: %1")
                               .arg(QDir::toNativeSeparators(depPath));
            continue;
        }
        if (depExit == 0) {
            depWarnings << QStringLiteral(
                               "[INJECT] AVISO: dependencia remota no cargó: %1 "
                               "(se continuará con la DLL principal)")
                               .arg(QDir::toNativeSeparators(depPath));
        }
    }
    DWORD exitCode = 0;
    if (!remoteLoadLibraryW(wpath, &exitCode)) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("CreateRemoteThread/LoadLibraryW falló para DLL principal: %1")
                            .arg(QString::number(static_cast<qulonglong>(GetLastError())));
        }
        CloseHandle(hProc);
        return false;
    }
    CloseHandle(hProc);

    if (exitCode == 0) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral(
                "[INJECT] LoadLibraryW en el proceso remoto devolvió NULL.\n"
                "Bitness (EXE 64 / DLL 64), dependencias MinGW junto a la DLL si aplica, antivirus o permisos.\n"
                "Códigos de LoadLibrary típicos: 126 = DLL o dependencias no encontradas junto al .exe/Dofus; "
                "1114 = inicialización rechazada (DllMain FALSE, p.ej. MinHook/connect falló).\n"
                "Revisa C:\\dofus_dll_log.txt (OutputDebugString + archivo). Si no se creó, la DLL puede no haber "
                "llegado a escribir o DllMain falló muy pronto.");
        }
        return false;
    }
    if (errorOut != nullptr && !depWarnings.isEmpty()) {
        *errorOut = depWarnings.join(QLatin1Char('\n'));
    }
    return true;
}

#endif
