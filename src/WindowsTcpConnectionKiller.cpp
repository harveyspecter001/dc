#include "WindowsTcpConnectionKiller.h"

#if defined(Q_OS_WIN)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <vector>

#ifndef MIB_TCP_STATE_DELETE_TCB
#define MIB_TCP_STATE_DELETE_TCB 12
#endif

namespace {

bool mibRemoteAddrNwIsLoopback(quint32 dwRemoteAddr)
{
    return ((dwRemoteAddr >> 24) & 0xFFU) == 127U;
}

bool eligibleState(DWORD dwState)
{
    switch (dwState) {
    case 5:  // MIB_TCP_STATE_ESTAB / ESTABLISHED
    case 3:  // SYN_SENT
    case 4:  // SYN_RCVD
    case 6:  // FIN_WAIT1
    case 7:  // FIN_WAIT2
    case 8:  // CLOSE_WAIT
    case 9:  // CLOSING
    case 10: // LAST_ACK
        return true;
    default:
        return false;
    }
}

quint16 remotePortDecoded(DWORD dwRemotePortField)
{
    const auto w = static_cast<u_short>(dwRemotePortField & 0xffffU);
    return static_cast<quint16>(ntohs(w));
}

} // namespace

int closePidOutboundTcpOnRemotePort(quint32 pid, quint16 remotePort, QString* errorDetailOut,
                                    bool closingAlsoServersOnLoopback)
{
    if (pid == 0) {
        return 0;
    }

    // Sin WSAStartup/WSACleanup: iguala el contador Winsock con Qt (QTcpSocket).

    int closedTotal = 0;
    DWORD lastError = NO_ERROR;

    bool everSawClosingCandidate = false;

    constexpr int kMaxPasses = 256;
    for (int pass = 0; pass < kMaxPasses; ++pass) {
        DWORD bufSize = 0;
        ULONG res = GetExtendedTcpTable(nullptr, &bufSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (res != ERROR_INSUFFICIENT_BUFFER || bufSize == 0) {
            lastError = res;
            break;
        }

        std::vector<UCHAR> buf(bufSize);
        res = GetExtendedTcpTable(buf.data(), &bufSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (res != NO_ERROR) {
            lastError = res;
            break;
        }

        const auto* tbl = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
        bool anyRemovedThisPass = false;

        const DWORD num = tbl->dwNumEntries;
        for (DWORD i = 0; i < num; ++i) {
            const MIB_TCPROW_OWNER_PID& r = tbl->table[i];

            if (static_cast<quint32>(r.dwOwningPid) != pid) {
                continue;
            }
            if (!eligibleState(r.dwState)) {
                continue;
            }
            if (r.dwRemoteAddr == 0) {
                continue;
            }

            if (!closingAlsoServersOnLoopback && mibRemoteAddrNwIsLoopback(static_cast<quint32>(r.dwRemoteAddr))) {
                continue;
            }

            if (remotePortDecoded(r.dwRemotePort) != remotePort) {
                continue;
            }

            everSawClosingCandidate = true;

            MIB_TCPROW kill{};
            kill.dwState = MIB_TCP_STATE_DELETE_TCB;
            kill.dwLocalAddr = r.dwLocalAddr;
            kill.dwLocalPort = r.dwLocalPort;
            kill.dwRemoteAddr = r.dwRemoteAddr;
            kill.dwRemotePort = r.dwRemotePort;

            const DWORD st = SetTcpEntry(&kill);
            if (st == NO_ERROR) {
                closedTotal++;
                anyRemovedThisPass = true;
            } else if (lastError == NO_ERROR) {
                lastError = st;
            }
        }

        if (!anyRemovedThisPass) {
            break;
        }
    }

    if (closedTotal == 0 && everSawClosingCandidate) {
        if (errorDetailOut != nullptr) {
            if (errorDetailOut->isEmpty()) {
                *errorDetailOut =
                    QStringLiteral("SetTcpEntry falló para todas las coincidencias (código sistema %1). ¿Administrador "
                                   "elevado sobre el token UAC efectivo?")
                        .arg(static_cast<qulonglong>(lastError));
            }
        }
        return -1;
    }

    if (closedTotal == 0 && lastError != NO_ERROR && errorDetailOut != nullptr && errorDetailOut->isEmpty()) {
        *errorDetailOut =
            QStringLiteral("GetExtendedTcpTable falló (código %1). ¿Administrador / stack IP saludable?")
                .arg(static_cast<qulonglong>(lastError));
    }

    return closedTotal;
}

int closePidAllOutboundTcpConnections(quint32 pid, QString* errorDetailOut, bool preserveLoopbackRemotes)
{
    if (pid == 0) {
        return 0;
    }

    int closedTotal = 0;
    DWORD lastError = NO_ERROR;
    bool everSawClosingCandidate = false;

    constexpr int kMaxPasses = 256;
    for (int pass = 0; pass < kMaxPasses; ++pass) {
        DWORD bufSize = 0;
        ULONG res = GetExtendedTcpTable(nullptr, &bufSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (res != ERROR_INSUFFICIENT_BUFFER || bufSize == 0) {
            lastError = res;
            break;
        }

        std::vector<UCHAR> buf(bufSize);
        res = GetExtendedTcpTable(buf.data(), &bufSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (res != NO_ERROR) {
            lastError = res;
            break;
        }

        const auto* tbl = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
        bool anyRemovedThisPass = false;

        const DWORD num = tbl->dwNumEntries;
        for (DWORD i = 0; i < num; ++i) {
            const MIB_TCPROW_OWNER_PID& r = tbl->table[i];

            if (static_cast<quint32>(r.dwOwningPid) != pid) {
                continue;
            }
            if (!eligibleState(r.dwState)) {
                continue;
            }
            if (r.dwRemoteAddr == 0) {
                continue;
            }

            if (preserveLoopbackRemotes && mibRemoteAddrNwIsLoopback(static_cast<quint32>(r.dwRemoteAddr))) {
                continue;
            }

            everSawClosingCandidate = true;

            MIB_TCPROW kill{};
            kill.dwState = MIB_TCP_STATE_DELETE_TCB;
            kill.dwLocalAddr = r.dwLocalAddr;
            kill.dwLocalPort = r.dwLocalPort;
            kill.dwRemoteAddr = r.dwRemoteAddr;
            kill.dwRemotePort = r.dwRemotePort;

            const DWORD st = SetTcpEntry(&kill);
            if (st == NO_ERROR) {
                closedTotal++;
                anyRemovedThisPass = true;
            } else if (lastError == NO_ERROR) {
                lastError = st;
            }
        }

        if (!anyRemovedThisPass) {
            break;
        }
    }

    if (closedTotal == 0 && everSawClosingCandidate) {
        if (errorDetailOut != nullptr && errorDetailOut->isEmpty()) {
            *errorDetailOut =
                QStringLiteral("SetTcpEntry falló (código %1). ¿Administrador?")
                    .arg(static_cast<qulonglong>(lastError));
        }
        return -1;
    }

    if (closedTotal == 0 && lastError != NO_ERROR && errorDetailOut != nullptr && errorDetailOut->isEmpty()) {
        *errorDetailOut =
            QStringLiteral("GetExtendedTcpTable falló (código %1).")
                .arg(static_cast<qulonglong>(lastError));
    }

    return closedTotal;
}

#endif // Q_OS_WIN
