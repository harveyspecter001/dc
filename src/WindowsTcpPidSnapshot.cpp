#include "WindowsTcpPidSnapshot.h"

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

#include <algorithm>
#include <unordered_set>
#include <vector>

#include <QtEndian>

namespace {

quint16 portFromRowField(DWORD dwPortField)
{
    const auto w = static_cast<u_short>(dwPortField & 0xffffU);
    return static_cast<quint16>(ntohs(w));
}

bool mibIpv4DwordNWIsLoopback(quint32 addrNwEndian)
{
    return ((addrNwEndian >> 24) & 0xFFU) == 127U;
}

bool mibTcpPeerLikelyOutboundShard(quint32 state)
{
    switch (state) {
    case 3: // SYN_SENT
    case 4: // SYN_RCVD
    case 5: // ESTABLISHED
    case 6: // FIN_WAIT1
    case 7: // FIN_WAIT2
    case 8: // CLOSE_WAIT
    case 10: // LAST_ACK
        return true;
    default:
        return false;
    }
}

int mibTcpOutboundPriority(quint32 state)
{
    switch (state) {
    case 5:
        return 0;
    case 3:
        return 1;
    case 8:
        return 2;
    case 6:
    case 7:
    case 10:
        return 3;
    case 4:
        return 4;
    default:
        return 9;
    }
}

} // namespace

QString winTcpIpv4StateName(quint32 state)
{
    switch (state) {
    case 1:
        return QStringLiteral("CLOSED");
    case 2:
        return QStringLiteral("LISTEN");
    case 3:
        return QStringLiteral("SYN_SENT");
    case 4:
        return QStringLiteral("SYN_RCVD");
    case 5:
        return QStringLiteral("ESTABLISHED");
    case 6:
        return QStringLiteral("FIN_WAIT1");
    case 7:
        return QStringLiteral("FIN_WAIT2");
    case 8:
        return QStringLiteral("CLOSE_WAIT");
    case 9:
        return QStringLiteral("CLOSING");
    case 10:
        return QStringLiteral("LAST_ACK");
    case 11:
        return QStringLiteral("TIME_WAIT");
    case 12:
        return QStringLiteral("DELETE_TCB");
    default:
        return QStringLiteral("STATE_%1").arg(state);
    }
}

QVector<TcpRowPidIpv4> winEnumerateTcpIpv4RowsForOwningPid(quint32 pid)
{
    QVector<TcpRowPidIpv4> out;
    if (pid == 0) {
        return out;
    }

    DWORD bufSize = 0;
    ULONG q = GetExtendedTcpTable(nullptr, &bufSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (q != ERROR_INSUFFICIENT_BUFFER || bufSize == 0) {
        return out;
    }

    std::vector<UCHAR> buf(bufSize);
    q = GetExtendedTcpTable(buf.data(), &bufSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (q != NO_ERROR) {
        return out;
    }

    const auto* tbl = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
    const DWORD n = tbl->dwNumEntries;
    out.reserve(static_cast<int>(n));

    for (DWORD i = 0; i < n; ++i) {
        const MIB_TCPROW_OWNER_PID& r = tbl->table[i];
        if (static_cast<quint32>(r.dwOwningPid) != pid) {
            continue;
        }

        TcpRowPidIpv4 row;
        row.localAddrIpv4BE = static_cast<quint32>(r.dwLocalAddr);
        row.remoteAddrIpv4BE = static_cast<quint32>(r.dwRemoteAddr);
        row.localPort = portFromRowField(r.dwLocalPort);
        row.remotePort = portFromRowField(r.dwRemotePort);
        row.tcpState = static_cast<quint32>(r.dwState);
        out.append(row);
    }

    return out;
}

QVector<quint32> winDiscoverRemotePeerIpv4sOnRemotePort(quint32 owningPid, quint16 remoteTcpPortHostOrder)
{
    QVector<quint32> ranked;
    if (owningPid == 0 || remoteTcpPortHostOrder == 0) {
        return ranked;
    }
    QVector<TcpRowPidIpv4> rows = winEnumerateTcpIpv4RowsForOwningPid(owningPid);
    struct Cand {
        int pri{};
        quint32 ipv4Host{};
    };
    QVector<Cand> cands;

    std::unordered_set<quint32> seenHosts;
    seenHosts.reserve(static_cast<size_t>(rows.size()));

    for (const TcpRowPidIpv4& row : rows) {
        if (row.remotePort != remoteTcpPortHostOrder) {
            continue;
        }
        if (!mibTcpPeerLikelyOutboundShard(row.tcpState)) {
            continue;
        }
        if (mibIpv4DwordNWIsLoopback(row.remoteAddrIpv4BE)) {
            continue;
        }
        const quint32 ipv4Host = qFromBigEndian(row.remoteAddrIpv4BE);
        if (!seenHosts.insert(ipv4Host).second) {
            continue;
        }
        Cand c{mibTcpOutboundPriority(row.tcpState), ipv4Host};
        cands.push_back(c);
    }

    std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) {
        if (a.pri != b.pri) {
            return a.pri < b.pri;
        }
        return a.ipv4Host < b.ipv4Host;
    });

    ranked.reserve(cands.size());
    for (const Cand& c : cands) {
        ranked.push_back(c.ipv4Host);
    }
    return ranked;
}

#endif
