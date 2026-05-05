#pragma once

#include <QString>
#include <QtGlobal>
#include <QVector>

#ifdef Q_OS_WIN

struct TcpRowPidIpv4 {
    quint32 localAddrIpv4BE = 0;  //!< como en tabla Windows (NETWORK order DWORD)
    quint32 remoteAddrIpv4BE = 0;
    quint16 localPort = 0;   //!< orden host para mostrar/pintar
    quint16 remotePort = 0;
    quint32 tcpState = 0;
};

QVector<TcpRowPidIpv4> winEnumerateTcpIpv4RowsForOwningPid(quint32 pid);

QString winTcpIpv4StateName(quint32 state);

/// IPv4 remotas (sin loopback) con las que \a owningPid tiene filas TCP hacia puerto remoto \a remoteTcpPortHostOrder.
/// Útiles cuando el cliente ya eligió shard (p. ej. 54.x) pero la UI tiene otra IP: el primer candidato debe ser probado
/// igual que upstream en el parche de memoria. Orden: ESTABLISHED, SYN_SENT, resto «no cerrado» conocido (p. ej. CLOSE_WAIT).
QVector<quint32> winDiscoverRemotePeerIpv4sOnRemotePort(quint32 owningPid, quint16 remoteTcpPortHostOrder);

#endif
