#pragma once

#include <QtGlobal>

#include <QString>

#ifdef Q_OS_WIN

/// Cierra (DELETE_TCB) sockets TCP IPv4 del \p pid cuyo puerto **remoto** = \p remotePort (orden host, p. ej. 5555).
/// Si \p closingAlsoServersOnLoopback es \c false, se omiten filas cuyo remoto pertenezca a 127.0.0.1/8
/// (no matar «127.0.0.1:5555» al proxy cuando el juego reconectó bien por localhost).
///
/// Devuelve el número de cierres con éxito, o −1 ante fallos GetExtendedTcpTable / SetTcpEntry.
int closePidOutboundTcpOnRemotePort(quint32 pid, quint16 remotePort, QString* errorDetailOut,
                                    bool closingAlsoServersOnLoopback = false);

/// Cierra todas las conexiones TCP IPv4 elegibles del PID (cualquier puerto remoto).
/// Si \a preserveLoopbackRemotes es \c true, no toca remotos 127.0.0.0/8.
int closePidAllOutboundTcpConnections(quint32 pid, QString* errorDetailOut, bool preserveLoopbackRemotes);

#endif
