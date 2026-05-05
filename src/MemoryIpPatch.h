#pragma once

#include <QByteArray>
#include <QString>
#include <QVector>

#include <QtGlobal>
#include <utility>

#ifdef Q_OS_WIN

/// Comprueba si el proceso actual tiene token elevado (administrador).
bool winIsElevatedAdministrator();

/// Busca ocurrencias de la IPv4 (4 octetos en orden «uint32 sobre LE», como antes) y también en orden invertido,
/// y si \a relatedPortLittleEndian ≠ 0, patrones de 6 bytes: IPv4||puerto (LE y BE) y \c sockaddr_in (puerto NW
/// seguido de la misma IPv4).
/// Las regiones COMMIT sin PAGE_GUARD / PAGE_NOACCESS se intentan leer (más permisivo que sólo páginas R/W clásicas).
bool memoryIpv4PatchesApply(quint32 pid, const quint8 targetIpv4[4], const quint8 replacementIpv4[4],
                            quint16 relatedPortLittleEndian,
                            QVector<QPair<quintptr, QByteArray>>* undoOut, QString* errorMessage);

/// Restaura bytes guardados en `undo` (si el proceso sigue vivo).
bool memoryIpv4PatchesRestore(quint32 pid, const QVector<QPair<quintptr, QByteArray>>& undo,
                              QString* errorMessage);

/// Lee 4 octetos en la dirección dada del proceso (orden LE típico de IPv4 sobre Windows).
bool memoryReadIpv4QuadAt(quint32 pid, quintptr address, quint8 outOctets[4], QString* errorMessage);

/// Resumen legible tipo «127.0.0.1 (4/5 sitios leídos coinciden)» según contenido RAM actual en `sites`.
QString memoryIpv4PatchesReadbackSummary(quint32 pid, const QVector<QPair<quintptr, QByteArray>>& sites,
                                         QString* errorMessage);

#endif
