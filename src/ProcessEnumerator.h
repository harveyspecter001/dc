#pragma once

#include <QtGlobal>
#include <QString>
#include <QVector>

struct ProcessEntry {
    quint32 pid = 0;
    QString name;
};

/// Lista de procesos en ejecución (snapshot). Orden: nombre, luego PID.
QVector<ProcessEntry> enumerateRunningProcesses();

/// Coincide con «Dofus» en el nombre del ejecutable (sin distinguir mayús./minús.).
inline bool processNameLooksLikeDofus(const QString& exeName)
{
    return exeName.contains(QStringLiteral("dofus"), Qt::CaseInsensitive);
}

/// Identifica el propio ejecutable de esta herramienta (no es el juego).
inline bool processNameIsSnifferTool(const QString& exeName)
{
    return exeName.compare(QStringLiteral("dofus_process_sniffer.exe"), Qt::CaseInsensitive) == 0;
}

/// «Dofus» típico de juego/lanzador, excluye esta herramienta para no confundir con el cliente real.
inline bool processNameLooksLikeGameDofus(const QString& exeName)
{
    return processNameLooksLikeDofus(exeName) && !processNameIsSnifferTool(exeName);
}
