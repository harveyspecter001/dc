#include "DebugCentralLog.h"

#include <QDateTime>
#include <QFile>
#include <QIODevice>
#include <QMutex>
#include <QMutexLocker>

namespace {
QMutex g_centralLogMutex;
constexpr auto kCentralPath = "C:/dofus_debug_log.txt";
} // namespace

void DebugCentralLog::append(const char* tag, const QString& message)
{
    QMutexLocker lock(&g_centralLogMutex);
    QFile f(QString::fromUtf8(kCentralPath));
    if (!f.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        return;
    }
    const QString line = QDateTime::currentDateTime().toString(QStringLiteral("[yyyy-MM-dd HH:mm:ss.zzz] "))
        + QStringLiteral("[") + QString::fromUtf8(tag) + QStringLiteral("] ") + message + QLatin1Char('\n');
    f.write(line.toUtf8());
}
