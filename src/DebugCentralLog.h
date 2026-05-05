#pragma once

#include <QString>

/// Append a line to C:\dofus_debug_log.txt: [yyyy-MM-dd HH:mm:ss.zzz] [tag] message
namespace DebugCentralLog {
void append(const char* tag, const QString& message);
} // namespace DebugCentralLog
