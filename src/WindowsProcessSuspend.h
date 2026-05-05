#pragma once

#include <QtGlobal>

#include <QString>

#ifdef Q_OS_WIN

namespace WindowsProcessSuspend {

/// Suspende todos los hilos del proceso (NtSuspendProcess).
bool suspendProcess(quint32 pid, QString* errorMessage);

/// Reanuda tras \ref suspendProcess (NtResumeProcess).
bool resumeProcess(quint32 pid, QString* errorMessage);

} // namespace WindowsProcessSuspend

#endif
