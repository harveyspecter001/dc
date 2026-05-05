#pragma once

#include <QtGlobal>

#include <QString>

#ifdef Q_OS_WIN

[[nodiscard]] bool winIsElevatedAdministrator();

/// Busca el primer PID cuyo nombre de ejecutable coincida (comparación exacta, p. ej. L"Dofus.exe").
[[nodiscard]] quint32 winFindPidByExeName(const QString& exeFileName);

/// Inyecta la DLL en el proceso (CreateRemoteThread + LoadLibraryW). Requiere permisos elevados.
[[nodiscard]] bool winInjectDllIntoProcess(quint32 pid, const QString& dllAbsolutePath, QString* errorOut);

#endif
