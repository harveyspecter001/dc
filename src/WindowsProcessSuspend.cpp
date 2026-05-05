#include "WindowsProcessSuspend.h"

#if defined(Q_OS_WIN)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

using NtSuspendProcessFn = LONG(WINAPI*)(HANDLE);
using NtResumeProcessFn = LONG(WINAPI*)(HANDLE);

namespace WindowsProcessSuspend {

namespace {

bool ntSuspendResume(quint32 pid, bool suspend, QString* errorMessage)
{
    if (errorMessage != nullptr) {
        errorMessage->clear();
    }
    if (pid == 0) {
        if (errorMessage != nullptr) {
            *errorMessage = QStringLiteral("PID inválido.");
        }
        return false;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        if (errorMessage != nullptr) {
            *errorMessage = QStringLiteral("ntdll.dll no cargado.");
        }
        return false;
    }

    FARPROC rawProc =
        GetProcAddress(ntdll, suspend ? "NtSuspendProcess" : "NtResumeProcess");
    if (rawProc == nullptr) {
        if (errorMessage != nullptr) {
            *errorMessage = QStringLiteral("NtSuspendProcess/NtResumeProcess no exportado.");
        }
        return false;
    }

    HANDLE hProc = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, static_cast<DWORD>(pid));
    if (hProc == nullptr) {
        if (errorMessage != nullptr) {
            *errorMessage =
                QStringLiteral("OpenProcess(PROCESS_SUSPEND_RESUME) PID %1: %2")
                    .arg(pid)
                    .arg(QString::number(static_cast<qulonglong>(GetLastError())));
        }
        return false;
    }

    LONG st = 0;
    if (suspend) {
        st = reinterpret_cast<NtSuspendProcessFn>(rawProc)(hProc);
    } else {
        st = reinterpret_cast<NtResumeProcessFn>(rawProc)(hProc);
    }
    CloseHandle(hProc);

    if (st != 0) {
        if (errorMessage != nullptr) {
            *errorMessage =
                QStringLiteral("NTSTATUS 0x%1")
                    .arg(QString::number(static_cast<qulonglong>(static_cast<ULONG>(st)), 16));
        }
        return false;
    }
    return true;
}

} // namespace

bool suspendProcess(quint32 pid, QString* errorMessage)
{
    return ntSuspendResume(pid, true, errorMessage);
}

bool resumeProcess(quint32 pid, QString* errorMessage)
{
    return ntSuspendResume(pid, false, errorMessage);
}

} // namespace WindowsProcessSuspend

#endif
