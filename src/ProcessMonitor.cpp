#include "ProcessMonitor.h"

#include <QThread>

#if defined(Q_OS_WIN)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <unordered_set>

ProcessMonitor::ProcessMonitor(QObject* parent)
    : QThread(parent)
{}

ProcessMonitor::~ProcessMonitor()
{
    stopSafely();
}

void ProcessMonitor::stopSafely()
{
    requestInterruption();
    if (isRunning()) {
        wait(3000);
    }
}

void ProcessMonitor::run()
{
    std::unordered_set<DWORD> seenAlive;

    while (!isInterruptionRequested()) {
        std::unordered_set<DWORD> currentDofus;

        const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"Dofus.exe") == 0) {
                        currentDofus.insert(pe.th32ProcessID);
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }

        for (DWORD pid : currentDofus) {
            if (seenAlive.insert(pid).second) {
                emit dofusProcessDetected(static_cast<quint32>(pid));
            }
        }

        for (auto it = seenAlive.begin(); it != seenAlive.end();) {
            if (currentDofus.find(*it) == currentDofus.end()) {
                it = seenAlive.erase(it);
            } else {
                ++it;
            }
        }

        QThread::sleep(1);
    }
}

#endif
