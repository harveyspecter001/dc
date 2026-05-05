#include "ProcessEnumerator.h"

#include <algorithm>
#include <windows.h>
#include <tlhelp32.h>

QVector<ProcessEntry> enumerateRunningProcesses()
{
    QVector<ProcessEntry> rows;
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return rows;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessEntry e;
            e.pid = static_cast<quint32>(pe.th32ProcessID);
            e.name = QString::fromWCharArray(pe.szExeFile);
            rows.push_back(e);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    std::sort(rows.begin(), rows.end(), [](const ProcessEntry& a, const ProcessEntry& b) {
        const int cmp = QString::compare(a.name, b.name, Qt::CaseInsensitive);
        if (cmp != 0) {
            return cmp < 0;
        }
        return a.pid < b.pid;
    });
    return rows;
}
