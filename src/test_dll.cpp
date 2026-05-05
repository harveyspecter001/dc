// DLL mínima de diagnóstico: sin hooks, solo escribe al cargar.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>

namespace {

void appendCentralDll(const char* body)
{
    FILE* fc = std::fopen("C:\\dofus_debug_log.txt", "a");
    if (fc == nullptr) {
        return;
    }
    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::fprintf(fc, "[%04u-%02u-%02u %02u:%02u:%02u.%03u] [DLL] %s\n", static_cast<unsigned>(st.wYear),
                 static_cast<unsigned>(st.wMonth), static_cast<unsigned>(st.wDay),
                 static_cast<unsigned>(st.wHour), static_cast<unsigned>(st.wMinute),
                 static_cast<unsigned>(st.wSecond), static_cast<unsigned>(st.wMilliseconds), body);
    std::fclose(fc);
}

} // namespace

BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD reason, LPVOID /*lpReserved*/)
{
    if (reason == DLL_PROCESS_ATTACH) {
        FILE* f = std::fopen("C:\\test_dll_log.txt", "w");
        if (f != nullptr) {
            std::fprintf(f, "DLL cargada en PID: %d\n", static_cast<int>(GetCurrentProcessId()));
            std::fclose(f);
        }
        char buf[256]{};
        std::snprintf(buf, sizeof(buf), "DLL test minimal cargada en PID %d (sin hooks)", static_cast<int>(GetCurrentProcessId()));
        appendCentralDll(buf);
    }
    return TRUE;
}
