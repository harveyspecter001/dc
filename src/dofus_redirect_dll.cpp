/*
 * DofusRedirect.dll — MinHook: DNS (getaddrinfo, GetAddrInfoW, gethostbyname) + connect/WSAConnect/ConnectEx
 * + traza socket/WSASocketW. Redirige endpoints dofus2-co-* y conexiones :5555 hacia loopback.
 *
 * Tras instalar hooks: opcional DOFUS_REDIRECT_PATCH_HOSTS=1 añade una línea a hosts (requiere permisos);
 * opcional DOFUS_REDIRECT_DISABLE_SETTCPENTRY=1 evita usar SetTcpEntry y deja solo redirección por hooks connect.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mswsock.h>
#include <iphlpapi.h>

#include <MinHook.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <vector>

namespace {

void appendDofusDebugCentral(const char* lineWithTimestamp)
{
    FILE* fc = std::fopen("C:\\dofus_debug_log.txt", "a");
    if (fc == nullptr) {
        return;
    }
    std::fprintf(fc, "%s\n", lineWithTimestamp != nullptr ? lineWithTimestamp : "");
    std::fclose(fc);
}

} // namespace

namespace {

typedef int(WSAAPI* ConnectFn)(SOCKET s, const struct sockaddr* name, int namelen);
typedef int(WSAAPI* WSAConnectFn)(SOCKET s,
                                  const sockaddr* name,
                                  int namelen,
                                  LPWSABUF lpCallerData,
                                  LPWSABUF lpCalleeData,
                                  LPQOS lpSQOS,
                                  LPQOS lpGQOS);

typedef BOOL(WINAPI* ConnectExFn)(SOCKET s,
                                  const sockaddr* name,
                                  int namelen,
                                  PVOID lpSendBuffer,
                                  DWORD dwSendDataLength,
                                  LPDWORD lpdwBytesSent,
                                  LPOVERLAPPED lpOverlapped);

typedef SOCKET(WSAAPI* SocketFn)(int af, int type, int protocol);
typedef SOCKET(WSAAPI* WSASocketWFn)(int af,
                                     int type,
                                     int protocol,
                                     LPWSAPROTOCOL_INFOW lpProtocolInfo,
                                     GROUP g,
                                     DWORD dwFlags);

typedef int(WSAAPI* GetAddrInfoFn)(PCSTR pNodeName,
                                   PCSTR pServiceName,
                                   const ADDRINFOA* pHints,
                                   PADDRINFOA* ppResult);

typedef int(WSAAPI* GetAddrInfoWFn)(PCWSTR pNodeName,
                                    PCWSTR pServiceName,
                                    const ADDRINFOW* pHints,
                                    PADDRINFOW* ppResult);

typedef struct hostent*(WSAAPI* GethostbynameFn)(const char* name);

ConnectFn gRealConnect = nullptr;
WSAConnectFn gRealWSAConnect = nullptr;
ConnectExFn gRealConnectEx = nullptr;
SocketFn gRealSocket = nullptr;
WSASocketWFn gRealWSASocketW = nullptr;
GetAddrInfoFn gRealGetAddrInfo = nullptr;
GetAddrInfoWFn gRealGetAddrInfoW = nullptr;
GethostbynameFn gRealGethostbyname = nullptr;

std::atomic<bool> gHooksReady{false};
std::atomic<int> gConnectHookLogCount{0};
std::atomic<bool> gInitStarted{false};
std::atomic<bool> gUnloadRequested{false};
HANDLE gInitThreadHandle = nullptr;

#ifndef MIB_TCP_STATE_DELETE_TCB
#define MIB_TCP_STATE_DELETE_TCB 12
#endif

void logLine(const char* msg)
{
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char stamp[1800]{};
    std::snprintf(stamp,
                  sizeof(stamp),
                  "[%04u-%02u-%02u %02u:%02u:%02u.%03u] %s",
                  static_cast<unsigned>(st.wYear),
                  static_cast<unsigned>(st.wMonth),
                  static_cast<unsigned>(st.wDay),
                  static_cast<unsigned>(st.wHour),
                  static_cast<unsigned>(st.wMinute),
                  static_cast<unsigned>(st.wSecond),
                  static_cast<unsigned>(st.wMilliseconds),
                  msg != nullptr ? msg : "");

    OutputDebugStringA(stamp);
    OutputDebugStringA("\r\n");

    if (FILE* primary = std::fopen("C:\\dofus_dll_log.txt", "a")) {
        std::fprintf(primary, "%s\n", stamp);
        std::fclose(primary);
    }

    char path[MAX_PATH]{};
    DWORD n = GetTempPathA(static_cast<DWORD>(sizeof(path)), path);
    if (n == 0 || n >= sizeof(path)) {
        std::strncpy(path, "C:\\", sizeof(path) - 1);
    }
    std::strncat(path, "dofus_redirect_log.txt", sizeof(path) - std::strlen(path) - 1);
    if (FILE* f = std::fopen(path, "a")) {
        std::fprintf(f, "%s\n", stamp);
        std::fclose(f);
    }

    appendDofusDebugCentral(stamp);
}

bool containsAnkamaAscii(const char* s)
{
    if (s == nullptr) {
        return false;
    }
    const size_t n = std::strlen(s);
    for (size_t i = 0; i + 6 <= n; ++i) {
        if (_strnicmp(s + i, "ankama", 6) == 0) {
            return true;
        }
    }
    return false;
}

bool containsDofusCoAscii(const char* s)
{
    if (s == nullptr) {
        return false;
    }
    return std::strstr(s, "dofus2-co-") != nullptr || std::strstr(s, "dofus2-co.") != nullptr;
}

bool containsDofusGaAscii(const char* s)
{
    if (s == nullptr) {
        return false;
    }
    return std::strstr(s, "dofus2-ga-") != nullptr || std::strstr(s, "dofus2-ga.") != nullptr;
}

bool containsDofusGameHostAscii(const char* s)
{
    return containsDofusCoAscii(s) || containsDofusGaAscii(s);
}

bool containsAnkamaWide(const wchar_t* s)
{
    if (s == nullptr) {
        return false;
    }
    const size_t n = std::wcslen(s);
    for (size_t i = 0; i + 6 <= n; ++i) {
        if (_wcsnicmp(s + i, L"ankama", 6) == 0) {
            return true;
        }
    }
    return false;
}

bool containsDofusCoWide(const wchar_t* s)
{
    if (s == nullptr) {
        return false;
    }
    return std::wcsstr(s, L"dofus2-co-") != nullptr || std::wcsstr(s, L"dofus2-co.") != nullptr;
}

bool containsDofusGaWide(const wchar_t* s)
{
    if (s == nullptr) {
        return false;
    }
    return std::wcsstr(s, L"dofus2-ga-") != nullptr || std::wcsstr(s, L"dofus2-ga.") != nullptr;
}

bool containsDofusGameHostWide(const wchar_t* s)
{
    return containsDofusCoWide(s) || containsDofusGaWide(s);
}

bool serviceIsGamePort5555A(const char* svc)
{
    if (svc == nullptr || svc[0] == '\0') {
        return false;
    }
    char* endPtr = nullptr;
    const long v = std::strtol(svc, &endPtr, 10);
    return (endPtr != nullptr && *endPtr == '\0' && v == 5555);
}

bool serviceIsGamePort5555W(const wchar_t* svc)
{
    if (svc == nullptr || svc[0] == L'\0') {
        return false;
    }
    wchar_t* endPtr = nullptr;
    const long v = std::wcstol(svc, &endPtr, 10);
    return (endPtr != nullptr && *endPtr == L'\0' && v == 5555);
}

/// muchos clientes no pasan "5555" como string de servicio en getaddrinfo (lo dejan NULL)
bool shouldRedirectGetAddrInfoA(PCSTR pNodeName, PCSTR pServiceName)
{
    if (pNodeName == nullptr || !containsAnkamaAscii(pNodeName) || !containsDofusGameHostAscii(pNodeName)) {
        return false;
    }
    // Para endpoints de juego (co/ga), forzamos siempre resolución local al puerto del proxy.
    if (pServiceName != nullptr && pServiceName[0] != '\0') {
        return true;
    }
    if (serviceIsGamePort5555A(pServiceName)) {
        return true;
    }
    if (pServiceName == nullptr || pServiceName[0] == '\0') {
        return true;
    }
    return false;
}

bool shouldRedirectGetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName)
{
    if (pNodeName == nullptr || !containsAnkamaWide(pNodeName) || !containsDofusGameHostWide(pNodeName)) {
        return false;
    }
    // Para endpoints de juego (co/ga), forzamos siempre resolución local al puerto del proxy.
    if (pServiceName != nullptr && pServiceName[0] != L'\0') {
        return true;
    }
    if (serviceIsGamePort5555W(pServiceName)) {
        return true;
    }
    if (pServiceName == nullptr || pServiceName[0] == L'\0') {
        return true;
    }
    return false;
}

static u_short remotePortFieldToHost(DWORD dwRemotePort)
{
    const auto w = static_cast<u_short>(dwRemotePort & 0xffffU);
    return ntohs(w);
}

static bool mibRemoteAddrNwIsLoopbackIpv4(DWORD dwRemoteAddr)
{
    return ((dwRemoteAddr >> 24) & 0xFFU) == 127U;
}

static bool tcpStateEligible(DWORD st)
{
    switch (st) {
    case MIB_TCP_STATE_ESTAB:
    case MIB_TCP_STATE_SYN_SENT:
    case MIB_TCP_STATE_SYN_RCVD:
    case MIB_TCP_STATE_FIN_WAIT1:
    case MIB_TCP_STATE_FIN_WAIT2:
    case MIB_TCP_STATE_CLOSE_WAIT:
    case MIB_TCP_STATE_CLOSING:
    case MIB_TCP_STATE_LAST_ACK:
        return true;
    default:
        return false;
    }
}

static bool isTruthyEnvFlag(const char* key)
{
    if (key == nullptr) {
        return false;
    }
    char flag[16]{};
    const DWORD n = GetEnvironmentVariableA(key, flag, static_cast<DWORD>(sizeof(flag)));
    if (n == 0 || n >= sizeof(flag)) {
        return false;
    }
    return (flag[0] == '1' && flag[1] == '\0') || _stricmp(flag, "true") == 0
           || _stricmp(flag, "yes") == 0 || _stricmp(flag, "on") == 0;
}

/// Cierra conexiones IPv4 del proceso actual hacia remoto :5555 que no sean loopback (SetTcpEntry).
int abortExistingIpv4GameConnections()
{
    const DWORD pid = GetCurrentProcessId();
    WSADATA wsd{};
    if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
        logLine("[DLL] abort TCP: WSAStartup falló");
        return -1;
    }

    int closedTotal = 0;
    constexpr int kMaxPasses = 128;
    for (int pass = 0; pass < kMaxPasses; ++pass) {
        DWORD bufSize = 0;
        ULONG res = GetExtendedTcpTable(nullptr, &bufSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (res != ERROR_INSUFFICIENT_BUFFER || bufSize == 0) {
            break;
        }

        std::vector<UCHAR> buf(bufSize);
        res = GetExtendedTcpTable(buf.data(), &bufSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (res != NO_ERROR) {
            char m[96];
            std::snprintf(m, sizeof(m), "[DLL] abort TCP: GetExtendedTcpTable falló (%lu)", static_cast<unsigned long>(res));
            logLine(m);
            break;
        }

        const auto* tbl = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
        bool anyRemoved = false;

        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
            const MIB_TCPROW_OWNER_PID& r = tbl->table[i];
            if (r.dwOwningPid != pid) {
                continue;
            }
            if (!tcpStateEligible(r.dwState)) {
                continue;
            }
            if (r.dwRemoteAddr == 0) {
                continue;
            }
            if (mibRemoteAddrNwIsLoopbackIpv4(r.dwRemoteAddr)) {
                continue;
            }
            if (remotePortFieldToHost(r.dwRemotePort) != 5555) {
                continue;
            }

            MIB_TCPROW kill{};
            kill.dwState = MIB_TCP_STATE_DELETE_TCB;
            kill.dwLocalAddr = r.dwLocalAddr;
            kill.dwLocalPort = r.dwLocalPort;
            kill.dwRemoteAddr = r.dwRemoteAddr;
            kill.dwRemotePort = r.dwRemotePort;

            char ipStr[16]{};
            IN_ADDR ra{};
            ra.S_un.S_addr = r.dwRemoteAddr;
            if (inet_ntop(AF_INET, &ra, ipStr, sizeof(ipStr)) == nullptr) {
                std::strncpy(ipStr, "?", sizeof(ipStr) - 1);
            }

            const DWORD st = SetTcpEntry(&kill);
            if (st == NO_ERROR) {
                closedTotal++;
                anyRemoved = true;
                char line[200];
                std::snprintf(line,
                              sizeof(line),
                              "[DLL] SetTcpEntry: cerrada sesión IPv4 hacia %s:5555 (forzar reconexión por hooks)",
                              ipStr);
                logLine(line);
            } else if (st == ERROR_NOT_FOUND) {
                // En servidores beta puede desaparecer entre snapshot y SetTcpEntry (317): no es fatal.
                char line[240];
                std::snprintf(line,
                              sizeof(line),
                              "[DLL] SetTcpEntry aviso %lu en %s:5555 (la conexión ya no existe; se continúa con "
                              "hooks connect)",
                              static_cast<unsigned long>(st),
                              ipStr);
                logLine(line);
            } else {
                char line[220];
                std::snprintf(line,
                              sizeof(line),
                              "[DLL] SetTcpEntry falló %lu al cerrar %s:5555 (¿ejecutar el juego/admin como "
                              "administrador?)",
                              static_cast<unsigned long>(st),
                              ipStr);
                logLine(line);
            }
        }

        if (!anyRemoved) {
            break;
        }
    }

    WSACleanup();
    if (closedTotal > 0) {
        char sum[96];
        std::snprintf(sum, sizeof(sum), "[DLL] abort TCP: total conexiones IPv4 :5555 cerradas: %d", closedTotal);
        logLine(sum);
    }
    return closedTotal;
}

static void logHookConnectDestination(const char* apiTag, SOCKET s, const sockaddr* name, int namelen)
{
    if (gConnectHookLogCount.fetch_add(1) >= 400) {
        return;
    }
    if (name == nullptr || namelen < static_cast<int>(sizeof(sockaddr))) {
        char b[120];
        std::snprintf(b, sizeof(b), "[DLL] %s(sock=%llu) sockaddr inválido", apiTag,
                      static_cast<unsigned long long>(s));
        logLine(b);
        return;
    }

    if (name->sa_family == AF_INET && namelen >= static_cast<int>(sizeof(SOCKADDR_IN))) {
        auto* in = reinterpret_cast<const SOCKADDR_IN*>(name);
        char ip[64]{};
        if (inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip)) == nullptr) {
            std::strncpy(ip, "?", sizeof(ip) - 1);
        }
        const u_short port = ntohs(in->sin_port);
        char line[280];
        std::snprintf(line, sizeof(line), "[DLL] %s(sock=%llu) destino %s:%u", apiTag,
                      static_cast<unsigned long long>(s), ip, static_cast<unsigned>(port));
        logLine(line);
    } else if (name->sa_family == AF_INET6 && namelen >= static_cast<int>(sizeof(sockaddr_in6))) {
        auto* in6 = reinterpret_cast<const sockaddr_in6*>(name);
        char ip[INET6_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip)) == nullptr) {
            std::strncpy(ip, "?", sizeof(ip) - 1);
        }
        const u_short port = ntohs(in6->sin6_port);
        char line[320];
        std::snprintf(line, sizeof(line), "[DLL] %s(sock=%llu) destino [%s]:%u", apiTag,
                      static_cast<unsigned long long>(s), ip, static_cast<unsigned>(port));
        logLine(line);
    } else {
        char b[120];
        std::snprintf(b, sizeof(b), "[DLL] %s(sock=%llu) familia %d", apiTag,
                      static_cast<unsigned long long>(s), static_cast<int>(name->sa_family));
        logLine(b);
    }
}

static void maybeAppendHostsFallback()
{
    char flag[8]{};
    if (GetEnvironmentVariableA("DOFUS_REDIRECT_PATCH_HOSTS", flag, sizeof(flag)) == 0) {
        return;
    }
    if (flag[0] != '1' || flag[1] != '\0') {
        return;
    }

    const char* hostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    const char* markerLine = "# DOFUS_REDIRECT_NEXT_LINE";
    const char* entryLine = "127.0.0.1 dofus2-ga-rafal.ankama-games.com";

    FILE* rf = std::fopen(hostsPath, "r");
    if (rf != nullptr) {
        char chunk[4096]{};
        size_t n = std::fread(chunk, 1, sizeof(chunk) - 1, rf);
        chunk[n] = '\0';
        std::fclose(rf);
        if (std::strstr(chunk, "dofus2-ga-rafal.ankama-games.com") != nullptr) {
            logLine("[DLL] hosts: entrada Ankama ya presente; no se modifica.");
            return;
        }
    }

    FILE* wf = std::fopen(hostsPath, "a");
    if (wf == nullptr) {
        logLine("[DLL] hosts: no se pudo abrir hosts para append (¿administrador?). "
                "Añade manualmente 127.0.0.1 dofus2-ga-rafal.ankama-games.com");
        return;
    }
    std::fprintf(wf, "\r\n%s\r\n%s\r\n", markerLine, entryLine);
    std::fclose(wf);
    logLine("[DLL] hosts: añadida línea 127.0.0.1 dofus2-ga-rafal.ankama-games.com (DOFUS_REDIRECT_PATCH_HOSTS=1). "
            "Quítala tras probar.");
}

bool tryBuildRedirect5555(const sockaddr* name, int namelen, sockaddr_storage* out, int* outLen)
{
    if (name == nullptr || outLen == nullptr || out == nullptr) {
        return false;
    }

    if (name->sa_family == AF_INET && namelen >= static_cast<int>(sizeof(SOCKADDR_IN))) {
        auto* in = reinterpret_cast<const SOCKADDR_IN*>(name);
        const u_short port = ntohs(in->sin_port);
        const ULONG loop = inet_addr("127.0.0.1");
        if (port == 5555 && in->sin_addr.s_addr != loop) {
            SOCKADDR_IN copy = *in;
            const ULONG orig = copy.sin_addr.s_addr;
            copy.sin_addr.s_addr = loop;
            std::memcpy(out, &copy, sizeof(copy));
            *outLen = static_cast<int>(sizeof(copy));
            char buf[280];
            std::snprintf(buf, sizeof(buf),
                          "[DLL] Redirect IPv4 %u.%u.%u.%u:5555 -> 127.0.0.1:5555",
                          static_cast<unsigned>(orig & 0xFFU),
                          static_cast<unsigned>((orig >> 8) & 0xFFU),
                          static_cast<unsigned>((orig >> 16) & 0xFFU),
                          static_cast<unsigned>((orig >> 24) & 0xFFU));
            logLine(buf);

            IN_ADDR originalAddr{};
            originalAddr.S_un.S_addr = orig;
            char originalIp[16]{};
            if (inet_ntop(AF_INET, &originalAddr, originalIp, static_cast<DWORD>(sizeof(originalIp))) != nullptr) {
                char msg[128]{};
                std::snprintf(msg, sizeof(msg), "[DLL] Conexión original a %s:5555", originalIp);
                logLine(msg);
                FILE* f = std::fopen("C:\\dofus_upstream_ip.txt", "w");
                if (f != nullptr) {
                    std::fprintf(f, "%s\n", originalIp);
                    std::fclose(f);
                }
            }
            return true;
        }
    }

    if (name->sa_family == AF_INET6 && namelen >= static_cast<int>(sizeof(sockaddr_in6))) {
        auto* in6 = reinterpret_cast<const sockaddr_in6*>(name);
        if (ntohs(in6->sin6_port) == 5555) {
            const bool isLoop = IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr) != 0;
            if (!isLoop) {
                sockaddr_in6 cpy = *in6;
                IN6_ADDR loop6{};
                loop6.u.Byte[15] = 1;
                cpy.sin6_addr = loop6;
                std::memcpy(out, &cpy, sizeof(cpy));
                *outLen = static_cast<int>(sizeof(cpy));
                logLine("[DLL] Redirect IPv6 :5555 -> ::1:5555");
                return true;
            }
        }
    }

    return false;
}

int WSAAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen)
{
    if (gRealConnect == nullptr) {
        return SOCKET_ERROR;
    }
    if (name != nullptr && name->sa_family == AF_INET && namelen >= static_cast<int>(sizeof(SOCKADDR_IN))) {
        auto* in = reinterpret_cast<const SOCKADDR_IN*>(name);
        const u_short portHost = ntohs(in->sin_port);
        const ULONG loop = inet_addr("127.0.0.1");
        char line[200];
        std::snprintf(line,
                      sizeof(line),
                      "[DLL] connect() llamada — socket %llu, puerto destino %u",
                      static_cast<unsigned long long>(s),
                      static_cast<unsigned>(portHost));
        logLine(line);
        if (portHost == 5555U && in->sin_addr.s_addr != loop) {
            logLine("[DLL] connect: :5555 hacia IP no loopback → redirigiendo a 127.0.0.1:5555");
        }
    }
    logHookConnectDestination("connect", s, name, namelen);
    sockaddr_storage st{};
    int nl = 0;
    if (tryBuildRedirect5555(name, namelen, &st, &nl)) {
        logLine("[DLL] connect -> aplicando redirección a 127.0.0.1:5555");
        return gRealConnect(s, reinterpret_cast<const sockaddr*>(&st), nl);
    }
    return gRealConnect(s, name, namelen);
}

int WSAAPI HookedWSAConnect(SOCKET s,
                            const sockaddr* name,
                            int namelen,
                            LPWSABUF lpCallerData,
                            LPWSABUF lpCalleeData,
                            LPQOS lpSQOS,
                            LPQOS lpGQOS)
{
    if (gRealWSAConnect == nullptr) {
        return SOCKET_ERROR;
    }
    logHookConnectDestination("WSAConnect", s, name, namelen);
    sockaddr_storage st{};
    int nl = 0;
    if (tryBuildRedirect5555(name, namelen, &st, &nl)) {
        logLine("[DLL] WSAConnect -> aplicando redirección a 127.0.0.1:5555");
        return gRealWSAConnect(s, reinterpret_cast<const sockaddr*>(&st), nl, lpCallerData, lpCalleeData, lpSQOS,
                               lpGQOS);
    }
    return gRealWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

BOOL WINAPI HookedConnectEx(SOCKET s,
                            const sockaddr* name,
                            int namelen,
                            PVOID lpSendBuffer,
                            DWORD dwSendDataLength,
                            LPDWORD lpdwBytesSent,
                            LPOVERLAPPED lpOverlapped)
{
    if (gRealConnectEx == nullptr) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
    logHookConnectDestination("ConnectEx", s, name, namelen);
    sockaddr_storage st{};
    int nl = 0;
    if (tryBuildRedirect5555(name, namelen, &st, &nl)) {
        logLine("[DLL] ConnectEx -> aplicando redirección a 127.0.0.1:5555 / ::1:5555");
        return gRealConnectEx(s, reinterpret_cast<const sockaddr*>(&st), nl, lpSendBuffer, dwSendDataLength,
                              lpdwBytesSent, lpOverlapped);
    }
    return gRealConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
}

SOCKET WSAAPI HookedSocket(int af, int type, int protocol)
{
    if (gRealSocket == nullptr) {
        return INVALID_SOCKET;
    }
    static std::atomic<int> skLogLeft{8};
    const int left = skLogLeft.fetch_sub(1);
    if (left > 0) {
        char b[160];
        std::snprintf(b, sizeof(b), "[DLL] socket(af=%d,type=%d,proto=%d) #%d", af, type, protocol, 9 - left);
        logLine(b);
    }
    return gRealSocket(af, type, protocol);
}

SOCKET WSAAPI HookedWSASocketW(int af,
                               int type,
                               int protocol,
                               LPWSAPROTOCOL_INFOW lpProtocolInfo,
                               GROUP g,
                               DWORD dwFlags)
{
    if (gRealWSASocketW == nullptr) {
        return INVALID_SOCKET;
    }
    static std::atomic<int> wLogLeft{8};
    const int left = wLogLeft.fetch_sub(1);
    if (left > 0) {
        char b[160];
        std::snprintf(b, sizeof(b), "[DLL] WSASocketW(af=%d,type=%d,proto=%d) #%d", af, type, protocol, 9 - left);
        logLine(b);
    }
    return gRealWSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags);
}

int WSAAPI HookedGetAddrInfo(PCSTR pNodeName,
                             PCSTR pServiceName,
                             const ADDRINFOA* pHints,
                             PADDRINFOA* ppResult)
{
    if (gRealGetAddrInfo == nullptr) {
        return WSANO_RECOVERY;
    }
    if (shouldRedirectGetAddrInfoA(pNodeName, pServiceName)) {
        char msg[520];
        std::snprintf(msg, sizeof(msg),
                      "[DLL] getaddrinfo DNS redir: nodo «%s» servicio«%s» -> resolviendo «127.0.0.1:5555»",
                      pNodeName, (pServiceName && pServiceName[0]) ? pServiceName : "(vacío)");
        logLine(msg);
        return gRealGetAddrInfo("127.0.0.1", "5555", pHints, ppResult);
    }
    return gRealGetAddrInfo(pNodeName, pServiceName, pHints, ppResult);
}

int WSAAPI HookedGetAddrInfoW(PCWSTR pNodeName,
                              PCWSTR pServiceName,
                              const ADDRINFOW* pHints,
                              PADDRINFOW* ppResult)
{
    if (gRealGetAddrInfoW == nullptr) {
        return WSANO_RECOVERY;
    }
    if (shouldRedirectGetAddrInfoW(pNodeName, pServiceName)) {
        char narrow[512]{};
        WideCharToMultiByte(CP_UTF8, 0, pNodeName, -1, narrow, static_cast<int>(sizeof(narrow)) - 1, nullptr, nullptr);
        char msg[640];
        std::snprintf(msg, sizeof(msg),
                      "[DLL] GetAddrInfoW DNS redir: nodo UTF-8 «%s» -> resolviendo 127.0.0.1:5555",
                      narrow);
        logLine(msg);
        return gRealGetAddrInfoW(L"127.0.0.1", L"5555", pHints, ppResult);
    }
    return gRealGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
}

struct hostent* WSAAPI HookedGethostbyname(const char* name)
{
    if (gRealGethostbyname == nullptr) {
        return nullptr;
    }
    if (name != nullptr && containsAnkamaAscii(name) && containsDofusGameHostAscii(name)) {
        char msg[400];
        std::snprintf(msg, sizeof(msg), "[DLL] gethostbyname DNS redir: «%s» -> resolviendo «127.0.0.1»", name);
        logLine(msg);
        struct hostent* he = gRealGethostbyname("127.0.0.1");
        if (he != nullptr) {
            logLine("[DLL] gethostbyname: OK (hostent para 127.0.0.1)");
        } else {
            logLine("[DLL] gethostbyname: AVISO — gethostbyname(\"127.0.0.1\") devolvió NULL");
        }
        return he;
    }
    return gRealGethostbyname(name);
}

#define HOOK_OK "OK"
#define HOOK_SKIP "SKIP"

/// Dirección real de ConnectEx (no es export ordinal estable en mswsock.dll).
LPVOID resolveConnectExForMinHook()
{
    WSADATA wsd{};
    if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
        return nullptr;
    }
    const SOCKET s =
        WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        return nullptr;
    }
    GUID gid = WSAID_CONNECTEX;
    LPFN_CONNECTEX pfn = nullptr;
    DWORD br = 0;
    const int ir = WSAIoctl(s,
                             SIO_GET_EXTENSION_FUNCTION_POINTER,
                             &gid,
                             sizeof(gid),
                             &pfn,
                             sizeof(pfn),
                             &br,
                             nullptr,
                             nullptr);
    closesocket(s);
    if (ir != 0 || pfn == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<LPVOID>(pfn);
}

bool installHooksSynchronously()
{
    if (gUnloadRequested.load()) {
        return false;
    }
    logLine("[DLL] -------- DLL cargada (PROCESS_ATTACH) --------");

    if (MH_Initialize() != MH_OK) {
        logLine("[DLL] ERROR: MH_Initialize falló");
        return false;
    }

    const char* stConnect = HOOK_SKIP;
    const char* stWSA = HOOK_SKIP;
    const char* stCex = HOOK_SKIP;
    const char* stSock = HOOK_SKIP;
    const char* stWSk = HOOK_SKIP;
    const char* stGai = HOOK_SKIP;
    const char* stGaiW = HOOK_SKIP;
    const char* stGh = HOOK_SKIP;

    if (MH_CreateHookApi(L"ws2_32.dll", "connect", reinterpret_cast<LPVOID>(&HookedConnect),
                         reinterpret_cast<LPVOID*>(&gRealConnect))
        == MH_OK) {
        stConnect = HOOK_OK;
    } else {
        logLine("[DLL] ERROR: MH_CreateHookApi(connect) falló");
        MH_Uninitialize();
        return false;
    }
    if (MH_CreateHookApi(L"ws2_32.dll", "WSAConnect", reinterpret_cast<LPVOID>(&HookedWSAConnect),
                         reinterpret_cast<LPVOID*>(&gRealWSAConnect))
        == MH_OK) {
        stWSA = HOOK_OK;
    } else {
        logLine("[DLL] ERROR: MH_CreateHookApi(WSAConnect) falló");
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        return false;
    }

    if (GetModuleHandleW(L"mswsock.dll") == nullptr) {
        LoadLibraryW(L"mswsock.dll");
    }
    if (LPVOID pConnectEx = resolveConnectExForMinHook()) {
        ConnectExFn origCex = nullptr;
        if (MH_CreateHook(pConnectEx,
                          reinterpret_cast<LPVOID>(&HookedConnectEx),
                          reinterpret_cast<LPVOID*>(&origCex))
            == MH_OK) {
            gRealConnectEx = origCex;
            stCex = HOOK_OK;
            logLine("[DLL] ConnectEx resuelto con WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER) y hookeado.");
        } else {
            logLine("[DLL] ERROR: MH_CreateHook(ConnectEx) falló tras WSAIoctl.");
            gRealConnectEx = nullptr;
        }
    } else {
        logLine("[DLL] AVISO: ConnectEx no disponible (WSAIoctl / socket OVERLAPPED).");
        gRealConnectEx = nullptr;
    }

    if (MH_CreateHookApi(L"ws2_32.dll", "socket", reinterpret_cast<LPVOID>(&HookedSocket),
                         reinterpret_cast<LPVOID*>(&gRealSocket))
        == MH_OK) {
        stSock = HOOK_OK;
    } else {
        logLine("[DLL] AVISO: socket() no hookeado.");
        gRealSocket = nullptr;
    }
    if (MH_CreateHookApi(L"ws2_32.dll", "WSASocketW", reinterpret_cast<LPVOID>(&HookedWSASocketW),
                         reinterpret_cast<LPVOID*>(&gRealWSASocketW))
        == MH_OK) {
        stWSk = HOOK_OK;
    } else {
        logLine("[DLL] AVISO: WSASocketW no hookeado.");
        gRealWSASocketW = nullptr;
    }

    if (MH_CreateHookApi(L"ws2_32.dll", "getaddrinfo", reinterpret_cast<LPVOID>(&HookedGetAddrInfo),
                         reinterpret_cast<LPVOID*>(&gRealGetAddrInfo))
        == MH_OK) {
        stGai = HOOK_OK;
    } else {
        logLine("[DLL] AVISO: getaddrinfo no hookeado.");
        gRealGetAddrInfo = nullptr;
    }
    if (MH_CreateHookApi(L"ws2_32.dll", "GetAddrInfoW", reinterpret_cast<LPVOID>(&HookedGetAddrInfoW),
                         reinterpret_cast<LPVOID*>(&gRealGetAddrInfoW))
        == MH_OK) {
        stGaiW = HOOK_OK;
    } else {
        logLine("[DLL] AVISO: GetAddrInfoW no hookeado.");
        gRealGetAddrInfoW = nullptr;
    }
    if (MH_CreateHookApi(L"ws2_32.dll", "gethostbyname", reinterpret_cast<LPVOID>(&HookedGethostbyname),
                         reinterpret_cast<LPVOID*>(&gRealGethostbyname))
        == MH_OK) {
        stGh = HOOK_OK;
    } else {
        logLine("[DLL] AVISO: gethostbyname no hookeado.");
        gRealGethostbyname = nullptr;
    }

    if (gUnloadRequested.load()) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        logLine("[DLL] AVISO: descarga solicitada antes de habilitar hooks.");
        return false;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        logLine("[DLL] ERROR: MH_EnableHook falló");
        MH_Uninitialize();
        return false;
    }

    if (gUnloadRequested.load()) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        logLine("[DLL] AVISO: hooks deshabilitados tras EnableHook por descarga.");
        return false;
    }

    gHooksReady = true;
    char sum[512];
    std::snprintf(sum, sizeof(sum),
                  "[DLL] Resumen hooks: connect=%s WSAConnect=%s ConnectEx=%s socket=%s WSASocketW=%s "
                  "getaddrinfo=%s GetAddrInfoW=%s gethostbyname=%s",
                  stConnect, stWSA, stCex, stSock, stWSk, stGai, stGaiW, stGh);
    logLine(sum);
    logLine("[DLL] DNS: redirección para dofus2-co-* y dofus2-ga-* -> 127.0.0.1:5555.");
    maybeAppendHostsFallback();
    if (isTruthyEnvFlag("DOFUS_REDIRECT_DISABLE_SETTCPENTRY")
        || isTruthyEnvFlag("DOFUS_REDIRECT_NO_SETTCPENTRY")) {
        logLine("[DLL] SetTcpEntry deshabilitado por entorno (DOFUS_REDIRECT_DISABLE_SETTCPENTRY=1). "
                "Solo redirección por hooks connect/WSAConnect/ConnectEx.");
    } else {
        abortExistingIpv4GameConnections();
    }
    return true;
}

DWORD WINAPI InstallHooksThreadProc(LPVOID)
{
    if (gUnloadRequested.load()) {
        return 0;
    }

    if (!installHooksSynchronously()) {
        // No abortar el proceso remoto; dejar traza y continuar.
        logLine("[DLL] AVISO: installHooksSynchronously falló en hilo de inicialización.");
    } else {
        logLine("[DLL] Hooks instalados desde hilo de inicialización.");
    }

    return 0;
}

} // namespace

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD reason, LPVOID)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        gUnloadRequested = false;
        if (!gInitStarted.exchange(true)) {
            gInitThreadHandle = CreateThread(nullptr, 0, &InstallHooksThreadProc, nullptr, 0, nullptr);
            if (gInitThreadHandle == nullptr) {
                logLine("[DLL] ERROR: no se pudo crear hilo para instalar hooks.");
                gInitStarted = false;
            }
        }
        break;
    case DLL_PROCESS_DETACH:
        gUnloadRequested = true;
        if (gInitThreadHandle != nullptr) {
            WaitForSingleObject(gInitThreadHandle, 15000);
            CloseHandle(gInitThreadHandle);
            gInitThreadHandle = nullptr;
        }
        if (gHooksReady.exchange(false)) {
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
        }
        gInitStarted = false;
        break;
    default:
        break;
    }
    return TRUE;
}
