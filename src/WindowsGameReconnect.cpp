#include "WindowsGameReconnect.h"

#if defined(Q_OS_WIN)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <vector>

#ifndef IDOK
#define IDOK 1
#endif
#ifndef IDRETRY
#define IDRETRY 4
#endif
#ifndef IDYES
#define IDYES 6
#endif

namespace {

constexpr int kTxtCap = 384;

QString wCharBufToQString(const WCHAR* ws, int cap)
{
    if (!ws || cap <= 0) {
        return {};
    }
    int n = 0;
    while (n < cap && ws[n] != L'\0') {
        ++n;
    }
    return QString::fromWCharArray(ws, n);
}

QString latinLowerFold(const QString& t)
{
    return t.trimmed().toLower();
}

bool titleMatchesReconnect(const QString& trimmedLower)
{
    if (trimmedLower.isEmpty()) {
        return false;
    }

    const QString& l = trimmedLower;
    return l.contains(QLatin1String("reconectar")) || l.contains(QLatin1String("reconnect"))
           || l.contains(QLatin1String("reconnexion")) || l.contains(QLatin1String("connexion"))
           || l.contains(QLatin1String("se connecter"))
           || l.contains(QLatin1String("aceptar")) || l.contains(QLatin1String("accept"))
           || l.contains(QLatin1String("acceptar")) || l.contains(QLatin1String("ok"))
           || l.contains(QLatin1String("continuar")) || l.contains(QLatin1String("continue"))
           || l.contains(QLatin1String("réessayer")) || l.contains(QLatin1String("retry"))
           || l.contains(QLatin1String("intentar")) || l.contains(QLatin1String("connect"))
           || l.contains(QLatin1String("reprendre")) || l.contains(QLatin1String("valider"))
           || l.contains(QLatin1String("jouer")) || l.contains(QLatin1String("fermer"))
           || l.contains(QLatin1String("close")) || l.contains(QLatin1String("got it"));
}

bool tryStandardDialogButtons(HWND root, QString* actionLogOut)
{
    const int ids[]{IDOK, IDYES, IDRETRY};
    for (int id : ids) {
        HWND ch = ::GetDlgItem(root, id);
        if (ch == nullptr || !::IsWindowVisible(ch)) {
            continue;
        }
        WCHAR cls[64]{};
        ::GetClassNameW(ch, cls, static_cast<int>(sizeof(cls) / sizeof(cls[0])) - 1);
        const QString cl = latinLowerFold(wCharBufToQString(cls, static_cast<int>(sizeof(cls))));
        if (!cl.contains(QLatin1String("button"))) {
            continue;
        }
        ::SendMessageW(ch, BM_CLICK, 0, 0);
        if (actionLogOut) {
            *actionLogOut = QStringLiteral("BM_CLICK en botón de diálogo Win32 (control ID %1).").arg(id);
        }
        return true;
    }
    return false;
}

struct CollectCtx {
    DWORD pid = 0;
    std::vector<HWND>* out = nullptr;
};

BOOL CALLBACK enumTopProc(HWND hwnd, LPARAM lp)
{
    auto* cx = reinterpret_cast<CollectCtx*>(lp);
    DWORD wp = 0;
    ::GetWindowThreadProcessId(hwnd, &wp);
    if (wp != cx->pid) {
        return TRUE;
    }
    if (!IsWindowVisible(hwnd)) {
        return TRUE;
    }
    if (::GetAncestor(hwnd, GA_ROOT) != hwnd) {
        return TRUE;
    }
    if (::GetWindow(hwnd, GW_OWNER) != nullptr) {
        return TRUE;
    }
    const LONG ex = ::GetWindowLongW(hwnd, GWL_EXSTYLE);
    if ((ex & WS_EX_TOOLWINDOW) != 0 && (ex & WS_EX_APPWINDOW) == 0) {
        return TRUE;
    }
    cx->out->push_back(hwnd);
    return TRUE;
}

struct BtnCtx {
    HWND buttonHwnd = nullptr;
    HWND fallbackHwnd = nullptr;
};

void considerHwndForMatch(HWND hwnd, BtnCtx* out)
{
    WCHAR title[kTxtCap]{};
    ::GetWindowTextW(hwnd, title, static_cast<int>(sizeof(title) / sizeof(title[0])) - 1);
    const QString qt = latinLowerFold(wCharBufToQString(title, kTxtCap));

    if (!titleMatchesReconnect(qt)) {
        return;
    }

    WCHAR cls[96]{};
    ::GetClassNameW(hwnd, cls, static_cast<int>(sizeof(cls) / sizeof(cls[0])) - 1);
    const QString cl = latinLowerFold(wCharBufToQString(cls, static_cast<int>(sizeof(cls))));

    if (cl.contains(QLatin1String("button"))) {
        out->buttonHwnd = hwnd;
    } else if (out->fallbackHwnd == nullptr) {
        out->fallbackHwnd = hwnd;
    }
}

void walkTree(HWND hwnd, BtnCtx* out)
{
    considerHwndForMatch(hwnd, out);
    ::EnumChildWindows(
        hwnd,
        [](HWND c, LPARAM p) -> BOOL {
            walkTree(c, reinterpret_cast<BtnCtx*>(p));
            return TRUE;
        },
        reinterpret_cast<LPARAM>(out));
}

BtnCtx scanWindowTree(HWND root)
{
    BtnCtx out{};
    walkTree(root, &out);
    return out;
}

void postEnter(HWND hwnd)
{
    ::PostMessageW(hwnd, WM_KEYDOWN, static_cast<WPARAM>(VK_RETURN), 0);
    ::PostMessageW(hwnd, WM_CHAR, static_cast<WPARAM>(VK_RETURN), 0);
    ::PostMessageW(hwnd, WM_KEYUP, static_cast<WPARAM>(VK_RETURN), 0);
}

HWND findLargestTopLevelVisibleHwndForPid(quint32 pid)
{
    if (pid == 0) {
        return nullptr;
    }
    std::vector<HWND> tops;
    CollectCtx cx{static_cast<DWORD>(pid), &tops};
    ::EnumWindows(enumTopProc, reinterpret_cast<LPARAM>(&cx));
    if (tops.empty()) {
        return nullptr;
    }
    std::sort(tops.begin(), tops.end(), [](HWND a, HWND b) {
        RECT ra{};
        RECT rb{};
        if (!GetWindowRect(a, &ra) || !GetWindowRect(b, &rb)) {
            return reinterpret_cast<quintptr>(a) > reinterpret_cast<quintptr>(b);
        }
        const qint64 aa = qint64(std::abs(ra.right - ra.left)) * qint64(std::abs(ra.bottom - ra.top));
        const qint64 bb = qint64(std::abs(rb.right - rb.left)) * qint64(std::abs(rb.bottom - rb.top));
        return aa > bb;
    });
    return tops.front();
}

} // namespace

bool winPostEscapeToGameWindow(quint32 pid, QString* actionLogOut)
{
    if (actionLogOut != nullptr) {
        actionLogOut->clear();
    }
    HWND h = findLargestTopLevelVisibleHwndForPid(pid);
    if (h == nullptr) {
        if (actionLogOut != nullptr) {
            *actionLogOut = QStringLiteral("Sin ventana toplevel visible para ese PID.");
        }
        return false;
    }
    for (int i = 0; i < 2; ++i) {
        ::PostMessageW(h, WM_KEYDOWN, static_cast<WPARAM>(VK_ESCAPE), 0);
        ::PostMessageW(h, WM_KEYUP, static_cast<WPARAM>(VK_ESCAPE), 0);
    }
    if (actionLogOut != nullptr) {
        *actionLogOut = QStringLiteral("ESC×2 en ventana principal más grande (PID).");
    }
    return true;
}

bool winPostEnterToGameWindow(quint32 pid, QString* actionLogOut)
{
    if (actionLogOut != nullptr) {
        actionLogOut->clear();
    }
    HWND h = findLargestTopLevelVisibleHwndForPid(pid);
    if (h == nullptr) {
        if (actionLogOut != nullptr) {
            *actionLogOut = QStringLiteral("Sin ventana toplevel visible para ese PID.");
        }
        return false;
    }
    postEnter(h);
    if (actionLogOut != nullptr) {
        *actionLogOut = QStringLiteral("ENTER en ventana principal más grande (PID).");
    }
    return true;
}

bool winTryReconnectGameUi(quint32 pid, QString* actionLogOut)
{
    if (pid == 0) {
        if (actionLogOut) {
            *actionLogOut = QStringLiteral("(PID inválido)");
        }
        return false;
    }

    std::vector<HWND> tops;
    CollectCtx cx{static_cast<DWORD>(pid), &tops};
    ::EnumWindows(enumTopProc, reinterpret_cast<LPARAM>(&cx));
    if (tops.empty()) {
        if (actionLogOut) {
            *actionLogOut = QStringLiteral("Sin ventana toplevel visible para ese PID.");
        }
        return false;
    }

    std::sort(tops.begin(), tops.end(), [](HWND a, HWND b) {
        RECT ra{};
        RECT rb{};
        if (!GetWindowRect(a, &ra) || !GetWindowRect(b, &rb)) {
            return reinterpret_cast<quintptr>(a) > reinterpret_cast<quintptr>(b);
        }
        const qint64 aa = qint64(std::abs(ra.right - ra.left)) * qint64(std::abs(ra.bottom - ra.top));
        const qint64 bb = qint64(std::abs(rb.right - rb.left)) * qint64(std::abs(rb.bottom - rb.top));
        return aa > bb;
    });

    auto tryBmClick = [](HWND hwnd) -> bool {
        if (hwnd != nullptr && IsWindow(hwnd)) {
            ::SendMessageW(hwnd, BM_CLICK, 0, 0);
            return true;
        }
        return false;
    };

    for (HWND root : tops) {
        WCHAR cap[kTxtCap]{};
        ::GetWindowTextW(root, cap, static_cast<int>(sizeof(cap) / sizeof(cap[0])) - 1);
        const QString capLower = latinLowerFold(wCharBufToQString(cap, kTxtCap));

        QString dlgAct;
        if (tryStandardDialogButtons(root, &dlgAct)) {
            if (actionLogOut) {
                *actionLogOut = dlgAct;
            }
            return true;
        }

        const BtnCtx hit = scanWindowTree(root);

        HWND toClick = hit.buttonHwnd != nullptr ? hit.buttonHwnd : hit.fallbackHwnd;
        if (toClick != nullptr && tryBmClick(toClick)) {
            if (actionLogOut) {
                *actionLogOut =
                    QStringLiteral("BM_CLICK sobre control («reconectar/aceptar/…», clase Button si existe).");
            }
            return true;
        }

        if (titleMatchesReconnect(capLower)) {
            postEnter(root);
            if (actionLogOut) {
                *actionLogOut =
                    QStringLiteral("Tecla Enter enviada a ventana por título (reconectar/…).");
            }
            return true;
        }
    }

    postEnter(tops.front());
    if (actionLogOut) {
        *actionLogOut =
            QStringLiteral("Enter genérico (ventana grande; sin botón reconocido — revisa manual si sigue bloqueado).");
    }
    return false;
}

#endif
