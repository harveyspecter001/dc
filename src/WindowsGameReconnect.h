#pragma once

#include <QtGlobal>

#include <QString>

#ifdef Q_OS_WIN

/// Intenta activar reconexión: enumera ventanas/hijos del PID, busca botón por texto conocido y BM_CLICK,
/// o si no encuentra botón envía Enter a una ventana toplevel visible.
/// Devuelve true si ejecutó alguna acción (puede igual fallar ante UI Qt custom).
bool winTryReconnectGameUi(quint32 pid, QString* actionLogOut);

/// Envía ESC (dos pulsaciones) a la ventana toplevel visible más grande del PID.
bool winPostEscapeToGameWindow(quint32 pid, QString* actionLogOut);

/// Envía Enter a la ventana toplevel visible más grande del PID.
bool winPostEnterToGameWindow(quint32 pid, QString* actionLogOut);

#endif
