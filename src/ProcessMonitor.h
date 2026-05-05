#pragma once

#include <QThread>
#include <QtGlobal>

#ifdef Q_OS_WIN

/// Hilo que detecta procesos nuevos Dofus.exe y emite \ref dofusProcessDetected una vez por PID vivo.
class ProcessMonitor : public QThread {
    Q_OBJECT

public:
    explicit ProcessMonitor(QObject* parent = nullptr);
    ~ProcessMonitor() override;

    /// Solicita salida del bucle y espera a que termine (hasta ~3 s).
    void stopSafely();

signals:
    void dofusProcessDetected(quint32 pid);

protected:
    void run() override;
};

#endif
