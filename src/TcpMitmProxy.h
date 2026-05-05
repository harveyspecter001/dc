#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>

/// Proxy TCP con una sesión cliente↔upstream a la vez (reenvío bruto).
class TcpMitmProxy : public QObject {
    Q_OBJECT

public:
    explicit TcpMitmProxy(QObject* parent = nullptr);
    ~TcpMitmProxy() override;

    [[nodiscard]] bool isListening() const;

    /// Log opcional: primeros maxRawBytes de cada lectura en hex (puede ser ruidoso).
    void setTrafficLogging(bool enabled, int maxRawBytesPreview);

    /// Log completo por paquete: [CLIENTE→PROXY], [PROXY→SERVIDOR], [SERVIDOR→PROXY], [PROXY→CLIENTE] + HEX.
    void setFullTrafficLog(bool enabled) { fullTrafficLog_ = enabled; }
    [[nodiscard]] bool fullTrafficLog() const { return fullTrafficLog_; }

    /// Logs [PROXY] tamaño, hex primeros 64, detección iri, conexión cliente/upstream.
    void setVerboseDiagnostics(bool enabled) { verboseDiagnostics_ = enabled; }

    /// Colas reenvío, writes parciales, timeouts connect, familia IP; no cambia el payload.
    void setFullDiagnosticMode(bool enabled) { fullDiagnosticMode_ = enabled; }

    /// Tiempo máx. de espera para advertir si el upstream sigue en estado «conectando» (ms).
    void setUpstreamConnectTimeoutMs(int ms) { upstreamConnectTimeoutMs_ = qBound(5000, ms, 300000); }

    /// Solo reenvío byte-a-byte; bloquea inyección manual (☆iri) hacia el servidor.
    void setTransparentMode(bool enabled) { transparentMode_ = enabled; }
    /// Forwarder bruto: sin análisis ni logs en hot-path; solo túnel C↔S.
    void setRawTcpForwarderMode(bool enabled) { rawTcpForwarderMode_ = enabled; }

    /// Log (Registro + qDebug) de cada `write` desde colas hacia upstream/cliente; payload sin modificar.
    void setDrainQueueLogging(bool enabled) { logDrainQueues_ = enabled; }

    /// Eco: no conecta upstream; devuelve al cliente lo que envía (prueba local).
    void setEchoMode(bool enabled) { echoMode_ = enabled; }

    /// Solo acepta TCP, registra datos del cliente; sin upstream ni reenvío (diagnóstico).
    void setMinimalReceiveOnlyMode(bool enabled) { minimalReceiveOnlyMode_ = enabled; }

    /// Si es true (por defecto), además de 127.0.0.1:puerto escucha en [::1]:puerto (clientes IPv6 del hook).
    void setListenIpv6(bool enabled) { listenIpv6_ = enabled; }

    /// Guarda la primera sesión (tramos C→S / S→C) en un .bin bajo el directorio temporal.
    void setHandshakeCaptureEnabled(bool enabled) { handshakeCaptureEnabled_ = enabled; }

    [[nodiscard]] bool transparentMode() const { return transparentMode_; }

    [[nodiscard]] QByteArray lastOutboundFromClient() const { return lastOutboundFromClient_; }

    /// true si `remoteHost_` es una dirección literal IPv4/IPv6 y el puerto > 0.
    [[nodiscard]] bool upstreamTargetConfigured() const { return upstreamEndpointUsable(); }

    [[nodiscard]] QString remoteHostString() const { return remoteHost_; }
    [[nodiscard]] quint16 remotePortValue() const { return remotePort_; }

public slots:
    bool start(const QString& bindAddress, quint16 bindPort, const QString& remoteHost, quint16 remotePort);
    /// Abre el listener sin exigir upstream válido (se resuelve al conectar el cliente o con setUpstream + connectUpstreamForCurrentSession).
    bool startListenOnly(const QString& bindAddress, quint16 bindPort);
    void stop();

    /// Upstream efectivo cuando el siguiente cliente enlaza tras `listen` (no reinicia sockets abiertos).
    void setRemoteEndpoint(const QString& remoteHost, quint16 remotePort);

    /// Alias explícito para configurar el servidor real tras arrancar el listener.
    void setUpstream(const QString& host, int port);

    /// Tras cambiar upstream en la UI: intenta conectar al servidor si ya hay un cliente local.
    void connectUpstreamForCurrentSession();
    /// Limpia upstream en memoria y fuerza redetección (log DLL primero, archivo como fallback).
    void forceUpstreamRedetect();

    /// ☆iri / paquete bruto enviado al servidor real (solo si hay túnel activo).
    [[nodiscard]] QString injectTowardServer(const QByteArray& data);

signals:
    void listeningChanged(bool on);
    void logLine(const QString& line);

    /// Trozo TCP crudo (cliente→servidor o servidor→cliente) para analizar protocolo Ankama en la UI.
    void protocolPayloadCaptured(bool fromClient, const QByteArray& payload);

    /// true cuando cliente local conectado y socket upstream Connected (se puede inject), o modo echo listo.
    void tunnelReadyChanged(bool ready);

private slots:
    void onNewConnection();
    void pumpClientUpstream();
    void pumpUpstreamClient();
    void pumpClientEchoOnly();
    void pumpClientMinimalOnly();
    void onUpstreamConnected();
    void onUpstreamDisconnected();
    void onUpstreamSocketError(QAbstractSocket::SocketError socketError);
    void teardown(const QString& reason);
    void onUpstreamBytesWritten(qint64 bytes);
    void onClientBytesWritten(qint64 bytes);
    void onUpstreamConnectWatchTimeout();
    void onUpstreamNoResponseTimeout();
    void onAutoUpstreamWatchTick();

private:
    [[nodiscard]] QByteArray currentSessionToken5() const;
    [[nodiscard]] QByteArray maybePatchIriToken(const QByteArray& packet, bool* patchedOut = nullptr) const;
    [[nodiscard]] bool upstreamEndpointUsable() const;
    [[nodiscard]] bool openListeners(const QHostAddress& bindIpv4, quint16 bindPort);
    void maybeLogTraffic(const QString& arrowLabel, const QByteArray& chunk);
    void logProxyDetailed(const QString& tag, const QByteArray& chunk);
    void logServerToProxy(const QByteArray& chunk);
    void logFullTrafficPair(const QString& directionTitle, const QByteArray& chunk);
    void logDiag(const QString& line);
    void detectIriInClientChunk(const QByteArray& chunk);
    void recordClientOutboundChunk(const QByteArray& chunk);
    void appendHandshakeCapture(bool clientToServer, const QByteArray& chunk);
    void flushHandshakeCaptureToFile(const QString& reasonTag);

    void drainQueueToUpstream();
    void drainQueueToClient();
    void scheduleUpstreamConnectWatch();
    void cancelUpstreamConnectWatch();
    void armUpstreamNoResponseWatch();
    void clearUpstreamNoResponseWatch();
    void disconnectUpstreamSessionSlots();
    void connectUpstreamSocketToRemote();
    void startAutoUpstreamWatch();
    void stopAutoUpstreamWatch();

    QTcpServer server_;
    QTcpServer server6_;
    QString remoteHost_;
    quint16 remotePort_ = 5555;

    QTcpSocket* client_ = nullptr;
    QTcpSocket upstream_;

    QByteArray pendingFromClient_;
    QByteArray lastOutboundFromClient_;
    QByteArray lastOutboundIriFromClient_;

    bool logTraffic_{false};
    bool fullTrafficLog_{false};
    int trafficRawPreviewMax_{128};
    bool verboseDiagnostics_{true};
    bool fullDiagnosticMode_{false};
    int upstreamConnectTimeoutMs_{60000};
    QTimer upstreamConnectTimer_;
    QTimer upstreamNoResponseTimer_;
    bool awaitingUpstreamResponse_{false};
    QTimer autoUpstreamWatchTimer_;
    QString lastAutoUpstreamHost_;
    bool transparentMode_{false};
    bool echoMode_{false};
    bool minimalReceiveOnlyMode_{false};
    bool listenIpv6_{true};
    bool rawTcpForwarderMode_{false};
    bool logDrainQueues_{false};
    bool handshakeCaptureEnabled_{false};
    QByteArray handshakeCapture_;
    bool handshakeCaptureFlushed_{false};

    /// Reintentos de `connectToHost` al upstream si el servidor cierra pero el cliente local sigue conectado.
    int upstreamAutoRetriesLeft_ = 0;
    /// Se activa al detectar en S→C un host dofus2-ga-*. En ese caso no se reintenta sobre el mismo socket local.
    bool gaHandoffDetected_ = false;
    /// Mantiene el upstream GA por una ventana corta para evitar que auto-detección vuelva a CO.
    QString handoffPreferredHost_;
    quint16 handoffPreferredPort_ = 0;
    qint64 handoffPreferredUntilMs_ = 0;

    /// Colas si `write()` no admite todo el bloque (transparencia real, sin perder bytes).
    QByteArray queueToUpstream_;
    QByteArray queueToClient_;

    qint64 clientConnectEpochMs_ = 0;
};
