#include "TcpMitmProxy.h"

#include <QAbstractSocket>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QHostAddress>
#include <QHostInfo>
#include <QRegularExpression>
#include <QTimer>
#include <QtGlobal>

namespace {
constexpr quint32 kCaptureMagic = 0x31464F44; // 'D''O''F''1' LE on little-endian as dword
constexpr qint64 kCaptureMaxBytes = 32 * 1024 * 1024;

/// Última IP:puerto del mensaje «Redirect IPv4 a.b.c.d:5555» en el log de la DLL.
bool tryUpstreamFromDllRedirectLog(QString* hostOut, quint16* portOut)
{
    if (hostOut == nullptr || portOut == nullptr) {
        return false;
    }
    const QString paths[] = {
        QDir(QDir::tempPath()).absoluteFilePath(QStringLiteral("dofus_redirect_log.txt")),
        QStringLiteral("C:/dofus_dll_log.txt"),
    };
    QString pathChosen;
    for (const QString& path : paths) {
        if (QFile::exists(path)) {
            pathChosen = path;
            break;
        }
    }
    if (pathChosen.isEmpty()) {
        return false;
    }
    QFile f(pathChosen);
    if (!f.open(QIODevice::ReadOnly)) {
        return false;
    }
    const qint64 sz = f.size();
    constexpr qint64 kTail = 65536;
    if (sz > kTail) {
        f.seek(sz - kTail);
        f.readLine();
    }
    const QString text = QString::fromUtf8(f.readAll());
    const QRegularExpression re(QStringLiteral(R"(Redirect IPv4 (\d+)\.(\d+)\.(\d+)\.(\d+):(\d+))"));
    QString lastHost;
    quint16 lastPort = 0;
    for (auto it = re.globalMatch(text); it.hasNext();) {
        const QRegularExpressionMatch m = it.next();
        lastHost = QStringLiteral("%1.%2.%3.%4")
                       .arg(m.captured(1), m.captured(2), m.captured(3), m.captured(4));
        lastPort = m.captured(5).toUShort();
    }
    if (lastPort == 0 || lastHost.isEmpty()) {
        return false;
    }
    *hostOut = lastHost;
    *portOut = lastPort;
    return true;
}

bool tryResolveUpstreamFromDllHostName(QString* hostOut, quint16* portOut)
{
    if (hostOut == nullptr || portOut == nullptr) {
        return false;
    }
    const QString paths[] = {
        QDir(QDir::tempPath()).absoluteFilePath(QStringLiteral("dofus_redirect_log.txt")),
        QStringLiteral("C:/dofus_dll_log.txt"),
    };
    QString pathChosen;
    for (const QString& path : paths) {
        if (QFile::exists(path)) {
            pathChosen = path;
            break;
        }
    }
    if (pathChosen.isEmpty()) {
        return false;
    }
    QFile f(pathChosen);
    if (!f.open(QIODevice::ReadOnly)) {
        return false;
    }
    const qint64 sz = f.size();
    constexpr qint64 kTail = 65536;
    if (sz > kTail) {
        f.seek(sz - kTail);
        f.readLine();
    }
    const QString text = QString::fromUtf8(f.readAll());
    const QRegularExpression reHost(QStringLiteral(R"(getaddrinfo DNS redir: nodo «([^»]+)»)"));
    QString lastHost;
    for (auto it = reHost.globalMatch(text); it.hasNext();) {
        const QRegularExpressionMatch m = it.next();
        const QString h = m.captured(1).trimmed();
        if (!h.isEmpty()) {
            lastHost = h;
        }
    }
    if (lastHost.isEmpty()) {
        return false;
    }

    const QHostInfo info = QHostInfo::fromName(lastHost);
    if (info.error() != QHostInfo::NoError) {
        const QString hostLower = lastHost.toLower();
        if (hostLower.contains(QStringLiteral("dofus2-co-beta.ankama-games.com"))) {
            *hostOut = QStringLiteral("52.213.90.139");
            *portOut = 5555;
            return true;
        }
        if (hostLower.contains(QStringLiteral("dofus2-co-production.ankama-games.com"))) {
            *hostOut = QStringLiteral("54.76.83.103");
            *portOut = 5555;
            return true;
        }
        return false;
    }
    for (const QHostAddress& a : info.addresses()) {
        if (a.protocol() == QHostAddress::IPv4Protocol && !a.isLoopback()) {
            *hostOut = a.toString();
            *portOut = 5555;
            return true;
        }
    }
    return false;
}

bool tryUpstreamFromSharedIpFile(QString* hostOut)
{
    if (hostOut == nullptr) {
        return false;
    }
    const QFileInfo fi(QStringLiteral("C:\\dofus_upstream_ip.txt"));
    if (!fi.exists()) {
        return false;
    }
    // Evita reutilizar IPs antiguas (ej.: producción) cuando el servidor cambia (beta).
    const qint64 ageSec = fi.lastModified().secsTo(QDateTime::currentDateTime());
    if (ageSec > 120) {
        return false;
    }
    QFile f(fi.absoluteFilePath());
    if (!f.open(QIODevice::ReadOnly)) {
        return false;
    }
    const QString ip = QString::fromUtf8(f.readAll()).trimmed();
    const QHostAddress a(ip);
    if (ip.isEmpty() || a.isNull() || a.protocol() != QHostAddress::IPv4Protocol) {
        return false;
    }
    *hostOut = ip;
    return true;
}

QString hexPreviewBytes(const QByteArray& data, int maxBytes)
{
    const int take = qMin(data.size(), maxBytes);
    return QString::fromLatin1(data.left(take).toHex());
}

bool tryExtractGaHostFromPayload(const QByteArray& payload, QString* hostOut)
{
    if (hostOut == nullptr || payload.isEmpty()) {
        return false;
    }
    const QString text = QString::fromLatin1(payload);
    const QRegularExpression re(QStringLiteral(R"((dofus2-ga-[a-z0-9\-\.]+\.ankama-games\.com))"),
                                QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch m = re.match(text);
    if (!m.hasMatch()) {
        return false;
    }
    *hostOut = m.captured(1).toLower();
    return !hostOut->isEmpty();
}

bool tryResolveNonLoopbackIpv4(const QString& hostName, QString* ipOut)
{
    if (ipOut == nullptr || hostName.trimmed().isEmpty()) {
        return false;
    }
    const QHostInfo info = QHostInfo::fromName(hostName);
    if (info.error() != QHostInfo::NoError) {
        return false;
    }
    for (const QHostAddress& a : info.addresses()) {
        if (a.protocol() == QHostAddress::IPv4Protocol && !a.isLoopback()) {
            *ipOut = a.toString();
            return true;
        }
    }
    return false;
}
} // namespace

TcpMitmProxy::TcpMitmProxy(QObject* parent)
    : QObject(parent)
    , server_(this)
    , server6_(this)
    , upstream_(this)
{
    upstreamConnectTimer_.setSingleShot(true);
    connect(&upstreamConnectTimer_, &QTimer::timeout, this, &TcpMitmProxy::onUpstreamConnectWatchTimeout);
    upstreamNoResponseTimer_.setSingleShot(true);
    upstreamNoResponseTimer_.setInterval(30000);
    connect(&upstreamNoResponseTimer_, &QTimer::timeout, this, &TcpMitmProxy::onUpstreamNoResponseTimeout);
    autoUpstreamWatchTimer_.setInterval(1200);
    connect(&autoUpstreamWatchTimer_, &QTimer::timeout, this, &TcpMitmProxy::onAutoUpstreamWatchTick);
    connect(&upstream_, &QIODevice::bytesWritten, this, &TcpMitmProxy::onUpstreamBytesWritten);
}

bool TcpMitmProxy::isListening() const
{
    return server_.isListening() || server6_.isListening();
}

TcpMitmProxy::~TcpMitmProxy()
{
    stop();
}

void TcpMitmProxy::setTrafficLogging(bool enabled, int maxRawBytesPreview)
{
    logTraffic_ = enabled && !rawTcpForwarderMode_;
    trafficRawPreviewMax_ = qBound(8, maxRawBytesPreview, 8192);
}

void TcpMitmProxy::logFullTrafficPair(const QString& directionTitle, const QByteArray& chunk)
{
    if (!fullTrafficLog_ || chunk.isEmpty()) {
        return;
    }
    QString hex;
    hex.reserve(qMin(chunk.size() * 3 + 8, 48 * 1024 * 1024));
    for (int i = 0; i < chunk.size(); ++i) {
        if (i > 0) {
            hex += QLatin1Char(' ');
        }
        hex += QStringLiteral("%1").arg(quint8(chunk[i]), 2, 16, QLatin1Char('0')).toUpper();
    }
    emit logLine(directionTitle + QLatin1Char(' ') + QString::number(chunk.size())
                 + QStringLiteral(" bytes\nHEX: ") + hex);
}

bool TcpMitmProxy::upstreamEndpointUsable() const
{
    if (remotePort_ == 0) {
        return false;
    }
    const QHostAddress a(remoteHost_);
    return !a.isNull()
        && (a.protocol() == QHostAddress::IPv4Protocol || a.protocol() == QHostAddress::IPv6Protocol);
}

bool TcpMitmProxy::openListeners(const QHostAddress& bindIpv4, quint16 bindPort)
{
    disconnect(&server_, nullptr, this, nullptr);
    disconnect(&server6_, nullptr, this, nullptr);
    server_.close();
    server6_.close();

    connect(&server_, &QTcpServer::newConnection, this, &TcpMitmProxy::onNewConnection);
    connect(&server6_, &QTcpServer::newConnection, this, &TcpMitmProxy::onNewConnection);

    if (!server_.listen(bindIpv4, bindPort)) {
        const QString er = server_.errorString();
        emit logLine(QStringLiteral("[PROXY] No se pudo escuchar en ") + bindIpv4.toString() + QLatin1Char(':')
                     + QString::number(bindPort) + QStringLiteral(" — ") + er);
        emit listeningChanged(false);
        return false;
    }

    emit logLine(QStringLiteral("[PROXY] Escuchando %1:%2 (IPv4)")
                     .arg(bindIpv4.toString())
                     .arg(bindPort));

    if (listenIpv6_) {
        const QHostAddress loop6(QStringLiteral("::1"));
        if (!server6_.listen(loop6, bindPort)) {
            emit logLine(QStringLiteral("[PROXY] AVISO: no se pudo escuchar en [::1]:%1 — %2")
                             .arg(bindPort)
                             .arg(server6_.errorString()));
        } else {
            emit logLine(QStringLiteral("[PROXY] Escuchando [::1]:%1 (IPv6 loopback)").arg(bindPort));
        }
    }

    emit listeningChanged(true);
    return true;
}

bool TcpMitmProxy::start(const QString& bindAddress, quint16 bindPort, const QString& remoteHost, quint16 remotePort)
{
    stop();

    disconnectUpstreamSessionSlots();

    remoteHost_ = remoteHost.trimmed();
    remotePort_ = remotePort;

    const QHostAddress addr(bindAddress.trimmed());
    if (!openListeners(addr, bindPort)) {
        return false;
    }

    emit logLine(QStringLiteral("[PROXY] Upstream (IP literal, sin resolución DNS del sistema): %1:%2")
                     .arg(remoteHost_)
                     .arg(remotePort_));
    if (minimalReceiveOnlyMode_) {
        emit logLine(QStringLiteral("[PROXY] Proxy mínimo: sin reenvío a upstream."));
    }
    if (echoMode_) {
        emit logLine(QStringLiteral("[PROXY] Modo ECHO activo: no se abrirá conexión TCP al upstream."));
    }
    if (transparentMode_) {
        emit logLine(QStringLiteral("[PROXY] Modo TRANSPARENTE: reenvío bruto; la inyección manual de paquetes está "
                                    "desactivada."));
    }
    if (rawTcpForwarderMode_) {
        emit logLine(QStringLiteral("[PROXY] RAW TCP FORWARDER: túnel transparente total (sin análisis en hot-path)."));
    }
    startAutoUpstreamWatch();
    return true;
}

bool TcpMitmProxy::startListenOnly(const QString& bindAddress, quint16 bindPort)
{
    stop();

    disconnectUpstreamSessionSlots();

    const QHostAddress addr(bindAddress.trimmed());
    if (!openListeners(addr, bindPort)) {
        return false;
    }

    const QString upDesc = upstreamEndpointUsable()
        ? (remoteHost_ + QLatin1Char(':') + QString::number(remotePort_))
        : QStringLiteral("(pendiente: IP del servidor real en la UI, o redirect en %TEMP%\\dofus_redirect_log.txt al "
                         "conectar el juego)");
    emit logLine(QStringLiteral("[PROXY] Escuchando %1:%2 — upstream %3")
                     .arg(bindAddress.trimmed())
                     .arg(bindPort)
                     .arg(upDesc));
    if (minimalReceiveOnlyMode_) {
        emit logLine(QStringLiteral("[PROXY] Proxy mínimo: sin reenvío a upstream."));
    }
    if (echoMode_) {
        emit logLine(QStringLiteral("[PROXY] Modo ECHO activo: no se abrirá conexión TCP al upstream."));
    }
    if (transparentMode_) {
        emit logLine(QStringLiteral("[PROXY] Modo TRANSPARENTE: reenvío bruto; la inyección manual de paquetes está "
                                    "desactivada."));
    }
    if (rawTcpForwarderMode_) {
        emit logLine(QStringLiteral("[PROXY] RAW TCP FORWARDER: túnel transparente total (sin análisis en hot-path)."));
    }
    startAutoUpstreamWatch();
    return true;
}

QString TcpMitmProxy::injectTowardServer(const QByteArray& data)
{
    if (transparentMode_) {
        return QStringLiteral(
            "Modo transparente activo: no se permite inyectar/modificar paquetes desde la UI.\n"
            "Desmarca «Modo transparente» si necesitas enviar plantillas ☆iri manualmente.");
    }
    if (!client_) {
        return QStringLiteral(
            "No hay cliente TCP conectado al proxy.\n\n"
            "Comprueba que el juego conecta a 127.0.0.1:5555 con el proxy activo.\n"
            "Orden: inyectar DLL + Iniciar proxy → entrar al mundo / reconectar.");
    }
    if (echoMode_) {
        return QStringLiteral("Modo ECHO: no hay servidor upstream; no se puede inyectar hacia el mundo real.");
    }
    if (upstream_.state() != QAbstractSocket::ConnectedState) {
        return QStringLiteral(
            "Aún sin túnel hacia el servidor (upstream no conectado). Espera o revisa IP/puerto real.");
    }
    if (data.isEmpty()) {
        return {};
    }

    bool patched = false;
    const QByteArray use = maybePatchIriToken(data, &patched);
    if (patched) {
        emit logLine(QStringLiteral("[INJECT] Token ☆iri reemplazado automáticamente (offset 17, 5 bytes)."));
    }
    queueToUpstream_.append(use);
    drainQueueToUpstream();
    emit logLine(QStringLiteral("[MOV] Inyectados %1 bytes hacia servidor (cola C→S).").arg(use.size()));
    return {};
}

QByteArray TcpMitmProxy::currentSessionToken5() const
{
    static constexpr int kTokOff = 17;
    static constexpr int kTokLen = 5;
    if (lastOutboundIriFromClient_.size() < (kTokOff + kTokLen)) {
        return {};
    }
    return lastOutboundIriFromClient_.mid(kTokOff, kTokLen);
}

QByteArray TcpMitmProxy::maybePatchIriToken(const QByteArray& packet, bool* patchedOut) const
{
    if (patchedOut != nullptr) {
        *patchedOut = false;
    }
    if (packet.isEmpty()) {
        return packet;
    }
    static const QByteArray needle = QByteArrayLiteral("type.ankama.com/iri");
    if (!packet.contains(needle)) {
        return packet;
    }
    const QByteArray tok = currentSessionToken5();
    if (tok.size() != 5) {
        return packet;
    }
    static constexpr int kTokOff = 17;
    if (packet.size() < (kTokOff + 5)) {
        return packet;
    }
    QByteArray out = packet;
    out.replace(kTokOff, 5, tok);
    if (patchedOut != nullptr) {
        *patchedOut = true;
    }
    return out;
}

void TcpMitmProxy::stop()
{
    cancelUpstreamConnectWatch();
    clearUpstreamNoResponseWatch();
    stopAutoUpstreamWatch();
    if (handshakeCaptureEnabled_ && !handshakeCapture_.isEmpty() && !handshakeCaptureFlushed_) {
        flushHandshakeCaptureToFile(QStringLiteral("stop"));
    }
    upstreamAutoRetriesLeft_ = 0;
    gaHandoffDetected_ = false;
    handoffPreferredHost_.clear();
    handoffPreferredPort_ = 0;
    handoffPreferredUntilMs_ = 0;
    emit tunnelReadyChanged(false);
    disconnect(&server_, nullptr, this, nullptr);
    disconnect(&server6_, nullptr, this, nullptr);
    server_.close();
    server6_.close();

    disconnectUpstreamSessionSlots();
    if (client_) {
        disconnect(client_, nullptr, this, nullptr);
        client_->disconnectFromHost();
        client_->deleteLater();
        client_ = nullptr;
    }
    upstream_.disconnectFromHost();
    upstream_.close();
    pendingFromClient_.clear();
    queueToUpstream_.clear();
    queueToClient_.clear();
    lastOutboundFromClient_.clear();
    lastOutboundIriFromClient_.clear();
    handshakeCapture_.clear();
    handshakeCaptureFlushed_ = false;
    lastAutoUpstreamHost_.clear();

    emit listeningChanged(false);
}

void TcpMitmProxy::setRemoteEndpoint(const QString& remoteHost, quint16 remotePort)
{
    remoteHost_ = remoteHost.trimmed();
    remotePort_ = remotePort;
}

void TcpMitmProxy::setUpstream(const QString& host, int port)
{
    const int p = qBound(0, port, 65535);
    setRemoteEndpoint(host, static_cast<quint16>(p));
}

void TcpMitmProxy::forceUpstreamRedetect()
{
    const QString oldHost = remoteHost_;
    const quint16 oldPort = remotePort_;
    remoteHost_.clear();
    remotePort_ = 5555;

    QString autoHost;
    quint16 autoPort = 0;
    if (tryUpstreamFromDllRedirectLog(&autoHost, &autoPort)) {
        remoteHost_ = autoHost;
        remotePort_ = autoPort == 0 ? quint16(5555) : autoPort;
        emit logLine(QStringLiteral("[PROXY] Upstream redetectado desde log DLL: %1:%2")
                         .arg(remoteHost_)
                         .arg(remotePort_));
    } else if (tryUpstreamFromSharedIpFile(&autoHost)) {
        remoteHost_ = autoHost;
        remotePort_ = 5555;
        emit logLine(QStringLiteral("[PROXY] Upstream fallback desde C:\\dofus_upstream_ip.txt: %1:%2")
                         .arg(remoteHost_)
                         .arg(remotePort_));
    } else {
        emit logLine(QStringLiteral("[PROXY] Upstream: detectando... (sin dato aún en log DLL ni archivo)."));
    }

    const bool changed = (oldHost != remoteHost_) || (oldPort != remotePort_);
    if (changed && client_ != nullptr && !echoMode_ && !minimalReceiveOnlyMode_
        && upstream_.state() == QAbstractSocket::UnconnectedState && upstreamEndpointUsable()) {
        disconnectUpstreamSessionSlots();
        connect(&upstream_, &QTcpSocket::readyRead, this, &TcpMitmProxy::pumpUpstreamClient);
        connect(&upstream_, &QTcpSocket::connected, this, &TcpMitmProxy::onUpstreamConnected);
        connect(&upstream_, &QTcpSocket::disconnected, this, &TcpMitmProxy::onUpstreamDisconnected);
        connect(&upstream_, &QAbstractSocket::errorOccurred, this, &TcpMitmProxy::onUpstreamSocketError);
        emit logLine(QStringLiteral("[PROXY] Redetección: conectando a %1:%2").arg(remoteHost_).arg(remotePort_));
        connectUpstreamSocketToRemote();
        scheduleUpstreamConnectWatch();
    }
}

void TcpMitmProxy::connectUpstreamForCurrentSession()
{
    if (echoMode_ || minimalReceiveOnlyMode_) {
        emit logLine(QStringLiteral("[PROXY] Aplicar upstream: ignorado en modo ECHO o proxy mínimo."));
        return;
    }
    if (client_ == nullptr) {
        if (upstreamEndpointUsable()) {
            emit logLine(QStringLiteral(
                "[PROXY] Upstream guardado; se usará cuando un cliente se conecte al proxy (127.0.0.1 o ::1)."));
        }
        return;
    }
    if (!upstreamEndpointUsable()) {
        emit logLine(QStringLiteral("[PROXY] Upstream no válido: dirección literal IPv4/IPv6 y puerto > 0 en la UI."));
        return;
    }
    if (upstream_.state() == QAbstractSocket::ConnectedState) {
        emit logLine(QStringLiteral("[PROXY] Upstream ya estaba conectado."));
        return;
    }
    if (upstream_.state() != QAbstractSocket::UnconnectedState) {
        upstream_.abort();
    }
    disconnectUpstreamSessionSlots();
    connect(&upstream_, &QTcpSocket::readyRead, this, &TcpMitmProxy::pumpUpstreamClient);
    connect(&upstream_, &QTcpSocket::connected, this, &TcpMitmProxy::onUpstreamConnected);
    connect(&upstream_, &QTcpSocket::disconnected, this, &TcpMitmProxy::onUpstreamDisconnected);
    connect(&upstream_, &QAbstractSocket::errorOccurred, this, &TcpMitmProxy::onUpstreamSocketError);
    emit logLine(QStringLiteral("[PROXY] Conectando upstream a %1:%2 (servidor real; no 127.0.0.1)")
                     .arg(remoteHost_)
                     .arg(remotePort_));
    connectUpstreamSocketToRemote();
    scheduleUpstreamConnectWatch();
}

void TcpMitmProxy::scheduleUpstreamConnectWatch()
{
    cancelUpstreamConnectWatch();
    upstreamConnectTimer_.start(upstreamConnectTimeoutMs_);
}

void TcpMitmProxy::cancelUpstreamConnectWatch()
{
    if (upstreamConnectTimer_.isActive()) {
        upstreamConnectTimer_.stop();
    }
}

void TcpMitmProxy::armUpstreamNoResponseWatch()
{
    if (rawTcpForwarderMode_) {
        return;
    }
    if (!client_ || upstream_.state() != QAbstractSocket::ConnectedState) {
        return;
    }
    awaitingUpstreamResponse_ = true;
    upstreamNoResponseTimer_.start();
}

void TcpMitmProxy::clearUpstreamNoResponseWatch()
{
    awaitingUpstreamResponse_ = false;
    if (upstreamNoResponseTimer_.isActive()) {
        upstreamNoResponseTimer_.stop();
    }
}

void TcpMitmProxy::disconnectUpstreamSessionSlots()
{
    disconnect(&upstream_, &QTcpSocket::readyRead, this, nullptr);
    disconnect(&upstream_, &QTcpSocket::connected, this, nullptr);
    disconnect(&upstream_, &QTcpSocket::disconnected, this, nullptr);
    disconnect(&upstream_, &QAbstractSocket::errorOccurred, this, nullptr);
}

void TcpMitmProxy::connectUpstreamSocketToRemote()
{
    const QHostAddress addr(remoteHost_);
    upstream_.connectToHost(addr, remotePort_);
}

void TcpMitmProxy::startAutoUpstreamWatch()
{
    if (!autoUpstreamWatchTimer_.isActive()) {
        autoUpstreamWatchTimer_.start();
    }
}

void TcpMitmProxy::stopAutoUpstreamWatch()
{
    if (autoUpstreamWatchTimer_.isActive()) {
        autoUpstreamWatchTimer_.stop();
    }
}

void TcpMitmProxy::onAutoUpstreamWatchTick()
{
    if (rawTcpForwarderMode_) {
        return;
    }
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    if (!handoffPreferredHost_.isEmpty() && handoffPreferredPort_ > 0 && nowMs < handoffPreferredUntilMs_) {
        if (remoteHost_ != handoffPreferredHost_ || remotePort_ != handoffPreferredPort_) {
            remoteHost_ = handoffPreferredHost_;
            remotePort_ = handoffPreferredPort_;
            emit logLine(QStringLiteral("[PROXY] Manteniendo upstream de handoff CO→GA: %1:%2")
                             .arg(remoteHost_)
                             .arg(remotePort_));
        }
        return;
    }
    QString autoHost;
    quint16 autoPort = 0;
    if (tryUpstreamFromDllRedirectLog(&autoHost, &autoPort)) {
        if (autoPort == 0) {
            autoPort = 5555;
        }
    } else if (tryResolveUpstreamFromDllHostName(&autoHost, &autoPort)) {
        // Resuelto por DNS a partir del host original (production/beta) del log DLL.
    } else if (tryUpstreamFromSharedIpFile(&autoHost)) {
        autoPort = 5555;
    } else {
        return;
    }
    const quint16 newPort = autoPort;
    if (autoHost == remoteHost_ && newPort == remotePort_ && autoHost == lastAutoUpstreamHost_) {
        return;
    }

    const bool changed = (remoteHost_ != autoHost) || (remotePort_ != newPort);
    remoteHost_ = autoHost;
    remotePort_ = newPort;
    lastAutoUpstreamHost_ = autoHost;

    if (changed) {
        emit logLine(QStringLiteral("[PROXY] Upstream auto-detectado: %1:%2")
                         .arg(remoteHost_)
                         .arg(remotePort_));
    }

    if (echoMode_ || minimalReceiveOnlyMode_ || client_ == nullptr) {
        return;
    }

    if (upstream_.state() == QAbstractSocket::ConnectedState) {
        const QString peer = upstream_.peerAddress().toString();
        const quint16 pport = upstream_.peerPort();
        if (peer == remoteHost_ && pport == remotePort_) {
            return;
        }
        emit logLine(QStringLiteral(
            "[PROXY] Upstream cambió en caliente (%1:%2 -> %3:%4). Reconectando túnel...")
                         .arg(peer)
                         .arg(pport)
                         .arg(remoteHost_)
                         .arg(remotePort_));
        upstream_.abort();
        return;
    }

    if (upstream_.state() == QAbstractSocket::UnconnectedState) {
        disconnectUpstreamSessionSlots();
        connect(&upstream_, &QTcpSocket::readyRead, this, &TcpMitmProxy::pumpUpstreamClient);
        connect(&upstream_, &QTcpSocket::connected, this, &TcpMitmProxy::onUpstreamConnected);
        connect(&upstream_, &QTcpSocket::disconnected, this, &TcpMitmProxy::onUpstreamDisconnected);
        connect(&upstream_, &QAbstractSocket::errorOccurred, this, &TcpMitmProxy::onUpstreamSocketError);
        emit logLine(QStringLiteral("[PROXY] Auto-upstream: conectando a %1:%2 (servidor real; no 127.0.0.1)")
                         .arg(remoteHost_)
                         .arg(remotePort_));
        connectUpstreamSocketToRemote();
        scheduleUpstreamConnectWatch();
    }
}

void TcpMitmProxy::onUpstreamConnectWatchTimeout()
{
    if (upstream_.state() == QAbstractSocket::ConnectingState) {
        emit logLine(QStringLiteral(
            "[PROXY] AVISO: upstream sigue «conectando» tras %1 s — handshake TCP lento, firewall o servidor "
            "ocupado. No se aborta por esto; el intento continúa hasta que el SO indique éxito o error.")
            .arg(upstreamConnectTimeoutMs_ / 1000));
        logDiag(QStringLiteral("upstream timeout soft: state=Connecting, QAbstractSocket::SocketError=%1 — %2")
                    .arg(int(upstream_.error()))
                    .arg(upstream_.errorString()));
    }
}

void TcpMitmProxy::onUpstreamNoResponseTimeout()
{
    if (rawTcpForwarderMode_) {
        return;
    }
    if (!awaitingUpstreamResponse_) {
        return;
    }
    if (client_ == nullptr || client_->state() != QAbstractSocket::ConnectedState
        || upstream_.state() != QAbstractSocket::ConnectedState) {
        clearUpstreamNoResponseWatch();
        return;
    }
    emit logLine(QStringLiteral(
        "[PROXY] Sin respuesta del servidor en 30 s tras tráfico C→S: se cierra upstream y se reintenta conexión."));
    logDiag(QStringLiteral("timeout sin respuesta S→C (30s), abort upstream para reconectar"));
    clearUpstreamNoResponseWatch();
    upstream_.abort();
}

void TcpMitmProxy::logDiag(const QString& line)
{
    if (!fullDiagnosticMode_ || rawTcpForwarderMode_) {
        return;
    }
    emit logLine(QStringLiteral("[DIAG] ") + line);
}

void TcpMitmProxy::onUpstreamBytesWritten(qint64)
{
    drainQueueToUpstream();
}

void TcpMitmProxy::onClientBytesWritten(qint64)
{
    drainQueueToClient();
}

void TcpMitmProxy::drainQueueToUpstream()
{
    if (queueToUpstream_.isEmpty()) {
        return;
    }
    if (upstream_.state() != QAbstractSocket::ConnectedState) {
        return;
    }
    const qint64 n = upstream_.write(queueToUpstream_);
    if (n < 0) {
        logDiag(QStringLiteral("write C→S falló: %1").arg(upstream_.errorString()));
        emit logLine(QStringLiteral("[PROXY] ERROR: no se pudo volcar cola hacia upstream — %1")
                         .arg(upstream_.errorString()));
        return;
    }
    if (n > 0) {
        const QByteArray sentSlice = queueToUpstream_.left(int(n));
        if (logDrainQueues_ && !fullTrafficLog_) {
            const int hxCount = qMin(int(n), 64);
            qDebug() << "[PROXY] Reenviando" << n << "bytes (cliente→servidor, cola→upstream)";
            emit logLine(
                QStringLiteral("[PROXY] Cliente→Servidor (cola→upstream): %1 bytes · hex primeros %2: %3%4")
                    .arg(n)
                    .arg(hxCount)
                    .arg(hexPreviewBytes(sentSlice, hxCount))
                    .arg(sentSlice.size() > hxCount ? QStringLiteral("…") : QString()));
        }
        queueToUpstream_.remove(0, int(n));
    }
    if (fullDiagnosticMode_ && !queueToUpstream_.isEmpty()) {
        logDiag(QStringLiteral("cola hacia servidor pendiente: %1 bytes (buffer lleno, se reenvía con bytesWritten)")
                    .arg(queueToUpstream_.size()));
    }
}

void TcpMitmProxy::drainQueueToClient()
{
    if (!client_ || queueToClient_.isEmpty()) {
        return;
    }
    if (client_->state() != QAbstractSocket::ConnectedState) {
        return;
    }
    const qint64 n = client_->write(queueToClient_);
    if (n < 0) {
        logDiag(QStringLiteral("write S→C falló: %1").arg(client_->errorString()));
        emit logLine(QStringLiteral("[PROXY] ERROR: no se pudo volcar cola hacia cliente — %1")
                         .arg(client_->errorString()));
        return;
    }
    if (n > 0) {
        const QByteArray sentSlice = queueToClient_.left(int(n));
        if (logDrainQueues_ && !fullTrafficLog_) {
            const int hxCount = qMin(int(n), 64);
            qDebug() << "[PROXY] Servidor→Cliente:" << n << "bytes (cola→socket)";
            emit logLine(QStringLiteral("[PROXY] Servidor→Cliente: %1 bytes · hex primeros %2: %3%4")
                             .arg(n)
                             .arg(hxCount)
                             .arg(QString::fromLatin1(sentSlice.left(hxCount).toHex()))
                             .arg(sentSlice.size() > hxCount ? QStringLiteral("…") : QString()));
        }
        queueToClient_.remove(0, int(n));
    }
    if (fullDiagnosticMode_ && !queueToClient_.isEmpty()) {
        logDiag(QStringLiteral("cola hacia cliente pendiente: %1 bytes (buffer lleno)")
                    .arg(queueToClient_.size()));
    }
}

void TcpMitmProxy::maybeLogTraffic(const QString& arrowLabel, const QByteArray& chunk)
{
    if (fullTrafficLog_ || !logTraffic_ || chunk.isEmpty()) {
        return;
    }
    QString hex;
    const int take = qMin(chunk.size(), qMax(1, trafficRawPreviewMax_));
    const QByteArray slice = chunk.left(take);
    hex.reserve(slice.size() * 3);
    for (int i = 0; i < slice.size(); ++i) {
        hex += QStringLiteral("%1 ").arg(quint8(slice[i]), 2, 16, QLatin1Char('0')).toUpper();
    }
    hex = hex.trimmed();
    emit logLine(QStringLiteral("[tcp ").append(arrowLabel).append(QStringLiteral(" %1 bytes] ")).arg(chunk.size())
                 + hex + (chunk.size() > take ? QStringLiteral(" …") : QString()));
}

void TcpMitmProxy::logProxyDetailed(const QString& tag, const QByteArray& chunk)
{
    if (fullTrafficLog_) {
        return;
    }
    if (chunk.isEmpty() || (!verboseDiagnostics_ && !fullDiagnosticMode_)) {
        return;
    }
    const int n = chunk.size();
    const QByteArray head = chunk.left(64);
    const QString hex = head.toHex();
    emit logLine(QStringLiteral("[PROXY] %1: %2 bytes · hex primeros %3: %4")
                     .arg(tag)
                     .arg(n)
                     .arg(head.size())
                     .arg(hex));
}

void TcpMitmProxy::logServerToProxy(const QByteArray& chunk)
{
    if (fullTrafficLog_) {
        return;
    }
    if (chunk.isEmpty() || (!verboseDiagnostics_ && !fullDiagnosticMode_ && !logTraffic_)) {
        return;
    }
    const int n = chunk.size();
    const QByteArray head = chunk.left(64);
    const QString hex = head.toHex();
    emit logLine(QStringLiteral("[PROXY] Servidor→Proxy: %1 bytes · hex primeros %2: %3")
                     .arg(n)
                     .arg(head.size())
                     .arg(hex));
}

void TcpMitmProxy::detectIriInClientChunk(const QByteArray& chunk)
{
    if (!verboseDiagnostics_ || chunk.isEmpty()) {
        return;
    }
    static const QByteArray needle = QByteArrayLiteral("type.ankama.com/iri");
    const int idx = chunk.indexOf(needle);
    if (idx < 0) {
        return;
    }
    emit logLine(QStringLiteral("[PROXY] *** PAQUETE MAPA / iri *** substring «type.ankama.com/iri» en offset %1 "
                                "(trozo cliente→proxy %2 bytes)")
                     .arg(idx)
                     .arg(chunk.size()));
}

void TcpMitmProxy::recordClientOutboundChunk(const QByteArray& chunk)
{
    if (!chunk.isEmpty()) {
        lastOutboundFromClient_ = chunk;
        static const QByteArray needle = QByteArrayLiteral("type.ankama.com/iri");
        if (chunk.contains(needle)) {
            lastOutboundIriFromClient_ = chunk;
        }
    }
}

void TcpMitmProxy::appendHandshakeCapture(bool clientToServer, const QByteArray& chunk)
{
    if (!handshakeCaptureEnabled_ || handshakeCaptureFlushed_ || chunk.isEmpty()) {
        return;
    }
    if (handshakeCapture_.size() + 9 + chunk.size() > kCaptureMaxBytes) {
        emit logLine(QStringLiteral("[PROXY] Captura .bin: límite de tamaño alcanzado; se deja de grabar."));
        handshakeCaptureEnabled_ = false;
        return;
    }
    // Bloque: magic LE + dir u8 + len LE32 + payload
    handshakeCapture_.append(reinterpret_cast<const char*>(&kCaptureMagic), 4);
    const quint8 dir = clientToServer ? 0 : 1;
    handshakeCapture_.append(char(dir));
    const quint32 len = quint32(chunk.size());
    handshakeCapture_.append(reinterpret_cast<const char*>(&len), 4);
    handshakeCapture_.append(chunk);
}

void TcpMitmProxy::flushHandshakeCaptureToFile(const QString& reasonTag)
{
    if (handshakeCaptureFlushed_ || handshakeCapture_.isEmpty()) {
        return;
    }
    handshakeCaptureFlushed_ = true;
    const QString name = QStringLiteral("dofus_proxy_first_session_%1.bin")
                               .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    const QString path = QDir(QDir::tempPath()).absoluteFilePath(name);
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        emit logLine(QStringLiteral("[PROXY] No se pudo escribir captura: ") + path);
        return;
    }
    f.write(handshakeCapture_);
    f.close();
    emit logLine(QStringLiteral("[PROXY] Captura primera sesión guardada (%1, %2 bytes, motivo: %3)")
                     .arg(path)
                     .arg(handshakeCapture_.size())
                     .arg(reasonTag));
    handshakeCapture_.clear();
}

void TcpMitmProxy::onNewConnection()
{
    QTcpSocket* pending = nullptr;
    if (server_.hasPendingConnections()) {
        pending = server_.nextPendingConnection();
    } else if (server6_.hasPendingConnections()) {
        pending = server6_.nextPendingConnection();
    } else {
        return;
    }

    if (client_ != nullptr) {
        emit logLine(QStringLiteral("[PROXY] Ya hay una sesión activa; se rechaza conexión extra desde %1:%2.")
                         .arg(pending->peerAddress().toString())
                         .arg(pending->peerPort()));
        pending->disconnectFromHost();
        pending->deleteLater();
        return;
    }

    client_ = pending;
    clientConnectEpochMs_ = QDateTime::currentMSecsSinceEpoch();
    pendingFromClient_.clear();
    lastOutboundFromClient_.clear();
    upstreamAutoRetriesLeft_ = 2;
    gaHandoffDetected_ = false;
    handshakeCaptureFlushed_ = false;
    handshakeCapture_.clear();

    const QHostAddress peer = client_->peerAddress();
    const QString peerFam = peer.protocol() == QHostAddress::IPv4Protocol
                                ? QStringLiteral("IPv4")
                                : (peer.protocol() == QHostAddress::IPv6Protocol ? QStringLiteral("IPv6")
                                                                                 : QStringLiteral("otro"));
    emit logLine(QStringLiteral("[PROXY] Cliente conectado desde %1:%2 (familia %3; socket local %4:%5)")
                     .arg(peer.toString())
                     .arg(client_->peerPort())
                     .arg(peerFam)
                     .arg(client_->localAddress().toString())
                     .arg(client_->localPort()));

    if (minimalReceiveOnlyMode_) {
        emit logLine(QStringLiteral("[PROXY] Cliente conectado! Socket aceptado (modo mínimo)."));
        connect(client_, &QTcpSocket::readyRead, this, &TcpMitmProxy::pumpClientMinimalOnly);
        connect(client_, &QTcpSocket::disconnected, this, [this]() { teardown(QStringLiteral("cliente local cerró")); });
        return;
    }

    if (echoMode_) {
        connect(client_, &QTcpSocket::readyRead, this, &TcpMitmProxy::pumpClientEchoOnly);
        connect(client_, &QTcpSocket::disconnected, this, [this]() { teardown(QStringLiteral("cliente local cerró")); });
        emit logLine(QStringLiteral("[PROXY] Modo ECHO: túnel local listo (sin upstream)."));
        emit tunnelReadyChanged(true);
        return;
    }

    connect(client_, &QTcpSocket::readyRead, this, &TcpMitmProxy::pumpClientUpstream);
    connect(client_, &QIODevice::bytesWritten, this, &TcpMitmProxy::onClientBytesWritten);
    connect(client_, &QTcpSocket::disconnected, this, [this]() { teardown(QStringLiteral("cliente local cerró")); });

    disconnectUpstreamSessionSlots();
    connect(&upstream_, &QTcpSocket::readyRead, this, &TcpMitmProxy::pumpUpstreamClient);
    connect(&upstream_, &QTcpSocket::connected, this, &TcpMitmProxy::onUpstreamConnected);
    connect(&upstream_, &QTcpSocket::disconnected, this, &TcpMitmProxy::onUpstreamDisconnected);
    connect(&upstream_, &QAbstractSocket::errorOccurred, this, &TcpMitmProxy::onUpstreamSocketError);

    {
        const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
        if (!handoffPreferredHost_.isEmpty() && handoffPreferredPort_ > 0 && nowMs < handoffPreferredUntilMs_) {
            remoteHost_ = handoffPreferredHost_;
            remotePort_ = handoffPreferredPort_;
            emit logLine(QStringLiteral("[PROXY] Upstream fijado por handoff CO→GA: %1:%2")
                             .arg(remoteHost_)
                             .arg(remotePort_));
        } else {
            QString autoHost;
            quint16 autoPort = 0;
            if (tryUpstreamFromDllRedirectLog(&autoHost, &autoPort)) {
                const bool changed = (remoteHost_ != autoHost) || (remotePort_ != autoPort);
                remoteHost_ = autoHost;
                remotePort_ = autoPort;
                emit logLine(QStringLiteral("[PROXY] Upstream inferido desde log DLL: %1:%2%3")
                                 .arg(remoteHost_)
                                 .arg(remotePort_)
                                 .arg(changed ? QStringLiteral(" (actualizado automáticamente)")
                                              : QStringLiteral("")));
            } else if (tryResolveUpstreamFromDllHostName(&autoHost, &autoPort)) {
                const bool changed = (remoteHost_ != autoHost) || (remotePort_ != autoPort);
                remoteHost_ = autoHost;
                remotePort_ = autoPort;
                emit logLine(QStringLiteral("[PROXY] Upstream resuelto por DNS desde host Ankama: %1:%2%3")
                                 .arg(remoteHost_)
                                 .arg(remotePort_)
                                 .arg(changed ? QStringLiteral(" (actualizado automáticamente)")
                                              : QStringLiteral("")));
            } else if (tryUpstreamFromSharedIpFile(&autoHost)) {
                const quint16 port = 5555;
                const bool changed = (remoteHost_ != autoHost) || (remotePort_ != port);
                remoteHost_ = autoHost;
                remotePort_ = port;
                lastAutoUpstreamHost_ = autoHost;
                emit logLine(QStringLiteral("[PROXY] Upstream fallback desde archivo compartido: %1:%2%3")
                                 .arg(remoteHost_)
                                 .arg(remotePort_)
                                 .arg(changed ? QStringLiteral(" (actualizado automáticamente)")
                                              : QStringLiteral("")));
            }
        }
    }

    if (upstreamEndpointUsable()) {
        emit logLine(QStringLiteral("[PROXY] Conectando upstream a %1:%2 (servidor real; no 127.0.0.1)")
                         .arg(remoteHost_)
                         .arg(remotePort_));
        connectUpstreamSocketToRemote();
        scheduleUpstreamConnectWatch();
    } else {
        emit logLine(QStringLiteral(
            "[PROXY] Cliente conectado; upstream aún sin definir. Esperando detección automática por log DLL "
            "(host/IP) o aplica upstream manual en la UI."));
    }
}

void TcpMitmProxy::onUpstreamSocketError(QAbstractSocket::SocketError socketError)
{
    Q_UNUSED(socketError);
    cancelUpstreamConnectWatch();
    emit logLine(QStringLiteral("[PROXY] ERROR upstream (socket): QAbstractSocket::SocketError=%1 — %2")
                     .arg(int(upstream_.error()))
                     .arg(upstream_.errorString()));
    logDiag(QStringLiteral("socket upstream: state=%1, error=%2")
                .arg(int(upstream_.state()))
                .arg(upstream_.errorString()));
}

void TcpMitmProxy::onUpstreamConnected()
{
    cancelUpstreamConnectWatch();
    clearUpstreamNoResponseWatch();
    emit logLine(QStringLiteral("[PROXY] Conectado upstream a %1:%2 (túnel bidireccional activo).")
                     .arg(remoteHost_)
                     .arg(remotePort_));

    const QHostAddress upPeer = upstream_.peerAddress();
    emit logLine(QStringLiteral("[PROXY] Upstream socket: local %1:%2 → peer %3:%4 (familia %5)")
                     .arg(upstream_.localAddress().toString())
                     .arg(upstream_.localPort())
                     .arg(upPeer.toString())
                     .arg(upstream_.peerPort())
                     .arg(upPeer.protocol() == QHostAddress::IPv4Protocol
                              ? QStringLiteral("IPv4")
                              : (upPeer.protocol() == QHostAddress::IPv6Protocol ? QStringLiteral("IPv6")
                                                                                 : QStringLiteral("otro"))));

    if (client_ != nullptr && !rawTcpForwarderMode_) {
        const QHostAddress cpa = client_->peerAddress();
        const bool clientIs6 = cpa.protocol() == QHostAddress::IPv6Protocol;
        const bool upIs4 = upPeer.protocol() == QHostAddress::IPv4Protocol;
        if (clientIs6 && upIs4) {
            emit logLine(QStringLiteral(
                "[PROXY] Cliente en IPv6 (::1/…) y servidor remoto en IPv4 — habitual; el proxy une dos TCP sin "
                "alterar el payload."));
        }
        if (fullDiagnosticMode_) {
            logDiag(QStringLiteral("compare familia: cliente=%1, upstream peer=%2")
                        .arg(clientIs6 ? QStringLiteral("IPv6") : QStringLiteral("IPv4"))
                        .arg(upIs4 ? QStringLiteral("IPv4") : QStringLiteral("IPv6")));
        }
    }

    if (transparentMode_ && !rawTcpForwarderMode_) {
        emit logLine(QStringLiteral(
            "[PROXY] Transparencia: reenvío bruto (readAll → write); no se modifica ningún byte del flujo."));
    }

    emit tunnelReadyChanged(true);
    if (!pendingFromClient_.isEmpty()) {
        emit logLine(QStringLiteral("[PROXY] Upstream listo: volcando %1 B que llegaron del cliente antes del connect "
                                      "(sin alterar bytes).")
                         .arg(pendingFromClient_.size()));
        if (fullTrafficLog_) {
            logFullTrafficPair(QStringLiteral("[PROXY → SERVIDOR]"), pendingFromClient_);
        }
        if (!rawTcpForwarderMode_) {
            recordClientOutboundChunk(pendingFromClient_);
        }
        queueToUpstream_.append(pendingFromClient_);
        pendingFromClient_.clear();
        drainQueueToUpstream();
    }
}

void TcpMitmProxy::pumpClientMinimalOnly()
{
    if (!client_) {
        return;
    }
    const QByteArray d = client_->readAll();
    if (fullTrafficLog_ && !d.isEmpty()) {
        logFullTrafficPair(QStringLiteral("[CLIENTE → PROXY]"), d);
    } else if (!d.isEmpty()) {
        emit logLine(QStringLiteral("[PROXY] Recibidos %1 bytes del cliente").arg(d.size()));
    }
    if (!d.isEmpty()) {
        emit protocolPayloadCaptured(true, d);
    }
}

void TcpMitmProxy::pumpClientEchoOnly()
{
    if (!client_) {
        return;
    }
    const QByteArray d = client_->readAll();
    if (fullTrafficLog_ && !d.isEmpty()) {
        logFullTrafficPair(QStringLiteral("[CLIENTE → PROXY]"), d);
        logFullTrafficPair(QStringLiteral("[PROXY → CLIENTE]"), d);
    }
    if (!d.isEmpty()) {
        emit protocolPayloadCaptured(true, d);
    }
    logProxyDetailed(QStringLiteral("Cliente→Proxy (ECHO entrada)"), d);
    detectIriInClientChunk(d);
    recordClientOutboundChunk(d);
    maybeLogTraffic(QStringLiteral("C→S(echo)"), d);
    if (!d.isEmpty()) {
        client_->write(d);
        logProxyDetailed(QStringLiteral("Proxy→Cliente (ECHO salida)"), d);
    }
}

void TcpMitmProxy::pumpClientUpstream()
{
    if (!client_) {
        return;
    }
    const QByteArray d = client_->readAll();
    if (rawTcpForwarderMode_) {
        if (fullTrafficLog_ && !d.isEmpty()) {
            logFullTrafficPair(QStringLiteral("[CLIENTE → PROXY]"), d);
            if (upstream_.state() == QAbstractSocket::ConnectedState) {
                logFullTrafficPair(QStringLiteral("[PROXY → SERVIDOR]"), d);
            }
        }
        if (!d.isEmpty()) {
            emit protocolPayloadCaptured(true, d);
        }
        if (upstream_.state() == QAbstractSocket::ConnectedState) {
            queueToUpstream_.append(d);
            drainQueueToUpstream();
        } else {
            pendingFromClient_.append(d);
        }
        return;
    }
    if (fullTrafficLog_ && !d.isEmpty()) {
        logFullTrafficPair(QStringLiteral("[CLIENTE → PROXY]"), d);
        if (upstream_.state() == QAbstractSocket::ConnectedState) {
            logFullTrafficPair(QStringLiteral("[PROXY → SERVIDOR]"), d);
        }
    }
    if (!d.isEmpty()) {
        emit protocolPayloadCaptured(true, d);
    }
    logProxyDetailed(QStringLiteral("Cliente→Proxy"), d);
    detectIriInClientChunk(d);
    maybeLogTraffic(QStringLiteral("C→S"), d);
    recordClientOutboundChunk(d);
    appendHandshakeCapture(true, d);
    if (upstream_.state() == QAbstractSocket::ConnectedState) {
        queueToUpstream_.append(d);
        drainQueueToUpstream();
        if (!d.isEmpty()) {
            armUpstreamNoResponseWatch();
        }
        if (fullDiagnosticMode_ && !d.isEmpty()) {
            logDiag(QStringLiteral("C→S: %1 bytes leídos del cliente; cola hacia upstream %2 B")
                        .arg(d.size())
                        .arg(queueToUpstream_.size()));
        }
    } else {
        pendingFromClient_.append(d);
    }
}

void TcpMitmProxy::pumpUpstreamClient()
{
    if (!client_) {
        return;
    }
    const QByteArray d = upstream_.readAll();
    if (d.isEmpty()) {
        return;
    }
    if (rawTcpForwarderMode_) {
        if (fullTrafficLog_) {
            logFullTrafficPair(QStringLiteral("[SERVIDOR → PROXY]"), d);
            logFullTrafficPair(QStringLiteral("[PROXY → CLIENTE]"), d);
        }
        emit protocolPayloadCaptured(false, d);
        queueToClient_.append(d);
        drainQueueToClient();
        return;
    }
    if (fullTrafficLog_) {
        logFullTrafficPair(QStringLiteral("[SERVIDOR → PROXY]"), d);
        logFullTrafficPair(QStringLiteral("[PROXY → CLIENTE]"), d);
    }
    emit protocolPayloadCaptured(false, d);
    logServerToProxy(d);
    QString gaHost;
    if (tryExtractGaHostFromPayload(d, &gaHost)) {
        QString gaIp;
        if (tryResolveNonLoopbackIpv4(gaHost, &gaIp)) {
            const quint16 gaPort = 5555;
            const bool changed = (remoteHost_ != gaIp) || (remotePort_ != gaPort);
            remoteHost_ = gaIp;
            remotePort_ = gaPort;
            lastAutoUpstreamHost_ = gaIp;
            gaHandoffDetected_ = true;
            handoffPreferredHost_ = gaIp;
            handoffPreferredPort_ = gaPort;
            handoffPreferredUntilMs_ = QDateTime::currentMSecsSinceEpoch() + 30000;
            emit logLine(QStringLiteral("[PROXY] Handoff detectado: host %1 -> %2:%3%4")
                             .arg(gaHost)
                             .arg(remoteHost_)
                             .arg(remotePort_)
                             .arg(changed ? QStringLiteral(" (upstream actualizado)") : QStringLiteral("")));
        } else {
            emit logLine(QStringLiteral("[PROXY] AVISO: handoff GA detectado (%1) pero DNS no resolvió IPv4.")
                             .arg(gaHost));
        }
    }
    maybeLogTraffic(QStringLiteral("S→C"), d);
    clearUpstreamNoResponseWatch();
    appendHandshakeCapture(false, d);
    queueToClient_.append(d);
    drainQueueToClient();
    if (fullDiagnosticMode_) {
        logDiag(QStringLiteral("S→C: leídos %1 B del upstream; hacia cliente cola %2 B (mismo payload, sin alterar).")
                    .arg(d.size())
                    .arg(queueToClient_.size()));
    }
}

void TcpMitmProxy::teardown(const QString& reason)
{
    cancelUpstreamConnectWatch();
    clearUpstreamNoResponseWatch();

    qint64 sessionMs = 0;
    if (clientConnectEpochMs_ > 0) {
        sessionMs = QDateTime::currentMSecsSinceEpoch() - clientConnectEpochMs_;
    }
    QString sockDiag;
    QTcpSocket* cl = client_;
    if (cl != nullptr && reason.contains(QStringLiteral("cliente"))) {
        sockDiag = QStringLiteral(" · QAbstractSocket::SocketError=%1 (%2)")
                       .arg(int(cl->error()))
                       .arg(cl->errorString());
    }

    if (fullDiagnosticMode_) {
        emit logLine(QStringLiteral("[DIAG] teardown «%1»: cliente state=%2, upstream state=%3 · sesión ~%4 ms%5")
                         .arg(reason)
                         .arg(client_ ? int(client_->state()) : -1)
                         .arg(int(upstream_.state()))
                         .arg(sessionMs)
                         .arg(sockDiag));
    }
    if (handshakeCaptureEnabled_ && !handshakeCapture_.isEmpty() && !handshakeCaptureFlushed_) {
        flushHandshakeCaptureToFile(reason);
    }
    upstreamAutoRetriesLeft_ = 0;
    gaHandoffDetected_ = false;
    if (client_) {
        disconnect(client_, nullptr, this, nullptr);
        client_->deleteLater();
        client_ = nullptr;
    }
    clientConnectEpochMs_ = 0;
    disconnectUpstreamSessionSlots();
    upstream_.disconnectFromHost();
    upstream_.close();
    pendingFromClient_.clear();
    queueToUpstream_.clear();
    queueToClient_.clear();

    emit logLine(QStringLiteral("[PROXY] Sesión terminada: %1 · duración ~%2 ms%3")
                     .arg(reason)
                     .arg(sessionMs)
                     .arg(sockDiag));
    emit tunnelReadyChanged(false);
}

void TcpMitmProxy::onUpstreamDisconnected()
{
    cancelUpstreamConnectWatch();
    clearUpstreamNoResponseWatch();
    if (client_ == nullptr) {
        return;
    }

    const int se = static_cast<int>(upstream_.error());
    const QString err = upstream_.errorString();
    emit logLine(QStringLiteral("[PROXY] Evento: upstream desconectado · QAbstractSocket::SocketError=%1 — %2")
                     .arg(se)
                     .arg(err.isEmpty() ? QStringLiteral("(sin texto)") : err));
    emit tunnelReadyChanged(false);

    if (echoMode_) {
        return;
    }

    if (gaHandoffDetected_) {
        gaHandoffDetected_ = false;
        emit logLine(QStringLiteral(
            "[PROXY] Cierre upstream tras handoff CO→GA detectado: se cierra sesión local para forzar reconexión limpia del cliente."));
        teardown(QStringLiteral("handoff CO→GA (reconexión limpia)"));
        return;
    }

    if (client_->state() == QAbstractSocket::ConnectedState && upstreamAutoRetriesLeft_ > 0
        && upstreamEndpointUsable()) {
        --upstreamAutoRetriesLeft_;
        emit logLine(QStringLiteral(
            "[PROXY] El cliente local sigue conectado; reintento automático hacia %1:%2 en ~400 ms "
            "(reintentos restantes tras este: %3).")
                         .arg(remoteHost_)
                         .arg(remotePort_)
                         .arg(upstreamAutoRetriesLeft_));

        QTimer::singleShot(400, this, [this]() {
            if (client_ == nullptr || client_->state() != QAbstractSocket::ConnectedState) {
                teardown(QStringLiteral("cliente ya no conectado (cancelado reintento upstream)"));
                return;
            }
            if (!upstreamEndpointUsable()) {
                teardown(QStringLiteral("upstream inválido (cancelado reintento)"));
                return;
            }
            disconnectUpstreamSessionSlots();
            if (upstream_.state() != QAbstractSocket::UnconnectedState) {
                upstream_.abort();
            }
            connect(&upstream_, &QTcpSocket::readyRead, this, &TcpMitmProxy::pumpUpstreamClient);
            connect(&upstream_, &QTcpSocket::connected, this, &TcpMitmProxy::onUpstreamConnected);
            connect(&upstream_, &QTcpSocket::disconnected, this, &TcpMitmProxy::onUpstreamDisconnected);
            connect(&upstream_, &QAbstractSocket::errorOccurred, this, &TcpMitmProxy::onUpstreamSocketError);
            emit logLine(QStringLiteral("[PROXY] Reintento: conectando upstream a %1:%2 (servidor real; no 127.0.0.1)")
                             .arg(remoteHost_)
                             .arg(remotePort_));
            connectUpstreamSocketToRemote();
            scheduleUpstreamConnectWatch();
        });
        return;
    }

    teardown(QStringLiteral("upstream cerró"));
}
