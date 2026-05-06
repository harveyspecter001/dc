#include "MainWindow.h"
#include "ResourceAliasEditor.h"
#include "ResourcePredictor.h"
#include "ProtobufParser.h"
#include "DebugCentralLog.h"
#include "DiagnosticsLogWindow.h"
#include "TcpMitmProxy.h"

#ifdef Q_OS_WIN
#include "DllInjector.h"
#include "ProcessMonitor.h"
#include "WindowsTcpConnectionKiller.h"
#include "WindowsTcpPidSnapshot.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include <QAbstractItemView>
#include <QCheckBox>
#include <QCloseEvent>
#include <QDesktopServices>
#include <QCoreApplication>
#include <QCursor>
#include <QDateTime>
#include <QUrl>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QInputDialog>
#include <QIODevice>
#include <QFont>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QTextBrowser>
#include <QTextEdit>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSize>
#include <QSizePolicy>
#include <QTabWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QComboBox>
#include <QListWidget>
#include <QTextEdit>
#include <QBrush>
#include <QColor>
#include <QStatusBar>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QToolBar>
#include <QVBoxLayout>
#include <algorithm>
#include <QTimer>
#include <QGroupBox>
#include <QMenu>
#include <QAction>
#include <QMenuBar>
#include <QAbstractSocket>
#include <QHostAddress>
#include <QTcpSocket>
#include <QtEndian>
#include <QtGlobal>

#include <QDragEnterEvent>
#include <QDropEvent>
#include <QSet>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMimeData>
#include <QItemSelectionModel>
#include <QSplitter>
#include <QSpinBox>
#include <QSettings>
#include <QTextStream>
#include <QStringConverter>
#include <QRegularExpression>

#include <functional>

namespace {
constexpr quint16 kUpstreamDefaultPort = 5555;
constexpr int kProtoVecRole = Qt::UserRole + 48;
/// Fila en la tabla de candidatos: 0 candidato vivo, 1 recurso en BD, 2 monstruo en BD (solo depuración UI).
constexpr int kCandTableRowKindRole = Qt::UserRole + 60;
constexpr int kRowKindCandidate = 0;

[[nodiscard]] bool packetKindUpdatesMapGuess(PacketKind k)
{
    switch (k) {
    case PacketKind::IsoResources:
    case PacketKind::ItxMapHeavyServer:
    case PacketKind::MapHydrateTripleServer:
    case PacketKind::MapHopJnrIspClient:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] QString protocolTreeKindColumnText(const ProtocolPacketRecord& r)
{
    QString t = r.kindLabel;
    switch (r.kind) {
    case PacketKind::MapGatherIerSnapshotServer:
    case PacketKind::MapGatherIevTapClient:
    case PacketKind::MapGatherIeuBundleServer:
    case PacketKind::ItvInteraction:
    case PacketKind::IeeHarvest:
        return QStringLiteral("🎯 %1").arg(t);
    default:
        return t;
    }
}

[[nodiscard]] bool detailPanelHighlightsInteraction(const ProtocolPacketRecord& rec)
{
    switch (rec.kind) {
    case PacketKind::MapGatherIerSnapshotServer:
    case PacketKind::MapGatherIevTapClient:
    case PacketKind::MapGatherIeuBundleServer:
    case PacketKind::ItvInteraction:
    case PacketKind::IeeHarvest:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] bool packetKindMatchesFilterCombo(PacketKind k, int fil)
{
    if (fil <= 0) {
        return true;
    }
    switch (fil) {
    case 1:
        return k == PacketKind::IriMovement;
    case 2:
        return k == PacketKind::IrlList;
    case 3:
        return k == PacketKind::IsoResources;
    case 4:
        return k == PacketKind::IrxMonsters;
    case 5:
        return k == PacketKind::IslEntities;
    case 6:
        return k == PacketKind::CommandData;
    case 7:
        return k == PacketKind::DataGeneric;
    case 8:
        return k == PacketKind::Unknown;
    case 9:
        return k == PacketKind::IeeHarvest;
    case 10:
        return k == PacketKind::IdrItemReceived;
    case 11:
        return k == PacketKind::IdyItemDisplayed;
    case 12:
        return k == PacketKind::IdwItemVanished;
    case 13:
        return k == PacketKind::IsuClientSync;
    case 14:
        return k == PacketKind::IrkSyncResponse;
    case 15:
        return k == PacketKind::IspSync;
    case 16:
        return k == PacketKind::ItvInteraction;
    case 17:
        return k == PacketKind::KjCompression;
    case 18:
        return k == PacketKind::JmwMonsterCmd;
    case 19:
        return k == PacketKind::JrrCommandResponse;
    case 20:
        return k == PacketKind::MapHopJnrIspClient;
    case 21:
        return k == PacketKind::IsaPingClient;
    case 22:
        return k == PacketKind::ItrMapTransitClient;
    case 23:
        return k == PacketKind::IshMapTinyServer;
    case 24:
        return k == PacketKind::ItoMapTransitClient;
    case 25:
        return k == PacketKind::MapHydrateTripleServer;
    case 26:
        return k == PacketKind::ItxMapHeavyServer;
    case 27:
        return k == PacketKind::KtaKeyedServer;
    case 28:
        return k == PacketKind::JsaPulseClient;
    case 29:
        return k == PacketKind::JsbPulseServer;
    case 30:
        return k == PacketKind::MapGatherIerSnapshotServer;
    case 31:
        return k == PacketKind::MapGatherIevTapClient;
    case 32:
        return k == PacketKind::MapGatherIeuBundleServer;
    default:
        return true;
    }
}

class LogsDropFrame final : public QFrame {
public:
    std::function<void(const QString&)> onFileDropped;

    explicit LogsDropFrame(QWidget* parent = nullptr)
        : QFrame(parent)
    {
        setAcceptDrops(true);
        setMinimumHeight(54);
        setFrameShape(QFrame::StyledPanel);
        setStyleSheet(QStringLiteral(
            "LogsDropFrame { border: 2px dashed #5c5c5c; border-radius: 8px; background: #1a1a1a; }"));
        auto* lay = new QVBoxLayout(this);
        lay->setContentsMargins(12, 10, 12, 10);
        auto* lb =
            new QLabel(QStringLiteral("Arrastra y suelta aquí un .txt del registro (bloques HEX). También: «Importar»."));
        lb->setWordWrap(true);
        lb->setToolTip(QStringLiteral(
            "Equivale a elegir archivo con el botón Importar; se abrirá el diálogo de vista previa antes de cargar."));
        lb->setStyleSheet(QStringLiteral("color:#94a3b8;"));
        lay->addWidget(lb);
    }

protected:
    void dragEnterEvent(QDragEnterEvent* e) override
    {
        if (e->mimeData()->hasUrls()) {
            e->acceptProposedAction();
        }
    }

    void dropEvent(QDropEvent* e) override
    {
        const QList<QUrl> urls = e->mimeData()->urls();
        if (urls.isEmpty()) {
            return;
        }
        const QString p = urls.first().toLocalFile();
        if (!p.isEmpty() && onFileDropped) {
            onFileDropped(p);
        }
    }
};

constexpr quint16 kLocalProxyMustPort = 5555;

void appendToCentralFromUiLine(const QString& line)
{
    const char* tag = "INJECTOR";
    QString body = line;
    if (line.startsWith(QStringLiteral("[PROXY]"))) {
        tag = "PROXY";
        body = line.mid(QStringLiteral("[PROXY]").size()).trimmed();
    }
    DebugCentralLog::append(tag, body.isEmpty() ? line : body);
}

bool substringFilterMatch(const QString& name, QString filterTrimmed)
{
    if (filterTrimmed.isEmpty()) {
        return true;
    }
    return name.contains(filterTrimmed, Qt::CaseInsensitive);
}

QString formatIrxMonsterSummaryLine(const ProtocolPacketRecord& rec, const QVector<IdRangeRule>& mergedRules)
{
    QHash<quint64, int> freq;
    for (quint64 id : rec.numericIds) {
        freq[id]++;
    }
    QList<quint64> keys = freq.keys();
    std::sort(keys.begin(), keys.end());
    QStringList parts;
    for (quint64 id : keys) {
        QString cat;
        const QString name = resolveIdWithRules(id, mergedRules, &cat);
        if (name.isEmpty() || cat != QStringLiteral("monstruo")) {
            continue;
        }
        parts.append(QStringLiteral("%1 (x%2)").arg(name).arg(freq.value(id)));
    }
    if (!parts.isEmpty()) {
        return parts.join(QStringLiteral(", "));
    }
    return QStringLiteral("IRX: %1 varints — sin nombre de monstruo (configura «Editar IDs»).")
        .arg(rec.numericIds.size());
}

QString guessDirectionMapJsonPath()
{
    const QDir exeDir(QCoreApplication::applicationDirPath());
    const QString rels[]{"../../../direcciones_map.json", "../../direcciones_map.json", "../direcciones_map.json",
                        QLatin1String("direcciones_map.json")};
    for (const QString& rel : rels) {
        const QFileInfo fi(exeDir.absoluteFilePath(rel));
        const QString can = fi.canonicalFilePath();
        if (!can.isEmpty() && QFile::exists(can)) {
            return can;
        }
    }
    return exeDir.absoluteFilePath(QStringLiteral("../../../direcciones_map.json"));
}

#ifdef Q_OS_WIN
QString systemHostsFilePath()
{
    return QStringLiteral("C:/Windows/System32/drivers/etc/hosts");
}

QString hostsBackupFilePath()
{
    return QStringLiteral("C:/Windows/System32/drivers/etc/hosts.bak.dofus_sniffer");
}

constexpr char kHostsMarkerBegin[] = "# --- dofus_process_sniffer hosts BEGIN ---";
constexpr char kHostsMarkerEnd[] = "# --- dofus_process_sniffer hosts END ---";

QString hostsProxyBlockBody()
{
    return QStringLiteral("127.0.0.1 dofus2-ga-rafal.ankama-games.com\r\n"
                          "127.0.0.1 dofus2-ga-rafal.ankama.com\r\n"
                          "127.0.0.1 ankama-games.com\r\n"
                          "127.0.0.1 ankama.com");
}

void appendOrReplaceHostsBlock(QString* content)
{
    const QString begin = QString::fromLatin1(kHostsMarkerBegin);
    const QString end = QString::fromLatin1(kHostsMarkerEnd);
    const QString body = hostsProxyBlockBody();
    const QString block = begin + QStringLiteral("\r\n") + body + QStringLiteral("\r\n") + end;
    const int i0 = content->indexOf(begin);
    const int i1 = i0 >= 0 ? content->indexOf(end, i0 + begin.size()) : -1;
    if (i0 >= 0 && i1 >= 0 && i1 > i0) {
        const int afterEnd = i1 + end.size();
        content->replace(i0, afterEnd - i0, block);
        return;
    }
    if (!content->isEmpty() && !content->endsWith(QLatin1Char('\n'))) {
        *content += QStringLiteral("\r\n");
    }
    *content += QStringLiteral("\r\n") + block + QStringLiteral("\r\n");
}

bool stripHostsProxyBlock(QString* content)
{
    const QString begin = QString::fromLatin1(kHostsMarkerBegin);
    const QString end = QString::fromLatin1(kHostsMarkerEnd);
    const int i0 = content->indexOf(begin);
    const int i1 = i0 >= 0 ? content->indexOf(end, i0 + begin.size()) : -1;
    if (i0 < 0 || i1 < 0 || i1 <= i0) {
        return false;
    }
    int cutEnd = i1 + end.size();
    while (cutEnd < content->size()
           && (content->at(cutEnd) == QLatin1Char('\r') || content->at(cutEnd) == QLatin1Char('\n'))) {
        ++cutEnd;
    }
    content->remove(i0, cutEnd - i0);
    return true;
}
#endif

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , proxy_(new TcpMitmProxy(this))
{
    setWindowTitle(QStringLiteral("Dofus · proxy TCP 0.0.0.0:5555"));
    setStyleSheet(appStyleSheet());
    setMinimumSize(560, 480);
    resize(1024, 720);

    startProxySoloBtn_ = new QPushButton(QStringLiteral("Iniciar proxy"));
    startProxySoloBtn_->setMinimumHeight(34);
    startProxySoloBtn_->setToolTip(QStringLiteral(
        "Escucha en 127.0.0.1:5555; el upstream es la IP literal del mundo (por defecto 54.76.83.103; sin DNS)."));
    connect(startProxySoloBtn_, &QPushButton::clicked, this, &MainWindow::onStartProxySoloClicked);
    stopProxyBtn_ = new QPushButton(QStringLiteral("Detener proxy"));
    stopProxyBtn_->setMinimumHeight(34);
    stopProxyBtn_->setEnabled(false);
    connect(stopProxyBtn_, &QPushButton::clicked, this, &MainWindow::onStopProxyClicked);

    startAllBtn_ = new QPushButton(QStringLiteral("▶ INICIAR TODO"));
    startAllBtn_->setMinimumHeight(34);
    startAllBtn_->setToolTip(QStringLiteral("Inicia proxy + monitor. Al detectar Dofus.exe, se inyecta la DLL (si aplica)."));
    connect(startAllBtn_, &QPushButton::clicked, this, &MainWindow::onStartAllClicked);
    stopAllBtn_ = new QPushButton(QStringLiteral("■ DETENER TODO"));
    stopAllBtn_->setMinimumHeight(34);
    stopAllBtn_->setEnabled(false);
    connect(stopAllBtn_, &QPushButton::clicked, this, &MainWindow::onStopAllClicked);
#ifdef Q_OS_WIN
    startProxyWithDllBtn_ = new QPushButton(QStringLiteral("Iniciar proxy + DLL (PID)"));
    startProxyWithDllBtn_->setMinimumHeight(34);
    startProxyWithDllBtn_->setToolTip(QStringLiteral(
        "Administrador: PID seleccionado, inyección de DofusRedirect.dll y arranque del proxy."));
    connect(startProxyWithDllBtn_, &QPushButton::clicked, this, &MainWindow::onStartProxyWithDllClicked);
#endif
#ifdef Q_OS_WIN
    processMonitor_ = new ProcessMonitor(this);
    connect(processMonitor_, &ProcessMonitor::dofusProcessDetected, this, &MainWindow::onDofusDetectedInject,
            Qt::QueuedConnection);
    monitorStartBtn_ = new QPushButton(QStringLiteral("Iniciar monitor Dofus"));
    monitorStopBtn_ = new QPushButton(QStringLiteral("Detener monitor"));
    fullDiagnosticBtn_ = new QPushButton(QStringLiteral("Diagnóstico completo"));
    monitorStopBtn_->setEnabled(false);
    connect(monitorStartBtn_, &QPushButton::clicked, this, &MainWindow::onProcessMonitorStart);
    connect(monitorStopBtn_, &QPushButton::clicked, this, &MainWindow::onProcessMonitorStop);
    connect(fullDiagnosticBtn_, &QPushButton::clicked, this, &MainWindow::onFullDiagnosticClicked);
#endif
    {
        QMenu* mVer = menuBar()->addMenu(QStringLiteral("&Ver"));
        mVer->addAction(QStringLiteral("Registro en ventana aparte…"), this, &MainWindow::openDiagnosticsLogWindow);
#ifdef Q_OS_WIN
        QMenu* mAd = menuBar()->addMenu(QStringLiteral("&Herramientas"));
        mAd->addAction(QStringLiteral("Diagnóstico completo (hook / TCP)"), this, &MainWindow::onFullDiagnosticClicked);
#endif
    }

    auto wrapInScroll = [](QWidget* inner) {
        auto* sc = new QScrollArea;
        sc->setWidgetResizable(true);
        sc->setFrameShape(QFrame::NoFrame);
        sc->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        sc->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        sc->setWidget(inner);
        return sc;
    };

    mainTabWidget_ = new QTabWidget;
    mainTabWidget_->setDocumentMode(true);
    mainTabWidget_->setUsesScrollButtons(true);
    mainTabWidget_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setCentralWidget(mainTabWidget_);

    {
        QToolBar* tb = addToolBar(QStringLiteral("Principal"));
        tb->setMovable(false);
        auto* gear = new QPushButton(QStringLiteral("\u2699"));
        gear->setFixedWidth(36);
        gear->setToolTip(QStringLiteral("Mostrar / ocultar pestaña Avanzado"));
        connect(gear, &QPushButton::clicked, this, [this]() {
            if (mainTabWidget_ == nullptr || advancedTabWrap_ == nullptr) {
                return;
            }
            const int idx = mainTabWidget_->indexOf(advancedTabWrap_);
            if (idx < 0) {
                return;
            }
            mainTabWidget_->setTabVisible(idx, !mainTabWidget_->isTabVisible(idx));
        });
        tb->addWidget(gear);
    }

    // —— Pestaña Proxy (vista simple) ——
    auto* pageProxyMain = new QWidget;
    auto* pmLay = new QVBoxLayout(pageProxyMain);
    pmLay->setSpacing(8);
    pmLay->setContentsMargins(8, 8, 8, 8);

    auto* proxyCtrlRow = new QHBoxLayout;
    proxyCtrlRow->addWidget(startAllBtn_);
    proxyCtrlRow->addWidget(stopAllBtn_);
    proxyCtrlRow->addWidget(startProxySoloBtn_);
    proxyCtrlRow->addWidget(stopProxyBtn_);
#ifdef Q_OS_WIN
    proxyCtrlRow->addWidget(startProxyWithDllBtn_);
#endif
    proxyCtrlRow->addStretch(1);
    pmLay->addLayout(proxyCtrlRow);

    pmLay->addWidget(new QLabel(QStringLiteral(
        "<b>Movimiento</b> — N/S/E/O usan plantillas ☆iri (cargá <code>direcciones_map.json</code> en Avanzado).")));

    arrowN_btn_ = new QPushButton(QStringLiteral("Norte"));
    arrowS_btn_ = new QPushButton(QStringLiteral("Sur"));
    arrowE_btn_ = new QPushButton(QStringLiteral("Este"));
    arrowO_btn_ = new QPushButton(QStringLiteral("Oeste"));
    arrowN_btn_->setEnabled(false);
    arrowS_btn_->setEnabled(false);
    arrowE_btn_->setEnabled(false);
    arrowO_btn_->setEnabled(false);
    connect(arrowN_btn_, &QPushButton::clicked, this,
            [this]() { applyCardinal(QStringLiteral("Norte")); });
    connect(arrowS_btn_, &QPushButton::clicked, this,
            [this]() { applyCardinal(QStringLiteral("Sur")); });
    connect(arrowE_btn_, &QPushButton::clicked, this,
            [this]() { applyCardinal(QStringLiteral("Este")); });
    connect(arrowO_btn_, &QPushButton::clicked, this,
            [this]() { applyCardinal(QStringLiteral("Oeste")); });
    auto* arrowLay = new QGridLayout;
    arrowLay->addWidget(arrowN_btn_, 0, 0);
    arrowLay->addWidget(arrowS_btn_, 0, 1);
    arrowLay->addWidget(arrowO_btn_, 1, 0);
    arrowLay->addWidget(arrowE_btn_, 1, 1);
    pmLay->addLayout(arrowLay);

    pmLay->addWidget(new QLabel(QStringLiteral(
        "<b>Cambio de mapa</b> — macro C→S (ITR · ITO · PASO MAPA con JNR+ISP). «☆iri» sigue solo para "
        "<code>/iri</code> en casillas.")));
    {
        auto* macroRow = new QHBoxLayout;
        saveMapTransitMacroBtn_ = new QPushButton(QStringLiteral("💾 Guardar macro (selección en Logs…)"));
        saveMapTransitMacroBtn_->setToolTip(QStringLiteral(
            "En Logs, Ctrl+clic en varios paquetes cliente: ITR, ITO y/o PASO MAPA (JNR+ISP). Se ordenan por #."));
        replayMapTransitMacroBtn_ = new QPushButton(QStringLiteral("▶️ Reproducir macro…"));
        replayMapTransitMacroBtn_->setToolTip(QStringLiteral(
            "Carga JSON (p. ej. map_transition_macro.json) e inyecta cada paso hacia el servidor con pausa."));
        macroRow->addWidget(saveMapTransitMacroBtn_);
        macroRow->addWidget(replayMapTransitMacroBtn_);
        macroRow->addWidget(new QLabel(QStringLiteral("Espera:")));
        mapTransitMacroDelaySpin_ = new QSpinBox;
        mapTransitMacroDelaySpin_->setRange(0, 5000);
        mapTransitMacroDelaySpin_->setSingleStep(50);
        mapTransitMacroDelaySpin_->setValue(250);
        mapTransitMacroDelaySpin_->setSuffix(QStringLiteral(" ms"));
        macroRow->addWidget(mapTransitMacroDelaySpin_);
        macroRow->addStretch(1);
        pmLay->addLayout(macroRow);
        pmLay->addWidget(new QLabel(QStringLiteral(
            "<span style=\"color:#cbd5e1;font-size:11px;\">Las respuestas del servidor (ISH, hidrato, etc.) no se "
            "inyectan — deben llegar vivas tras cada paso. Si falla, aumentá el tiempo entre pasos o grabá macro en la "
            "misma sesión.</span>")));
        connect(saveMapTransitMacroBtn_, &QPushButton::clicked, this, &MainWindow::saveMapTransitMacroFromSelection);
        connect(replayMapTransitMacroBtn_, &QPushButton::clicked, this, &MainWindow::replayMapTransitMacroFromDialog);
    }

    upstreamQuickLbl_ = new QLabel(QStringLiteral("Upstream: [Detectando...]"));
    upstreamQuickLbl_->setWordWrap(true);
    upstreamQuickLbl_->setStyleSheet(QStringLiteral("color:#93c5fd;font-size:12px;"));
    pmLay->addWidget(upstreamQuickLbl_);

    tunnelStatusLbl_ = new QLabel;
    tunnelStatusLbl_->setWordWrap(true);
    tunnelStatusLbl_->setText(QStringLiteral("<b>Estado:</b> sin túnel."));
    pmLay->addWidget(tunnelStatusLbl_);

    proxyLog_ = new QPlainTextEdit;
    proxyLog_->setReadOnly(true);
    proxyLog_->setMaximumBlockCount(50000);
    proxyLog_->setMinimumHeight(220);
    proxyLog_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    {
        auto fnt = proxyLog_->font();
        fnt.setFamily(QStringLiteral("Consolas"));
        fnt.setStyleHint(QFont::Monospace);
        proxyLog_->setFont(fnt);
    }
    pmLay->addWidget(proxyLog_, 1);

    auto* diagOpts = new QGroupBox(QStringLiteral("Opciones de diagnóstico"));
    diagOpts->setCheckable(true);
    diagOpts->setChecked(false);
    auto* dol = new QVBoxLayout(diagOpts);
    logTcpCheckbox_ =
        new QCheckBox(QStringLiteral("Log detallado: todo el tráfico Cliente↔Proxy↔Servidor con HEX"));
    logTcpCheckbox_->setChecked(true);
    connect(logTcpCheckbox_, &QCheckBox::toggled, this, &MainWindow::syncProxyOptionsFromUi);
    dol->addWidget(logTcpCheckbox_);

    echoProxyChk_ = new QCheckBox(
        QStringLiteral("Modo ECHO (no conecta al servidor; devuelve al cliente lo enviado)"));
    echoProxyChk_->setChecked(false);
    connect(echoProxyChk_, &QCheckBox::toggled, this, &MainWindow::syncProxyOptionsFromUi);
    connect(echoProxyChk_, &QCheckBox::toggled, this, &MainWindow::refreshMovementButtonsEnabled);
    dol->addWidget(echoProxyChk_);

    captureHandshakeChk_ =
        new QCheckBox(QStringLiteral("Capturar primera sesión a archivo (.bin en %TEMP%)"));
    captureHandshakeChk_->setChecked(false);
    connect(captureHandshakeChk_, &QCheckBox::toggled, this, &MainWindow::syncProxyOptionsFromUi);
    dol->addWidget(captureHandshakeChk_);
    pmLay->addWidget(diagOpts);

    testProxyBtn_ = new QPushButton(QStringLiteral("Probar proxy"));
    testProxyBtn_->setToolTip(QStringLiteral(
        "TCP a 127.0.0.1:5555 y envío «HOLA». Modo normal reenvía al upstream; ECHO devuelve «HOLA»."));
    connect(testProxyBtn_, &QPushButton::clicked, this, &MainWindow::onTestProxyClicked);
    pmLay->addWidget(testProxyBtn_);

    mainTabWidget_->addTab(wrapInScroll(pageProxyMain), QStringLiteral("Proxy"));

    auto* pageRes = new QWidget;
    {
        auto* v = new QVBoxLayout(pageRes);
        v->setSpacing(10);
        v->setContentsMargins(8, 8, 8, 8);
        v->addWidget(new QLabel(QStringLiteral(
            "<b>RECURSOS POR MAPA</b> — detectado en paquetes <code>type.ankama.com/iso</code> (varints 5136xx, 5138xx, 5140xx, 5142xx).")));
        mapCurrentIdLbl_ = new QLabel(QStringLiteral("Mapa actual: —"));
        mapCurrentIdLbl_->setStyleSheet(QStringLiteral("color:#fbbf24;font-size:14px;"));
        v->addWidget(mapCurrentIdLbl_);
        monstersMapLbl_ = new QLabel(QStringLiteral("Monstruos (IRX): —"));
        monstersMapLbl_->setWordWrap(true);
        monstersMapLbl_->setStyleSheet(QStringLiteral("color:#fca5a5;font-size:13px;"));
        v->addWidget(monstersMapLbl_);
        isoMapSummarySectionTitleLbl_ =
            new QLabel(QStringLiteral("<b>🌾 Recursos detectados en el mapa actual (ISO)</b> "
                                      "— rangos conocidos + <code>ids_database.json</code>."));
        isoMapSummarySectionTitleLbl_->setWordWrap(true);
        v->addWidget(isoMapSummarySectionTitleLbl_);
        resourcesMapSummary_ = new QTextBrowser;
        resourcesMapSummary_->setReadOnly(true);
        resourcesMapSummary_->setOpenExternalLinks(false);
        resourcesMapSummary_->setMinimumHeight(120);
        resourcesMapSummary_->setMaximumHeight(260);
        resourcesMapSummary_->setStyleSheet(QStringLiteral(
            "QTextBrowser{background:#121212;color:#e5e7eb;border:1px solid #333;border-radius:6px;}"));
        v->addWidget(resourcesMapSummary_);
        resourcesMapUpdatedLbl_ = new QLabel(QStringLiteral("Última actualización desde ISO: —"));
        resourcesMapUpdatedLbl_->setStyleSheet(QStringLiteral("color:#94a3af;font-size:12px;"));
        v->addWidget(resourcesMapUpdatedLbl_);
        resourceIsoSessionSubtitleLbl_ =
            new QLabel(QStringLiteral("<b>Sesión</b> — últimos repasos ISO (solo texto):"));
        v->addWidget(resourceIsoSessionSubtitleLbl_);
        resourceSessionHistory_ = new QPlainTextEdit;
        resourceSessionHistory_->setReadOnly(true);
        resourceSessionHistory_->setMaximumBlockCount(96);
        resourceSessionHistory_->setMinimumHeight(100);
        resourceSessionHistory_->setMaximumHeight(200);
        {
            auto rf = resourceSessionHistory_->font();
            rf.setFamily(QStringLiteral("Consolas"));
            resourceSessionHistory_->setFont(rf);
        }
        v->addWidget(resourceSessionHistory_);
        exportResourcesCsvBtn_ = new QPushButton(QStringLiteral("Exportar lista agregada (CSV)"));
        exportResourcesCsvBtn_->setToolTip(QStringLiteral(
            "CSV: recurso;cantidad;mapa_actual (útiles para mapeos / bots). Requiere haber pasado ISO con prediction."));
        connect(exportResourcesCsvBtn_, &QPushButton::clicked, this, &MainWindow::exportGatheredResourcesCsvDialog);
        v->addWidget(exportResourcesCsvBtn_);
        isoMapSummarySectionTitleLbl_->setVisible(false);
        resourcesMapSummary_->setVisible(false);
        resourcesMapUpdatedLbl_->setVisible(false);
        resourceIsoSessionSubtitleLbl_->setVisible(false);
        resourceSessionHistory_->setVisible(false);
        exportResourcesCsvBtn_->setVisible(false);

        auto* savedHdr = new QLabel(QStringLiteral(
            "<b>Recursos / monstruos guardados</b> — contenido de <code>ids_database.json</code>. "
            "Un mismo nombre puede tener múltiples IDs (variantes/cantidades)."));
        savedHdr->setWordWrap(true);
        v->addWidget(savedHdr);

        savedResMonTable_ = new QTableWidget(0, 3);
        savedResMonTable_->setHorizontalHeaderLabels(
            {QStringLiteral("Tipo"), QStringLiteral("ID"), QStringLiteral("Nombre")});
        savedResMonTable_->horizontalHeader()->setStretchLastSection(true);
        savedResMonTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        savedResMonTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        savedResMonTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        savedResMonTable_->setMinimumHeight(160);
        v->addWidget(savedResMonTable_, 1);

        auto* savedRow = new QHBoxLayout;
        addSavedResourceBtn_ = new QPushButton(QStringLiteral("Agregar recurso…"));
        addSavedMonsterBtn_ = new QPushButton(QStringLiteral("Agregar monstruo…"));
        removeSavedEntryBtn_ = new QPushButton(QStringLiteral("Eliminar seleccionado"));
        savedRow->addWidget(addSavedResourceBtn_);
        savedRow->addWidget(addSavedMonsterBtn_);
        savedRow->addWidget(removeSavedEntryBtn_);
        savedRow->addStretch(1);
        v->addLayout(savedRow);

        connect(addSavedResourceBtn_, &QPushButton::clicked, this, &MainWindow::addSavedResourceDialog);
        connect(addSavedMonsterBtn_, &QPushButton::clicked, this, &MainWindow::addSavedMonsterDialog);
        connect(removeSavedEntryBtn_, &QPushButton::clicked, this, &MainWindow::removeSelectedSavedEntry);
        refreshSavedResMonUi();
        refreshResourcesBtn_ = new QPushButton(QStringLiteral("Sincronizar mapa desde Logs"));
        refreshResourcesBtn_->setToolTip(QStringLiteral(
            "Sincroniza solo la etiqueta «Mapa actual» desde la cola del log. Los candidatos salen solo de ISO/ITX/IER "
            "snapshot en vivo, no del histórico completo."));
        connect(refreshResourcesBtn_, &QPushButton::clicked, this, &MainWindow::onRefreshResourcesFromLogsClicked);
        v->addWidget(refreshResourcesBtn_);
        editIdsBtn_ = new QPushButton(QStringLiteral("Editar IDs (ids_database.json)"));
        editIdsBtn_->setToolTip(
            QStringLiteral("Tabla: ID, nombre, tipo (recurso/monstruo/objeto) y notas. Se guarda junto al .exe."));
        connect(editIdsBtn_, &QPushButton::clicked, this, &MainWindow::onEditIdsClicked);
        v->addWidget(editIdsBtn_);
        editResourcesGuiBtn_ = new QPushButton(QStringLiteral("✏️ Editar recursos / monstruos (GUI)"));
        editResourcesGuiBtn_->setToolTip(
            QStringLiteral("Editor visual de ids_database.json sin editar JSON a mano."));
        connect(editResourcesGuiBtn_, &QPushButton::clicked, this, &MainWindow::openResourceEditor);
        v->addWidget(editResourcesGuiBtn_);

        auto* candHdr = new QLabel(QStringLiteral(
            "<b>Candidatos a recurso</b> — solo IDs nuevos desde paquetes <b>ISO / ITX / IER snapshot</b> del "
            "<b>mapa actual</b> (no crece con cada RECO de farmeo). Interacción = paquetes IEV/IEU al tocar recurso. "
            "Al guardar se guarda el hex del snapshot en <code>ids_database.json</code>."));
        candHdr->setWordWrap(true);
        v->addWidget(candHdr);

        resourceCandidatesHintLbl_ = new QLabel(QStringLiteral("Candidatos: —"));
        resourceCandidatesHintLbl_->setStyleSheet(QStringLiteral("color:#94a3af;font-size:12px;"));
        v->addWidget(resourceCandidatesHintLbl_);

        resourceCandidatesTable_ = new QTableWidget(0, 5);
        resourceCandidatesTable_->setHorizontalHeaderLabels(
            {QStringLiteral("ID"), QStringLiteral("Nombre sugerido"), QStringLiteral("Como en log"),
             QStringLiteral("Hex snapshot (truncado)"), QStringLiteral("Interactuado")});
        resourceCandidatesTable_->horizontalHeader()->setStretchLastSection(true);
        resourceCandidatesTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        resourceCandidatesTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        resourceCandidatesTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        resourceCandidatesTable_->setMinimumHeight(120);
        v->addWidget(resourceCandidatesTable_);

        auto* candRow = new QHBoxLayout;
        refreshResourceCandidatesBtn_ = new QPushButton(QStringLiteral("Vaciar candidatos"));
        refreshResourceCandidatesBtn_->setToolTip(
            QStringLiteral("Limpia los contadores acumulados en esta sesión (no reescanea el log). Para rellenar desde "
                          "«Logs» usar «Actualizar desde logs»."));
        addResourceCandidateBtn_ = new QPushButton(QStringLiteral("Agregar como recurso…"));
        addResourceCandidateBtn_->setToolTip(QStringLiteral("Guarda el ID seleccionado como recurso en ids_database.json."));
        hideResourceCandidateBtn_ = new QPushButton(QStringLiteral("Ocultar candidato"));
        hideResourceCandidateBtn_->setToolTip(QStringLiteral("Quita el ID de la lista (no modifica ids_database.json)."));
        removeInteractedCandidatesBtn_ = new QPushButton(QStringLiteral("Quitar interactuados"));
        removeInteractedCandidatesBtn_->setToolTip(
            QStringLiteral("Elimina de la tabla los IDs marcados como interactuados en este mapa (solo UI)."));
        candRow->addWidget(refreshResourceCandidatesBtn_);
        candRow->addWidget(addResourceCandidateBtn_);
        addMonsterCandidateBtn_ = new QPushButton(QStringLiteral("Agregar como monstruo…"));
        addMonsterCandidateBtn_->setToolTip(QStringLiteral("Guarda el ID seleccionado como monstruo en ids_database.json."));
        candRow->addWidget(addMonsterCandidateBtn_);
        candRow->addWidget(hideResourceCandidateBtn_);
        candRow->addWidget(removeInteractedCandidatesBtn_);
        candRow->addStretch(1);
        v->addLayout(candRow);

        connect(refreshResourceCandidatesBtn_, &QPushButton::clicked, this, [this]() {
            resourceCandidateHits_.clear();
            resourceCandidateInteractedHits_.clear();
            resourceCandidateSeenOnMap_.clear();
            resourceCandidateSourceHex_.clear();
            resourceCandidateLastInteractMs_.clear();
            resourceCandidateIntroLogLabel_.clear();
            resourceCandidateInteractLogLabel_.clear();
            refreshResourceCandidatesUi();
            statusBar()->showMessage(QStringLiteral("Candidatos vaciados (solo sesión en vivo)."), 3500);
        });
        connect(addResourceCandidateBtn_, &QPushButton::clicked, this, &MainWindow::addSelectedResourceCandidateAsOverride);
        connect(addMonsterCandidateBtn_, &QPushButton::clicked, this, &MainWindow::addSelectedResourceCandidateAsMonster);
        connect(hideResourceCandidateBtn_, &QPushButton::clicked, this, &MainWindow::hideSelectedResourceCandidate);
        connect(removeInteractedCandidatesBtn_, &QPushButton::clicked, this,
                &MainWindow::removeInteractedResourceCandidates);
    }
    auto* pageProto = new QWidget;
    {
        auto* v = new QVBoxLayout(pageProto);
        v->setSpacing(8);
        v->setContentsMargins(8, 8, 8, 8);
        v->addWidget(new QLabel(QStringLiteral(
            "<b>Logs de protocolo</b> — detalle HEX por paquete; plantillas ☆iri solo IRI. Macro cambio mapa: Ctrl+clic "
            "ITR/ITO/PASO MAPA → «Guardar macro» en Proxy.")));
        auto* fl = new QHBoxLayout;
        protocolKindFilter_ = new QComboBox;
        protocolKindFilter_->addItem(QStringLiteral("Todos"));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IriMovement));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IrlList));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IsoResources));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IrxMonsters));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IslEntities));
        protocolKindFilter_->addItem(QStringLiteral("COMANDO / jrt"));
        protocolKindFilter_->addItem(QStringLiteral("DATOS"));
        protocolKindFilter_->addItem(QStringLiteral("Otro / desconocido"));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IeeHarvest));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IdrItemReceived));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IdyItemDisplayed));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IdwItemVanished));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IsuClientSync));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IrkSyncResponse));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IspSync));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::ItvInteraction));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::KjCompression));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::JmwMonsterCmd));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::JrrCommandResponse));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::MapHopJnrIspClient));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IsaPingClient));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::ItrMapTransitClient));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::IshMapTinyServer));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::ItoMapTransitClient));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::MapHydrateTripleServer));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::ItxMapHeavyServer));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::KtaKeyedServer));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::JsaPulseClient));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::JsbPulseServer));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::MapGatherIerSnapshotServer));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::MapGatherIevTapClient));
        protocolKindFilter_->addItem(packetKindDisplayString(PacketKind::MapGatherIeuBundleServer));
        protocolKindFilter_->setToolTip(QStringLiteral("Filtra por tipo detectado en el payload."));
        connect(protocolKindFilter_, &QComboBox::currentIndexChanged, this, &MainWindow::onProtocolFilterChanged);
        fl->addWidget(protocolKindFilter_);
        protocolSearchEdit_ = new QLineEdit;
        protocolSearchEdit_->setPlaceholderText(QStringLiteral("Buscar string, URL o número de ID…"));
        protocolSearchEdit_->setToolTip(QStringLiteral(
            "Coincide en todo el contenido de la fila (incl. vista previa de IDs y URL principal)."));
        connect(protocolSearchEdit_, &QLineEdit::textChanged, this, &MainWindow::onProtocolFilterChanged);
        fl->addWidget(protocolSearchEdit_, 1);
        protocolLogAutoScrollChk_ = new QCheckBox(QStringLiteral("Auto-scroll a último paquete"));
        protocolLogAutoScrollChk_->setChecked(true);
        protocolLogAutoScrollChk_->setToolTip(
            QStringLiteral("Si está activo, al llegar un paquete nuevo la lista baja al final."));
        fl->addWidget(protocolLogAutoScrollChk_);
        importExportedLogBtn_ = new QPushButton(QStringLiteral("Importar .txt…"));
        importExportedLogBtn_->setToolTip(QStringLiteral("Vista previa del primer paquete y recuento antes de cargar."));
        connect(importExportedLogBtn_, &QPushButton::clicked, this, &MainWindow::onImportExportedLogClicked);
        fl->addWidget(importExportedLogBtn_);
        clearProtocolLogBtn_ = new QPushButton(QStringLiteral("Vaciar lista"));
        connect(clearProtocolLogBtn_, &QPushButton::clicked, this, &MainWindow::onClearProtocolLogClicked);
        fl->addWidget(clearProtocolLogBtn_);
        v->addLayout(fl);

        auto* fl2 = new QHBoxLayout;
        protocolPauseTableCaptureChk_ = new QCheckBox(QStringLiteral("Pausar nueva captura en tabla"));
        protocolPauseTableCaptureChk_->setToolTip(QStringLiteral(
            "El proxy sigue reenviando tráfico; no se añaden filas al log hasta que desmarcas (la importación desde .txt sigue funcionando)."));
        protocolMultiKindFilterChk_ = new QCheckBox(QStringLiteral("Varios tipos (elegir…)"));
        protocolMultiKindFilterChk_->setToolTip(QStringLiteral(
            "Oculta el filtro del desplegable y deja visibles solo los tipos que marques en «Tipos…»."));
        protocolPickMultiKindsBtn_ = new QPushButton(QStringLiteral("Tipos…"));
        protocolPickMultiKindsBtn_->setEnabled(false);
        connect(protocolMultiKindFilterChk_, &QCheckBox::toggled, this, [this](bool on) {
            if (protocolKindFilter_ != nullptr) {
                protocolKindFilter_->setEnabled(!on);
            }
            if (protocolPickMultiKindsBtn_ != nullptr) {
                protocolPickMultiKindsBtn_->setEnabled(on);
            }
            if (!on) {
                protocolMultiKindPickSet_.clear();
            }
            applyProtocolLogFilters();
        });
        connect(protocolPickMultiKindsBtn_, &QPushButton::clicked, this, &MainWindow::openProtocolKindMultiFilterDialog);
        fl2->addWidget(protocolPauseTableCaptureChk_);
        fl2->addWidget(protocolMultiKindFilterChk_);
        fl2->addWidget(protocolPickMultiKindsBtn_);
        fl2->addStretch(1);
        v->addLayout(fl2);

        idAliasRulesEdit_ = new QPlainTextEdit;
        idAliasRulesEdit_->setPlaceholderText(QStringLiteral(
            "Alias de rangos (opcional), una línea:\n513600-513699:Mi trigo personalizado\n2000000-2009999:Piwi:monstruo\n"
            "(categorías: recurso · monstruo · objeto · línea vacía tras # es comentario)"));
        idAliasRulesEdit_->setMinimumHeight(70);
        idAliasRulesEdit_->setMaximumHeight(120);
        idAliasRulesEdit_->setToolTip(
            QStringLiteral("Se aplican antes que los rangos por defecto; útil como «alias recursos» del script Python."));
        {
            auto fnt = idAliasRulesEdit_->font();
            fnt.setFamily(QStringLiteral("Consolas"));
            idAliasRulesEdit_->setFont(fnt);
        }
        connect(idAliasRulesEdit_, &QPlainTextEdit::textChanged, this, &MainWindow::onIdAliasRulesChanged);
        v->addWidget(idAliasRulesEdit_);

        protocolLogSplitter_ = new QSplitter(Qt::Vertical);

        protocolLogTree_ = new QTreeWidget;
        protocolLogTree_->setColumnCount(7);
        protocolLogTree_->setHeaderLabels({QStringLiteral("#"), QStringLiteral("Hora"), QStringLiteral("Dir"),
                                           QStringLiteral("Tipo"), QStringLiteral("Bytes"),
                                           QStringLiteral("String principal"), QStringLiteral("IDs (×3)")});
        protocolLogTree_->setAlternatingRowColors(true);
        protocolLogTree_->setUniformRowHeights(true);
        protocolLogTree_->setRootIsDecorated(false);
        protocolLogTree_->header()->setStretchLastSection(true);
        protocolLogTree_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        protocolLogTree_->setContextMenuPolicy(Qt::CustomContextMenu);
        protocolLogTree_->setToolTip(
            QStringLiteral("Clic: detalle HEX abajo · menú derecho: exportar paquete. Colores por tipo."));
        protocolLogSplitter_->addWidget(protocolLogTree_);

        auto* detailBox = new QWidget;
        auto* dv = new QVBoxLayout(detailBox);
        dv->setContentsMargins(0, 8, 0, 0);
        dv->addWidget(new QLabel(QStringLiteral("<b>Detalle del paquete</b> — HEX completo, strings, IDs y análisis")));
        protocolDetailText_ = new QTextBrowser;
        protocolDetailText_->setReadOnly(true);
        protocolDetailText_->setOpenExternalLinks(false);
        protocolDetailText_->setOpenLinks(false);
        protocolDetailText_->setMinimumHeight(220);
        protocolDetailText_->setStyleSheet(
            QStringLiteral("QTextBrowser { background-color: #111827; color: #e5e7eb; }"));
        {
            auto df = protocolDetailText_->font();
            df.setFamily(QStringLiteral("Segoe UI"));
            protocolDetailText_->setFont(df);
        }
        connect(protocolDetailText_, &QTextBrowser::anchorClicked, this, [this](const QUrl& url) {
            if (url.scheme() != QLatin1String("dofusid") || url.host() != QLatin1String("save")) {
                return;
            }
            QString p = url.path();
            if (p.startsWith(QLatin1Char('/'))) {
                p = p.mid(1);
            }
            bool ok = false;
            const quint64 id = p.toULongLong(&ok);
            if (!ok || id == 0) {
                return;
            }
            promptSaveIdFromPacketDetail(id);
        });
        dv->addWidget(protocolDetailText_);

        irxClassifyFrame_ = new QFrame;
        irxClassifyFrame_->setVisible(false);
        irxClassifyFrame_->setStyleSheet(QStringLiteral("QFrame { background:#0f172a; border:1px solid #334155;"
                                                      "border-radius:6px; padding: 4px;}"));
        auto* irLay = new QHBoxLayout(irxClassifyFrame_);
        irLay->addWidget(new QLabel(QStringLiteral("<b>IRX</b>: ID rápido →")));
        irxIdCombo_ = new QComboBox;
        irxIdCombo_->setMinimumWidth(200);
        irLay->addWidget(irxIdCombo_);
        irxNameEdit_ = new QLineEdit;
        irxNameEdit_->setPlaceholderText(QStringLiteral("Nombre visible (opcional)"));
        irxNameEdit_->setMinimumWidth(180);
        irLay->addWidget(irxNameEdit_);
        irxMarkMonsterBtn_ = new QPushButton(QStringLiteral("Marcar como monstruo"));
        irxMarkPersonajeBtn_ = new QPushButton(QStringLiteral("Marcar como personaje"));
        irLay->addWidget(irxMarkMonsterBtn_);
        irLay->addWidget(irxMarkPersonajeBtn_);
        irLay->addStretch(1);
        connect(irxMarkMonsterBtn_, &QPushButton::clicked, this, [this]() { persistSelectedIrxId(true); });
        connect(irxMarkPersonajeBtn_, &QPushButton::clicked, this, [this]() { persistSelectedIrxId(false); });
        dv->addWidget(irxClassifyFrame_);

        auto* tmplRow = new QHBoxLayout;
        saveTmplN_btn_ = new QPushButton(QStringLiteral("Plantilla ☆iri → Norte"));
        saveTmplS_btn_ = new QPushButton(QStringLiteral("Sur"));
        saveTmplE_btn_ = new QPushButton(QStringLiteral("Este"));
        saveTmplO_btn_ = new QPushButton(QStringLiteral("Oeste"));
        saveTmplN_btn_->setToolTip(QStringLiteral(
            "Guarda el payload IRI seleccionado (pide confirmación). Requiere direcciones_map.json."));
        saveTmplS_btn_->setToolTip(saveTmplN_btn_->toolTip());
        saveTmplE_btn_->setToolTip(saveTmplN_btn_->toolTip());
        saveTmplO_btn_->setToolTip(saveTmplN_btn_->toolTip());
        connect(saveTmplN_btn_, &QPushButton::clicked, this, [this]() { saveSelectedPacketAsTemplate(QStringLiteral("Norte")); });
        connect(saveTmplS_btn_, &QPushButton::clicked, this, [this]() { saveSelectedPacketAsTemplate(QStringLiteral("Sur")); });
        connect(saveTmplE_btn_, &QPushButton::clicked, this, [this]() { saveSelectedPacketAsTemplate(QStringLiteral("Este")); });
        connect(saveTmplO_btn_, &QPushButton::clicked, this, [this]() { saveSelectedPacketAsTemplate(QStringLiteral("Oeste")); });
        tmplRow->addWidget(saveTmplN_btn_);
        tmplRow->addWidget(saveTmplS_btn_);
        tmplRow->addWidget(saveTmplE_btn_);
        tmplRow->addWidget(saveTmplO_btn_);
        tmplRow->addStretch(1);
        dv->addLayout(tmplRow);
        auto* harvestRow = new QHBoxLayout;
        saveIeeTemplateBtn_ = new QPushButton(QStringLiteral("Guardar IEE → plantilla_recolectar.bin"));
        saveIeeTemplateBtn_->setToolTip(
            QStringLiteral("Solo paquetes IEE seleccionados en la tabla. Payload bruto junto al ejecutable."));
        connect(saveIeeTemplateBtn_, &QPushButton::clicked, this, &MainWindow::onSaveIeeTemplateClicked);
        recolectHarvestBtn_ = new QPushButton(QStringLiteral("RECOLECTAR"));
        recolectHarvestBtn_->setToolTip(
            QStringLiteral("Inyecta plantilla_recolectar.bin hacia el servidor y espera hasta 2 s un IDR."));
        connect(recolectHarvestBtn_, &QPushButton::clicked, this, &MainWindow::onRecolectHarvestClicked);
        harvestStatusLbl_ = new QLabel(QStringLiteral("Plantilla IEE: —"));
        harvestStatusLbl_->setStyleSheet(QStringLiteral("color:#cbd5e1;"));
        harvestRow->addWidget(saveIeeTemplateBtn_);
        harvestRow->addWidget(recolectHarvestBtn_);
        harvestRow->addWidget(harvestStatusLbl_, 1);
        dv->addLayout(harvestRow);

        protocolLogSplitter_->addWidget(detailBox);
        protocolLogSplitter_->setStretchFactor(0, 55);
        protocolLogSplitter_->setStretchFactor(1, 45);
        v->addWidget(protocolLogSplitter_, 1);

        auto* dz = new LogsDropFrame(pageProto);
        protocolDropZone_ = dz;
        dz->onFileDropped = [this](const QString& p) { showImportLogPreviewDialog(p); };
        v->addWidget(protocolDropZone_);

        connect(protocolLogTree_,
                QOverload<QTreeWidgetItem*, QTreeWidgetItem*>::of(&QTreeWidget::currentItemChanged), this,
                &MainWindow::onProtocolLogCurrentItemChanged);
        connect(protocolLogTree_, &QTreeWidget::customContextMenuRequested, this,
                &MainWindow::onProtocolLogContextMenu);
    }
    mainTabWidget_->insertTab(1, wrapInScroll(pageRes), QStringLiteral("Recursos"));
    mainTabWidget_->insertTab(2, wrapInScroll(pageProto), QStringLiteral("Logs"));

    // —— Bloques para pestaña Avanzado ——
    auto* pageProc = new QWidget;
    auto* procLay = new QVBoxLayout(pageProc);
    procLay->setSpacing(8);
    procLay->setContentsMargins(8, 8, 8, 8);

    auto* title = new QLabel(QStringLiteral(
        "<b>Procesos</b> — hook <code>connect()</code> + proxy <code>127.0.0.1:5555</code>."));
    title->setWordWrap(true);
    procLay->addWidget(title);

    auto* procTbRow = new QHBoxLayout;
    refreshBtn_ = new QPushButton(QStringLiteral("Actualizar procesos"));
    connect(refreshBtn_, &QPushButton::clicked, this, &MainWindow::refreshProcesses);
    procTbRow->addWidget(refreshBtn_);
    procTbRow->addStretch(1);
    procLay->addLayout(procTbRow);

    dofStatus_ = new QLabel;
    dofStatus_->setWordWrap(true);
    selectedPidLbl_ = new QLabel(QStringLiteral("PID seleccionado: —"));
    procLay->addWidget(dofStatus_);
    procLay->addWidget(selectedPidLbl_);

    auto* filterRow = new QHBoxLayout;
    filterRow->addWidget(new QLabel(QStringLiteral("Filtro nombre:")));
    nameFilterEdit_ = new QLineEdit;
    nameFilterEdit_->setPlaceholderText(QStringLiteral("vacío = todos"));
    connect(nameFilterEdit_, &QLineEdit::textChanged, this, &MainWindow::applyTableFilter);
    filterRow->addWidget(nameFilterEdit_, 1);
    procLay->addLayout(filterRow);

    dofusOnlyCheckbox_ = new QCheckBox(QStringLiteral("Mostrar solo procesos con «Dofus» en el nombre"));
    dofusOnlyCheckbox_->setChecked(true);
    connect(dofusOnlyCheckbox_, &QCheckBox::toggled, this, &MainWindow::applyTableFilter);

    autoSelectSingleCheckbox_ = new QCheckBox(
        QStringLiteral("Si hay exactamente un proceso «Dofus», seleccionarlo automáticamente"));
    autoSelectSingleCheckbox_->setChecked(true);
    procLay->addWidget(dofusOnlyCheckbox_);
    procLay->addWidget(autoSelectSingleCheckbox_);

    procTable_ = new QTableWidget(0, 2);
    procTable_->setHorizontalHeaderLabels({QStringLiteral("PID"), QStringLiteral("Proceso")});
    procTable_->horizontalHeader()->setStretchLastSection(true);
    procTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    procTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    procTable_->setAlternatingRowColors(true);
    procTable_->verticalHeader()->setVisible(false);
    connect(procTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
        const auto items = procTable_->selectedItems();
        if (items.isEmpty()) {
            selectedPidLbl_->setText(QStringLiteral("PID seleccionado: —"));
            return;
        }
        const int row = items.first()->row();
        bool ok = false;
        const quint32 pid = procTable_->item(row, 0)->text().toUInt(&ok);
        if (ok) {
            const QString name = procTable_->item(row, 1)->text();
            selectedPidLbl_->setText(QStringLiteral("PID seleccionado: %1 — %2").arg(pid).arg(name));
        }
    });

    procTable_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    procTable_->setMinimumHeight(160);
    procLay->addWidget(procTable_, 1);

    auto* pageProxyAdv = new QWidget;
    auto* al = new QVBoxLayout(pageProxyAdv);
    al->setSpacing(8);
    al->setContentsMargins(8, 8, 8, 8);
#ifdef Q_OS_WIN
    monitorUsageLbl_ = new QLabel(QStringLiteral(
        "<pre style=\"white-space:pre-wrap;font-family:Consolas,monospace;font-size:12px;color:#fde68a;\">"
        "================================================\n"
        "CÓMO USAR (monitor + DNS en DLL)\n"
        "================================================\n"
        "1. Ejecuta este programa COMO ADMINISTRADOR.\n"
        "2. NO abras Dofus todavía (recomendado para inyección temprana).\n"
        "3. Pulsa «Iniciar monitor Dofus» (pestaña Avanzado).\n"
        "4. Abre Dofus: al aparecer Dofus.exe se inyectará la DLL y se cerrarán sockets salientes.\n"
        "5. Pulsa «Iniciar proxy» y después abre Dofus; o usa «Iniciar proxy + DLL (PID)» si ya "
        "tienes el juego abierto.\n"
        "6. Si falla: «Diagnóstico completo» y revisa %TEMP%\\dofus_redirect_log.txt\n"
        "================================================</pre>"));
    monitorUsageLbl_->setWordWrap(true);
    al->addWidget(monitorUsageLbl_);

    hookDiagPanel_ = new QLabel(QStringLiteral("<b>Diagnóstico del hook</b> (leyendo log DLL…)"));
    hookDiagPanel_->setWordWrap(true);
    hookDiagPanel_->setTextFormat(Qt::RichText);
    hookDiagPanel_->setStyleSheet(QStringLiteral(
        "background:#1a1a1a;border:1px solid #444;border-radius:6px;padding:10px;color:#e5e5e5;"));
    al->addWidget(hookDiagPanel_);

    auto* monRowTop = new QHBoxLayout;
    monRowTop->addWidget(monitorStartBtn_);
    monRowTop->addWidget(monitorStopBtn_);
    monRowTop->addWidget(fullDiagnosticBtn_);
    monRowTop->addStretch(1);
    al->addLayout(monRowTop);
#endif
    al->addWidget(new QLabel(QStringLiteral(
        "<b>Proxy TCP</b> en <b>0.0.0.0:5555</b>. <b>DofusRedirect.dll</b> (MinHook) intercepta "
        "<code>getaddrinfo</code>/<code>GetAddrInfoW</code>/<code>gethostbyname</code> (Ankama→127.0.0.1) y "
        "<code>connect</code>/<code>WSAConnect</code>/<code>ConnectEx</code>; reenvío al <i>upstream</i>.")));

    auto* gridBind = new QGridLayout;
    gridBind->setHorizontalSpacing(8);
    gridBind->setColumnStretch(1, 1);
    gridBind->addWidget(new QLabel(QStringLiteral("Escucha")), 0, 0, Qt::AlignRight);
    bindHost_ = new QLineEdit(QStringLiteral("0.0.0.0"));
    bindPort_ = new QLineEdit(QString::number(kLocalProxyMustPort));
    bindPort_->setReadOnly(true);
    bindHost_->setReadOnly(true);
    bindHost_->setMaximumWidth(220);
    bindPort_->setMaximumWidth(88);
    gridBind->addWidget(bindHost_, 0, 1);
    gridBind->addWidget(new QLabel(QStringLiteral(":")), 0, 2);
    gridBind->addWidget(bindPort_, 0, 3);
    gridBind->addWidget(new QLabel(QStringLiteral("IP del servidor real (upstream)")), 1, 0, Qt::AlignRight);
    upstreamHost_ = new QLineEdit;
    upstreamHost_->setPlaceholderText(QStringLiteral(
        "IPv4/IPv6 literal — sin DNS (hosts puede mandar nombres Ankama a 127.0.0.1; el proxy usa solo esta IP)"));
    upstreamPort_ = new QLineEdit(QString::number(kUpstreamDefaultPort));
    upstreamPort_->setMaximumWidth(88);
    gridBind->addWidget(upstreamHost_, 1, 1);
    gridBind->addWidget(new QLabel(QStringLiteral(":")), 1, 2);
    gridBind->addWidget(upstreamPort_, 1, 3);
    applyUpstreamBtn_ = new QPushButton(QStringLiteral("Aplicar upstream"));
    applyUpstreamBtn_->setToolTip(QStringLiteral(
        "Copia IP/puerto del servidor real al proxy y, si ya hay un cliente en :5555, abre el túnel al servidor."));
    connect(applyUpstreamBtn_, &QPushButton::clicked, this, &MainWindow::onApplyUpstreamClicked);
    gridBind->addWidget(applyUpstreamBtn_, 2, 1, 1, 2);
    forceRedetectUpstreamBtn_ = new QPushButton(QStringLiteral("Forzar redetección"));
    forceRedetectUpstreamBtn_->setToolTip(
        QStringLiteral("Limpia upstream actual y vuelve a detectar automáticamente desde tráfico/log DLL."));
    connect(forceRedetectUpstreamBtn_, &QPushButton::clicked, this,
            &MainWindow::onForceUpstreamRedetectClicked);
    gridBind->addWidget(forceRedetectUpstreamBtn_, 2, 3, 1, 1);
    al->addLayout(gridBind);

    {
        auto* upstreamIpHint = new QLabel(
            QStringLiteral("<span style=\"color:#9ca3af;font-size:11px\">IPs habituales del mundo (prueba si una falla): "
                           "54.76.83.103 · 176.34.170.182 · 34.255.108.179 · 52.210.122.150 · "
                           "63.35.115.67 — el proxy <b>no</b> resuelve DNS del sistema para el upstream.</span>"));
        upstreamIpHint->setWordWrap(true);
        upstreamIpHint->setTextFormat(Qt::RichText);
        al->addWidget(upstreamIpHint);
    }

    proxyStartupOrderLbl_ = new QLabel(QStringLiteral(
        "<span style=\"color:#fcd34d\">⚠️ ORDEN recomendado:</span> "
        "<b>1)</b> Pulsa «Iniciar proxy» y espera la línea «Escuchando … :5555» en el <b>Registro</b>. "
        "<b>2)</b> Entonces abre Dofus (si el juego ya conectó antes al servidor, reconecta / reinicia). "
        "<b>Upstream:</b> IP literal del servidor real (por defecto 54.76.83.103); sin DNS."));
    proxyStartupOrderLbl_->setWordWrap(true);
    al->addWidget(proxyStartupOrderLbl_);

    proxyProbeHintsLbl_ = new QLabel(QStringLiteral(
        "<span style=\"color:#a5b4fc\">Pruebas:</span> Con el proxy en marcha, <code>telnet 127.0.0.1 5555</code> "
        "(o PowerShell <code>Test-NetConnection 127.0.0.1 -Port 5555</code>) comprueba que el puerto acepta TCP. "
        "Log DLL redirect: <code>%1</code>")
                           .arg(QDir::toNativeSeparators(
                               QDir(QDir::tempPath()).absoluteFilePath(QStringLiteral("dofus_redirect_log.txt")))));
    proxyProbeHintsLbl_->setWordWrap(true);
    proxyProbeHintsLbl_->setTextFormat(Qt::RichText);
    al->addWidget(proxyProbeHintsLbl_);

    connect(upstreamHost_, &QLineEdit::textChanged, this, &MainWindow::updateUpstreamQuickLabel);
    connect(upstreamPort_, &QLineEdit::textChanged, this, &MainWindow::updateUpstreamQuickLabel);

    drainQueueLogChk_ = new QCheckBox(QStringLiteral(
        "Log cada reenvío cola→socket (C→S / S→C): hex hasta 64 B en Servidor→Cliente + qDebug"));
    drainQueueLogChk_->setChecked(false);
    drainQueueLogChk_->setToolTip(QStringLiteral(
        "No modifica bytes: registra cada write() desde colas; en S→C verás [PROXY] Servidor→Cliente con hex "
        "(comparar con Cliente→Servidor)."));
    connect(drainQueueLogChk_, &QCheckBox::toggled, this, &MainWindow::syncProxyOptionsFromUi);
    al->addWidget(drainQueueLogChk_);

    verboseProxyChk_ = new QCheckBox(QStringLiteral("Diagnóstico [PROXY] detallado (tamaño + hex 64 B + iri)"));
    verboseProxyChk_->setChecked(true);
    connect(verboseProxyChk_, &QCheckBox::toggled, this, &MainWindow::syncProxyOptionsFromUi);
    al->addWidget(verboseProxyChk_);

    fullTunnelDiagChk_ = new QCheckBox(
        QStringLiteral("Diagnóstico completo del túnel ([DIAG] S↔C, colas, writes, timeout connect 60 s, IPv6/IPv4)"));
    fullTunnelDiagChk_->setChecked(false);
    fullTunnelDiagChk_->setToolTip(QStringLiteral(
        "Añade trazas [DIAG] y explica reenvío/colas/errores. No modifica bytes; el timeout de conexión upstream es de "
        "60 s (aviso en log si el servidor tarda)."));
    connect(fullTunnelDiagChk_, &QCheckBox::toggled, this, &MainWindow::syncProxyOptionsFromUi);
    al->addWidget(fullTunnelDiagChk_);

    rawForwarderChk_ = new QCheckBox(QStringLiteral(
        "Modo transparente — solo reenvío de bytes C↔S (sin análisis IRI, sin captura handshake, sin plantillas en "
        "último paquete)"));
    rawForwarderChk_->setChecked(false);
    rawForwarderChk_->setToolTip(QStringLiteral(
        "Equivalente a «raw pipe»: misma ruta que append(d)+write(d) sin transformar payload. Aísla si el cierre del "
        "upstream viene del análisis o del reenvío; desactiva telemetría en hot-path."));
    connect(rawForwarderChk_, &QCheckBox::toggled, this, &MainWindow::syncProxyOptionsFromUi);
    al->addWidget(rawForwarderChk_);

    transparentProxyChk_ = new QCheckBox(
        QStringLiteral("Modo transparente: solo reenvío bruto (sin inyectar paquetes desde la UI)"));
    transparentProxyChk_->setChecked(false);
    connect(transparentProxyChk_, &QCheckBox::toggled, this, &MainWindow::syncProxyOptionsFromUi);
    connect(transparentProxyChk_, &QCheckBox::toggled, this, &MainWindow::refreshMovementButtonsEnabled);
    al->addWidget(transparentProxyChk_);

    minimalProxyChk_ = new QCheckBox(QStringLiteral(
        "Diagnóstico: proxy mínimo (solo acepta TCP y loguea; sin upstream ni reenvío)"));
    minimalProxyChk_->setChecked(false);
    minimalProxyChk_->setToolTip(QStringLiteral(
        "Si está marcado, el listener en :5555 no abre conexión al servidor real; solo verás si algo conecta."));
    al->addWidget(minimalProxyChk_);
    connect(minimalProxyChk_, &QCheckBox::toggled, this, &MainWindow::syncProxyOptionsFromUi);
    connect(minimalProxyChk_, &QCheckBox::toggled, this, &MainWindow::refreshMovementButtonsEnabled);

    listenIpv6Chk_ = new QCheckBox(QStringLiteral("Escuchar en IPv6 ([::1], mismo puerto; clientes redirigidos por el hook IPv6)"));
    listenIpv6Chk_->setChecked(true);
    listenIpv6Chk_->setToolTip(QStringLiteral(
        "Por defecto activo: el juego puede usar ::1:5555 mientras el proxy también escucha en 127.0.0.1. "
        "Desmárcalo solo si no quieres el listener IPv6."));
    connect(listenIpv6Chk_, &QCheckBox::toggled, this, &MainWindow::syncProxyOptionsFromUi);
    al->addWidget(listenIpv6Chk_);

    auto* testRow = new QHBoxLayout;
    testUpstreamBtn_ = new QPushButton(QStringLiteral("Modo prueba upstream"));
    testUpstreamBtn_->setToolTip(QStringLiteral(
        "1) ping -n 1 a la IP · 2) TCP al puerto upstream (como telnet). Conexión por dirección literal, sin DNS."));
    connect(testUpstreamBtn_, &QPushButton::clicked, this, &MainWindow::onTestUpstreamClicked);
    testRow->addWidget(testUpstreamBtn_);
#ifdef Q_OS_WIN
    manualWinsockConnectBtn_ = new QPushButton(QStringLiteral("Test connect Winsock → 127.0.0.1:5555"));
    manualWinsockConnectBtn_->setToolTip(QStringLiteral(
        "Prueba manual con socket()/connect() nativos (como en el diagnóstico). Requiere proxy activo en :5555."));
    connect(manualWinsockConnectBtn_, &QPushButton::clicked, this, &MainWindow::onManualWinsockConnectClicked);
    testRow->addWidget(manualWinsockConnectBtn_);
#endif
    testRow->addStretch(1);
    al->addLayout(testRow);

#ifdef Q_OS_WIN
    auto* diagDllRow = new QHBoxLayout;
    injectTestDllBtn_ = new QPushButton(QStringLiteral("Inyectar DofusTestDll.dll (solo log, sin hooks)"));
    injectTestDllBtn_->setToolTip(QStringLiteral(
        "Inyecta la DLL mínima junto al .exe. Si la inyección funciona, aparece C:\\test_dll_log.txt y una línea en "
        "C:\\dofus_debug_log.txt."));
    connect(injectTestDllBtn_, &QPushButton::clicked, this, &MainWindow::onInjectTestDllClicked);
    diagDllRow->addWidget(injectTestDllBtn_);
    netstat5555Btn_ = new QPushButton(QStringLiteral("netstat :5555 (127.0.0.1)"));
    netstat5555Btn_->setToolTip(QStringLiteral("Ejecuta: netstat -ano | findstr 127.0.0.1:5555"));
    connect(netstat5555Btn_, &QPushButton::clicked, this, &MainWindow::onNetstat5555Clicked);
    diagDllRow->addWidget(netstat5555Btn_);
    diagDllRow->addStretch(1);
    al->addLayout(diagDllRow);
#endif

    upstreamDetectedLbl_ = new QLabel(QStringLiteral("Upstream visto en TCP: —"));
    upstreamDetectedLbl_->setWordWrap(true);
    upstreamDetectedLbl_->setStyleSheet(QStringLiteral("color:#93c5fd;font-size:12px;"));
    al->addWidget(upstreamDetectedLbl_);

    proxyTestHintsLbl_ = new QLabel(QStringLiteral(
        "<p><b>Prueba rápida en «Registro»</b></p>"
        "<ol style=\"margin-top:4px\">"
        "<li>Inicia proxy (y DLL si aplica).</li>"
        "<li>Abre Dofus; debe conectar a <code>127.0.0.1:5555</code>.</li>"
        "<li>Busca: <code>[PROXY] Cliente conectado desde …</code>, luego "
        "<code>Conectado upstream a …</code>.</li>"
        "<li>Si ves <code>Cliente→Proxy</code> y <code>Servidor→Proxy</code> con bytes, el túnel TCP funciona.</li>"
        "<li>Solo cliente→proxy y nada del servidor: revisa IP/puerto upstream o firewall.</li>"
        "<li>Sin líneas [PROXY]: el juego no llega al listener (DLL / puerto).</li>"
        "<li>Si el protocolo fuera TLS, haría falta MITM con certificados; este proxy solo reenvía bytes TCP tal "
        "cual.</li>"
        "</ol>"));
    proxyTestHintsLbl_->setWordWrap(true);
    proxyTestHintsLbl_->setTextInteractionFlags(Qt::TextBrowserInteraction);
    al->addWidget(proxyTestHintsLbl_);

    userStepsLbl_ =
        new QLabel(QStringLiteral(
            "<p><b>Uso corto</b></p>"
            "<ol>"
            "<li>Ejecuta esta app <b>como administrador</b> (inyección DLL + <code>SetTcpEntry</code> opcional).</li>"
            "<li>Compila: <b>DofusRedirect.dll</b> junto al .exe (MinHook: connect, WSAConnect, ConnectEx; traza "
            "<code>socket</code>/<code>WSASocketW</code>).</li>"
            "<li>O bien <b>Iniciar proxy</b> y luego abre Dofus; o selecciona <b>Dofus.exe</b>, "
            "revisa la DLL y usa <b>Iniciar proxy + DLL (PID)</b> / <b>Inyectar DLL ahora</b>. Tras inyectar, el "
            "programa intenta <b>cerrar sockets TCP IPv4 del PID al "
            "puerto remoto 5555</b> para forzar reconexión por el hook.</li>"
            "<li>Log del hook: <code>%TEMP%\\dofus_redirect_log.txt</code> (también se muestra un resumen en el "
            "monitor).</li>"
            "<li><b>Detener proxy</b> solo cierra el listener; la DLL sigue cargada hasta cerrar Dofus.</li>"
            "</ol>"
            "<p style=\"color:#fbbf24\"><b>IMPORTANTE</b> — Tras inyectar, si el juego ya estaba conectado al mundo, "
            "<b>reconecta</b>:</p>"
            "<ol style=\"color:#fcd34d\">"
            "<li>Cierra sesión en el juego (desconéctate del servidor / personaje).</li>"
            "<li>Vuelve a entrar al mundo.</li>"
            "<li>Las nuevas conexiones deberían ir a <code>127.0.0.1:5555</code>.</li>"
            "</ol>"
            "<p style=\"color:#e5e5e5\"><b>Más simple:</b> reinicia Dofus por completo después de la inyección.</p>"
            "<p><b>Sin DLL:</b> la sección «Archivo hosts» crea copia de seguridad y añade <code>127.0.0.1</code> "
            "para dominios Ankama (requiere ejecutar como administrador).</p>"));
    userStepsLbl_->setWordWrap(true);
    userStepsLbl_->setTextInteractionFlags(Qt::TextBrowserInteraction);
    al->addWidget(userStepsLbl_);

#ifdef Q_OS_WIN
    {
        auto* hostsBox =
            new QGroupBox(QStringLiteral("Archivo hosts (redirigir tráfico al proxy sin DLL)"));
        hostsBox->setStyleSheet(QStringLiteral(
            "QGroupBox { border: 1px solid #3f3f3f; border-radius: 6px; margin-top: 8px; padding: 12px 8px 8px 8px; "
            "}"));
        auto* hl = new QHBoxLayout(hostsBox);
        applyHostsBtn_ = new QPushButton(QStringLiteral("Aplicar entradas (backup + bloque 127.0.0.1)"));
        applyHostsBtn_->setToolTip(QStringLiteral(
            "Primera vez: copia hosts a hosts.bak.dofus_sniffer. Añade bloque marcado con dominios Ankama → "
            "127.0.0.1. "
            "Ejecutar como administrador."));
        connect(applyHostsBtn_, &QPushButton::clicked, this, &MainWindow::onApplyHostsClicked);
        restoreHostsBtn_ = new QPushButton(QStringLiteral("Restaurar hosts"));
        restoreHostsBtn_->setToolTip(
            QStringLiteral("Si existe el backup, restaura desde hosts.bak.dofus_sniffer; si no, quita solo el "
                           "bloque marcado."));
        connect(restoreHostsBtn_, &QPushButton::clicked, this, &MainWindow::onRestoreHostsClicked);
        hl->addWidget(applyHostsBtn_);
        hl->addWidget(restoreHostsBtn_);
        hl->addStretch(1);
        al->addWidget(hostsBox);
    }
#endif

    reconnectHintLbl_ = new QLabel(
        QStringLiteral("⚠️ Sin túnel activo: confirma que la DLL está inyectada y que el juego abre TCP a "
                       "<code>127.0.0.1:5555</code>."));
    reconnectHintLbl_->setWordWrap(true);
    reconnectHintLbl_->setVisible(false);
    reconnectHintLbl_->setStyleSheet(QStringLiteral("color: #fcd34d;"));

#ifdef Q_OS_WIN
    auto* dllBox = new QGroupBox(QStringLiteral("DofusRedirect.dll · inyección"));
    dllBox->setStyleSheet(QStringLiteral(
        "QGroupBox { border: 1px solid #3f3f3f; border-radius: 6px; margin-top: 8px; padding: 12px 8px 8px 8px; }"));
    auto* dvl = new QVBoxLayout(dllBox);
    dllPathEdit_ = new QLineEdit;
    dllPathEdit_->setPlaceholderText(QStringLiteral("Ruta absoluta a DofusRedirect.dll"));
    dllPathEdit_->setText(defaultRedirectDllPath());
    dvl->addWidget(dllPathEdit_);
    autoInjectDllChk_ = new QCheckBox(
        QStringLiteral("Al iniciar proxy: inyectar la DLL en el PID seleccionado (recomendado)"));
    autoInjectDllChk_->setChecked(true);
    dvl->addWidget(autoInjectDllChk_);
    massCloseOutboundTcpAfterInjectChk_ = new QCheckBox(
        QStringLiteral(
            "Avanzado (agresivo): tras inyectar, cerrar todas las salidas TCP IPv4 del PID (no-loopback)"));
    massCloseOutboundTcpAfterInjectChk_->setChecked(false);
    massCloseOutboundTcpAfterInjectChk_->setToolTip(
        QStringLiteral("Por defecto OFF: suele cortar launcher/HTTPS y puede hacer que Dofus se cierre. "
                       "Deja OFF y solo fuerza reconexión al mundo con el cierre dirigido :5555."));
    dvl->addWidget(massCloseOutboundTcpAfterInjectChk_);
    injectDllBtn_ = new QPushButton(QStringLiteral("Inyectar DLL ahora"));
    connect(injectDllBtn_, &QPushButton::clicked, this, &MainWindow::onInjectDllClicked);
    dvl->addWidget(injectDllBtn_);

    diagProxyIndLbl_ = new QLabel(QStringLiteral("127.0.0.1:5555 — —"));
    diagProxyIndLbl_->setWordWrap(true);
    dvl->addWidget(diagProxyIndLbl_);
    diagLastFlowLbl_ = new QLabel(QStringLiteral("Última conexión relevante: —"));
    diagLastFlowLbl_->setWordWrap(true);
    dvl->addWidget(diagLastFlowLbl_);
#endif

    auto* probeBox =
        new QGroupBox(QStringLiteral("🔗 Conexiones del PID (tabla TCP cada ~1,1 s · no bloquea UI)"));
    probeBox->setStyleSheet(QStringLiteral(
        "QGroupBox { border: 1px solid #3f3f3f; border-radius: 6px; margin-top: 8px; padding: 12px 8px 8px 8px; }"));
    probeBox->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    auto* gv = new QVBoxLayout(probeBox);
    gv->addWidget(reconnectHintLbl_);
#ifdef Q_OS_WIN
    gv->addWidget(dllBox);
#endif

    memIpReadLbl_ = new QLabel(QStringLiteral("Hook DLL: —"));
    memIpReadLbl_->setWordWrap(true);
    memIpReadLbl_->setTextFormat(Qt::RichText);
    memIpReadLbl_->setStyleSheet(QStringLiteral("color: #bae6fd;"));
    gv->addWidget(memIpReadLbl_);

    tcpConnDumpLbl_ = new QLabel(QStringLiteral("Selecciona un proceso en la tabla."));
    tcpConnDumpLbl_->setWordWrap(true);
    tcpConnDumpLbl_->setTextFormat(Qt::RichText);
    tcpConnDumpLbl_->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    tcpConnDumpLbl_->setMinimumWidth(200);
    {
        auto fmono = tcpConnDumpLbl_->font();
        fmono.setFamily(QStringLiteral("Consolas"));
        fmono.setStyleHint(QFont::Monospace);
        tcpConnDumpLbl_->setFont(fmono);
        tcpConnDumpLbl_->setStyleSheet(QStringLiteral("padding: 6px;"));
    }

    auto* tcpScroll = new QScrollArea;
    tcpScroll->setWidgetResizable(true);
    tcpScroll->setFrameShape(QFrame::StyledPanel);
    tcpScroll->setMinimumHeight(200);
    tcpScroll->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    auto* tcpDumpWrap = new QWidget;
    auto* tcpDumpLay = new QVBoxLayout(tcpDumpWrap);
    tcpDumpLay->setContentsMargins(2, 2, 2, 2);
    tcpDumpLay->addWidget(tcpConnDumpLbl_);
    tcpScroll->setWidget(tcpDumpWrap);
    gv->addWidget(tcpScroll, 1);

    al->addWidget(probeBox, 1);

    auto* pageAdv = new QWidget;
    auto* advRoot = new QVBoxLayout(pageAdv);
    advRoot->setSpacing(10);
    advRoot->setContentsMargins(4, 4, 4, 4);
    advRoot->addWidget(wrapInScroll(pageProc));
    advRoot->addWidget(wrapInScroll(pageProxyAdv));

    auto* pageMap = new QWidget;
    auto* ml = new QVBoxLayout(pageMap);
    ml->setSpacing(8);
    ml->setContentsMargins(8, 8, 8, 8);
    ml->addWidget(
        new QLabel(QStringLiteral("<b>direcciones_map.json</b> — plantillas ☆iri y offset para movimiento")));

    dirMapJsonPath_ = new QLineEdit(guessDirectionMapJsonPath());
    dirMapJsonPath_->setMinimumWidth(200);
    reloadDirMapBtn_ = new QPushButton(QStringLiteral("Cargar modelo"));
    connect(reloadDirMapBtn_, &QPushButton::clicked, this, &MainWindow::reloadDirectionMapClicked);

    auto* rowMap = new QHBoxLayout;
    rowMap->addWidget(dirMapJsonPath_, 1);
    rowMap->addWidget(reloadDirMapBtn_);
    ml->addLayout(rowMap);

    mapModelSummaryLbl_ = new QLabel(QStringLiteral("(modelo sin cargar)"));
    mapModelSummaryLbl_->setWordWrap(true);
    ml->addWidget(mapModelSummaryLbl_);

    importMovementLogBtn_ =
        new QPushButton(QStringLiteral("Importar desde log exportado…"));
    importMovementLogBtn_->setToolTip(QStringLiteral(
        "Busca el primer paquete ☆iri válido en un .txt (p. ej. exportados/ll_p1_to_190.txt) y opcionalmente "
        "fusiona en direcciones_map.json / templates.json."));
    connect(importMovementLogBtn_, &QPushButton::clicked, this, &MainWindow::onImportMovementLogClicked);
    ml->addWidget(importMovementLogBtn_);

    iriOfflineHintLbl_ = new QLabel(QStringLiteral(
        "<span style=\"color:#86efac\">Sin proxy:</span> puedes probar validación ☆iri y plantillas solo con "
        "«Importar desde log» (p. ej. ll_p1_to_190.txt, paquete #148) sin iniciar el proxy."));
    iriOfflineHintLbl_->setWordWrap(true);
    ml->addWidget(iriOfflineHintLbl_);

    iriTokenStatusLbl_ = new QLabel(QStringLiteral("Token sesión (tráfico vivo): —"));
    iriTokenStatusLbl_->setWordWrap(true);
    iriTokenStatusLbl_->setStyleSheet(QStringLiteral("color:#93c5fd;"));
    ml->addWidget(iriTokenStatusLbl_);

    iriTemplateCheckLbl_ = new QLabel(QStringLiteral("Plantillas vs sesión: —"));
    iriTemplateCheckLbl_->setWordWrap(true);
    iriTemplateCheckLbl_->setStyleSheet(QStringLiteral("color:#fcd34d;"));
    ml->addWidget(iriTemplateCheckLbl_);

    movementSeqHintLbl_ = new QLabel(QStringLiteral(
        "<span style=\"color:#bae6fd\">Cambiar de mapa</span>: al subir ves a veces un paquete C→S muy corto clasificado como "
        "<code>ISP</code> con <code>type.ankama.com/jnr</code> y <code>type.ankama.com/isp</code> mezclados en el mismo payload — "
        "sincronización. El movimiento con «clic mapa» reutiliza un IRI cliente→servidor "
        "(<code>type.ankama.com/iri</code>); los botones N/S/E/O y las plantillas ☆iri son la forma fiable de replicarlo en esta app."));
    movementSeqHintLbl_->setWordWrap(true);
    movementSeqHintLbl_->setStyleSheet(QStringLiteral("color:#cbd5e1;"));
    ml->addWidget(movementSeqHintLbl_);

    {
        auto* harvestBox = new QGroupBox(QStringLiteral("Recolectar · espera"));
        auto* hl = new QGridLayout(harvestBox);
        hl->setHorizontalSpacing(8);
        hl->addWidget(new QLabel(QStringLiteral("Espera IEE→IDR")), 0, 0, Qt::AlignRight);
        auto* spin = new QSpinBox;
        spin->setRange(500, 10000);
        spin->setSingleStep(100);
        spin->setSuffix(QStringLiteral(" ms"));
        spin->setValue(harvestWaitMs_);
        spin->setToolTip(QStringLiteral("Tiempo máximo de espera tras inyectar IEE hasta recibir un IDR."));
        connect(spin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int v) {
            harvestWaitMs_ = qBound(500, v, 10000);
            QSettings s(QStringLiteral("fabia"), QStringLiteral("cpp_dofus_sniffer"));
            s.setValue(QStringLiteral("harvestWaitMs"), harvestWaitMs_);
        });
        hl->addWidget(spin, 0, 1);
        auto* hint = new QLabel(QStringLiteral("<span style=\"color:#9ca3af;font-size:11px\">Si falla por timeout, sube a 3000–5000 ms.</span>"));
        hint->setTextFormat(Qt::RichText);
        hint->setWordWrap(true);
        hl->addWidget(hint, 1, 0, 1, 2);
        ml->addWidget(harvestBox);
    }

    ml->addWidget(new QLabel(QStringLiteral(
        "Las flechas de movimiento están en la pestaña <b>Proxy</b> (mismo modelo JSON).")));
    ml->addStretch(0);
    advRoot->addWidget(wrapInScroll(pageMap));
    {
        auto* pageLibrary = new QWidget;
        setupLibraryTab(pageLibrary);
        mainTabWidget_->insertTab(3, wrapInScroll(pageLibrary), QStringLiteral("📁 Biblioteca"));
    }
    advancedTabWrap_ = wrapInScroll(pageAdv);
    mainTabWidget_->addTab(advancedTabWrap_, QStringLiteral("Avanzado"));
    mainTabWidget_->setTabVisible(mainTabWidget_->indexOf(advancedTabWrap_), false);

    statusBar()->show();
    characterStatusBarLbl_ = new QLabel(
        QStringLiteral("Personaje: — · Nivel: — · Clase: —"));
    characterStatusBarLbl_->setStyleSheet(QStringLiteral("color:#e5e5e5;padding:4px 8px;"));
    statusBar()->addPermanentWidget(characterStatusBarLbl_);

    connect(proxy_, &TcpMitmProxy::logLine, this, &MainWindow::appendProxyLog);
    // Importante: mismo hilo GUI que el proxy. Antes estábamos con DirectConnection → el slot se ejecutaba
    // antes de que TcpMitmProxy hiciera queueToClient_, retrasando S→C (p. ej. handoff CO→GA) hasta terminar el
    // análisis (varints/buildRecord/UI). Encola para entregar octets primero y analizar después.
    connect(proxy_, &TcpMitmProxy::protocolPayloadCaptured, this, &MainWindow::onProtocolPayloadCaptured,
            Qt::QueuedConnection);
    connect(proxy_, &TcpMitmProxy::tunnelReadyChanged, this, &MainWindow::updateTunnelStatus);

    appendProxyLog(QStringLiteral(
        "— Tráfico va a 127.0.0.1:5555 cuando la DLL intercepta connect/WSAConnect/ConnectEx al puerto 5555."));
    appendProxyLog(QStringLiteral("— Flechas: si hay último paquete C→S con type.ankama.com/iri, úsalo como base; "
                                   "si no, plantillas cruzadas del JSON."));

    connMonitorTimer_ = new QTimer(this);
    connMonitorTimer_->setInterval(1100);
    connect(connMonitorTimer_, &QTimer::timeout, this, &MainWindow::refreshConnectionMonitor);
    connMonitorTimer_->start();

    {
        QSettings s(QStringLiteral("fabia"), QStringLiteral("cpp_dofus_sniffer"));
        harvestWaitMs_ = s.value(QStringLiteral("harvestWaitMs"), 2000).toInt();
        harvestWaitMs_ = qBound(500, harvestWaitMs_, 10000);
        const bool massClose = s.value(QStringLiteral("massCloseOutboundTcpAfterInject"), false).toBool();
        if (massCloseOutboundTcpAfterInjectChk_ != nullptr) {
            massCloseOutboundTcpAfterInjectChk_->setChecked(massClose);
        }
        connect(massCloseOutboundTcpAfterInjectChk_, &QCheckBox::toggled, this, [](bool checked) {
            QSettings st(QStringLiteral("fabia"), QStringLiteral("cpp_dofus_sniffer"));
            st.setValue(QStringLiteral("massCloseOutboundTcpAfterInject"), checked);
        });
    }

    harvestWatchTimer_ = new QTimer(this);
    harvestWatchTimer_->setSingleShot(true);
    connect(harvestWatchTimer_, &QTimer::timeout, this, &MainWindow::onHarvestWaitTimeout);

    reloadIdDatabaseFromDisk();
    {
        QString err;
        if (!packetTypeOverrides_.load(&err) && !err.isEmpty()) {
            appendProxyLog(QStringLiteral("[TIPOS] %1").arg(err));
        }
    }
    reloadHarvestTemplateFromDisk();

#ifdef Q_OS_WIN
    pendingMonitorInjectTimer_ = new QTimer(this);
    pendingMonitorInjectTimer_->setSingleShot(true);
    connect(pendingMonitorInjectTimer_, &QTimer::timeout, this, &MainWindow::onPendingMonitorInjectTimeout);
#endif

    tryLoadDirectionMapFromField(/*logOk=*/false);
    refreshProcesses();
    syncProxyOptionsFromUi();
    updateProxyToolbarState();
    updateUpstreamQuickLabel();
}

QString MainWindow::appStyleSheet() const
{
    return QStringLiteral(
        "QMainWindow, QWidget { background: #171717; color: #e8e8e8; font-size:13px; } "
        "QToolBar { background: #141414; border-bottom: 1px solid #2e2e2e; spacing: 8px; padding: 4px 6px; } "
        "QTabWidget::pane { border: 1px solid #3a3a3a; border-radius: 4px; margin-top: 2px; top: -1px; } "
        "QTabBar::tab { background: #232323; color: #cfcfcf; padding: 9px 16px; margin-right: 2px; "
        "border: 1px solid #393939; border-bottom: none; border-top-left-radius: 5px; border-top-right-radius: 5px; } "
        "QTabBar::tab:selected { background: #262626; color: #f5f5f5; font-weight: bold; "
        "border-bottom: 1px solid #262626; } "
        "QTabBar::tab:hover:!selected { background: #2a2a2a; } "
        "QScrollArea { border: none; background: transparent; } "
        "QGroupBox { font-weight: bold; } "
        "QLineEdit, QTableWidget { background: #202020; color: #e8e8e8; "
        "border: 1px solid #393939; border-radius: 4px; padding: 4px; } "
        "QPlainTextEdit { background: #2d3238; color: #d4dce6; "
        "border: 1px solid #393939; border-radius: 4px; padding: 6px; "
        "font-family: Consolas, 'DejaVu Sans Mono', monospace; } "
        "QTreeWidget { background: #202020; color: #e8e8e8; border: 1px solid #393939; border-radius: 4px; } "
        "QComboBox { background: #202020; color: #e8e8e8; border: 1px solid #393939; border-radius: 4px; padding: 4px; } "
        "QPushButton { background: #343434; padding: 6px 14px; border-radius: 4px; border: 1px solid #494949; } "
        "QPushButton:hover { background: #3f3f3f; } "
        "QHeaderView::section { background: #2a2a2a; padding: 4px; border: none; "
        "border-bottom: 1px solid #404040; } "
        "QCheckBox { spacing: 8px; } "
        "QTableWidget::item:selected { background: #356b93; color: white; }");
}

QVector<ProcessEntry> MainWindow::collectDofusMatches() const
{
    QVector<ProcessEntry> hits;
    for (const ProcessEntry& e : allRows_) {
        if (processNameLooksLikeGameDofus(e.name)) {
            hits.push_back(e);
        }
    }
    return hits;
}

void MainWindow::refreshProcesses()
{
    allRows_ = enumerateRunningProcesses();

    auto matches = collectDofusMatches();
    if (matches.isEmpty()) {
        dofStatus_->setText(QStringLiteral(
            "<span style=\"color:#f59e0b\">No hay proceso con «Dofus». Abre el juego.</span>"));
    } else if (matches.size() == 1) {
        dofStatus_->setText(QStringLiteral("<span style=\"color:#4ade80\">Único proceso Dofus:</span> %1 (PID %2).")
                                .arg(matches[0].name)
                                .arg(matches[0].pid));
    } else {
        dofStatus_->setText(QStringLiteral("<span style=\"color:#fcd34d\">Varios procesos «Dofus»</span>; revisa "
                                           "la pestaña <b>Procesos</b>."));
    }

    applyTableFilter();

    if (autoSelectSingleCheckbox_->isChecked() && matches.size() == 1) {
        const int r = rowForPid(matches[0].pid);
        if (r >= 0) {
            procTable_->clearSelection();
            procTable_->selectRow(r);
        }
    }
}

int MainWindow::rowForPid(quint32 pid) const
{
    for (int r = 0; r < procTable_->rowCount(); ++r) {
        auto* cell = procTable_->item(r, 0);
        if (!cell) {
            continue;
        }
        bool ok = false;
        const quint32 p = cell->text().toUInt(&ok);
        if (ok && p == pid) {
            return r;
        }
    }
    return -1;
}

void MainWindow::applyTableFilter()
{
    const QString filt = nameFilterEdit_ ? nameFilterEdit_->text().trimmed() : QString();
    procTable_->setRowCount(0);

    for (const ProcessEntry& e : allRows_) {
        if (dofusOnlyCheckbox_->isChecked() && !processNameLooksLikeGameDofus(e.name)) {
            continue;
        }
        if (!substringFilterMatch(e.name, filt)) {
            continue;
        }
        const int row = procTable_->rowCount();
        procTable_->insertRow(row);
        procTable_->setItem(row, 0, new QTableWidgetItem(QString::number(e.pid)));
        procTable_->setItem(row, 1, new QTableWidgetItem(e.name));
    }
    procTable_->resizeColumnsToContents();
}

void MainWindow::appendProxyLog(const QString& line)
{
    const QString stamped =
        QDateTime::currentDateTime().toString(QStringLiteral("[yyyy-MM-dd HH:mm:ss.zzz] ")) + line;
    if (proxyLog_ != nullptr) {
        proxyLog_->appendPlainText(stamped);
        if (auto* sb = proxyLog_->verticalScrollBar()) {
            sb->setValue(sb->maximum());
        }
    }
    if (diagLogWin_ != nullptr) {
        diagLogWin_->appendLine(stamped);
    }
    if (line.contains(QStringLiteral("Sin respuesta del servidor en 30 s"), Qt::CaseInsensitive)
        && tunnelStatusLbl_ != nullptr) {
        tunnelStatusLbl_->setText(QStringLiteral(
            "<b>Estado:</b> <span style=\"color:#f87171;font-weight:bold\">Sin respuesta del upstream por 30 s</span>"
            "<br/><span style=\"color:#fcd34d\">Se cerró y reintentó automáticamente la conexión al servidor.</span>"));
    }
    appendToCentralFromUiLine(line);
}

void MainWindow::syncProxyOptionsFromUi()
{
    if (proxy_ == nullptr) {
        return;
    }
    proxy_->setFullTrafficLog(logTcpCheckbox_ != nullptr && logTcpCheckbox_->isChecked());
    proxy_->setVerboseDiagnostics(verboseProxyChk_ == nullptr || verboseProxyChk_->isChecked());
    proxy_->setFullDiagnosticMode(fullTunnelDiagChk_ != nullptr && fullTunnelDiagChk_->isChecked());
    proxy_->setRawTcpForwarderMode(rawForwarderChk_ != nullptr && rawForwarderChk_->isChecked());
    proxy_->setDrainQueueLogging(drainQueueLogChk_ != nullptr && drainQueueLogChk_->isChecked());
    proxy_->setUpstreamConnectTimeoutMs(60000);
    proxy_->setTransparentMode(transparentProxyChk_ != nullptr && transparentProxyChk_->isChecked());
    proxy_->setEchoMode(echoProxyChk_ != nullptr && echoProxyChk_->isChecked());
    proxy_->setHandshakeCaptureEnabled(captureHandshakeChk_ != nullptr && captureHandshakeChk_->isChecked());
    proxy_->setListenIpv6(listenIpv6Chk_ == nullptr || listenIpv6Chk_->isChecked());
    proxy_->setTrafficLogging(logTcpCheckbox_ != nullptr && logTcpCheckbox_->isChecked(), 128);
}

void MainWindow::onTestProxyClicked()
{
    auto* sock = new QTcpSocket(this);
    auto* timer = new QTimer(this);
    timer->setSingleShot(true);

    auto cleanup = [sock, timer]() {
        if (sock != nullptr) {
            sock->deleteLater();
        }
        if (timer != nullptr) {
            timer->deleteLater();
        }
    };

    connect(timer, &QTimer::timeout, this, [this, sock, timer]() {
        if (sock->state() == QAbstractSocket::ConnectedState && sock->bytesAvailable() == 0) {
            appendProxyLog(QStringLiteral(
                "[TEST] Timeout (~15 s): conexión abierta pero sin bytes de respuesta (¿upstream colgado o juego "
                "esperando más datos?)."));
        } else if (sock->state() != QAbstractSocket::ConnectedState) {
            appendProxyLog(QStringLiteral("[TEST] Timeout sin llegar a conexión estable."));
        }
        sock->disconnect();
        sock->deleteLater();
        timer->deleteLater();
    });

    connect(sock, &QTcpSocket::connected, this, [this, sock]() {
        appendProxyLog(QStringLiteral("[TEST] Conectado a 127.0.0.1:%1 — enviando «HOLA»…")
                             .arg(kLocalProxyMustPort));
        sock->write(QStringLiteral("HOLA").toUtf8());
    });
    connect(sock, &QTcpSocket::readyRead, this, [this, sock, timer]() {
        const QByteArray r = sock->readAll();
        appendProxyLog(QStringLiteral("[TEST] Recibidos %1 bytes · hex: %2")
                             .arg(r.size())
                             .arg(QString::fromLatin1(r.toHex())));
        appendProxyLog(QStringLiteral("[TEST] OK: respuesta TCP desde 127.0.0.1:%1 (modo ECHO debería devolver «HOLA»).")
                             .arg(kLocalProxyMustPort));
        timer->stop();
        sock->deleteLater();
        timer->deleteLater();
    });
    connect(sock, &QAbstractSocket::errorOccurred, this, [this, sock, timer](QAbstractSocket::SocketError) {
        appendProxyLog(QStringLiteral("[TEST] Error: ") + sock->errorString());
        timer->stop();
        sock->deleteLater();
        timer->deleteLater();
    });

    timer->start(15000);
    sock->connectToHost(QHostAddress::LocalHost, kLocalProxyMustPort);
}

void MainWindow::runUpstreamTcpProbe(const QString& host, quint16 port)
{
    auto* sock = new QTcpSocket(this);
    auto* timer = new QTimer(this);
    timer->setSingleShot(true);

    connect(timer, &QTimer::timeout, this, [this, sock, timer, host, port]() {
        if (sock->state() == QAbstractSocket::ConnectedState && sock->bytesAvailable() == 0) {
            appendProxyLog(QStringLiteral(
                "[PRUEBA UPSTREAM] TCP conectado a %1:%2 pero sin datos en 8 s (handshake del juego puede ser otro).")
                               .arg(host)
                               .arg(port));
        } else if (sock->state() != QAbstractSocket::ConnectedState) {
            appendProxyLog(QStringLiteral("[PRUEBA UPSTREAM] Timeout TCP a %1:%2.").arg(host).arg(port));
        }
        sock->disconnectFromHost();
        sock->deleteLater();
        timer->deleteLater();
    });

    connect(sock, &QTcpSocket::connected, this, [this, sock, host, port]() {
        static const QByteArray kProbe = QByteArrayLiteral("DOFUS_PROXY_UPSTREAM_TEST\r\n");
        appendProxyLog(QStringLiteral("[PRUEBA UPSTREAM] TCP conectado a %1:%2 · probe %3 B…")
                           .arg(host)
                           .arg(port)
                           .arg(kProbe.size()));
        sock->write(kProbe);
    });

    connect(sock, &QTcpSocket::readyRead, this, [this, sock, timer, host, port]() {
        const QByteArray r = sock->readAll();
        appendProxyLog(QStringLiteral("[PRUEBA UPSTREAM] Respuesta %1:%2 · %3 B · hex (primeros %4): %5")
                           .arg(host)
                           .arg(port)
                           .arg(r.size())
                           .arg(qMin(64, r.size()))
                           .arg(QString::fromLatin1(r.left(64).toHex())));
        timer->stop();
        sock->disconnectFromHost();
        sock->deleteLater();
        timer->deleteLater();
    });

    connect(sock, &QAbstractSocket::errorOccurred, this, [this, sock, timer, host, port](QAbstractSocket::SocketError) {
        appendProxyLog(QStringLiteral("[PRUEBA UPSTREAM] TCP error %1:%2 — %3")
                           .arg(host)
                           .arg(port)
                           .arg(sock->errorString()));
        timer->stop();
        sock->deleteLater();
        timer->deleteLater();
    });

    appendProxyLog(QStringLiteral("[PRUEBA UPSTREAM] TCP → %1:%2 (dirección literal, sin DNS)…").arg(host).arg(port));
    timer->start(8000);
    sock->connectToHost(QHostAddress(host), port);
}

void MainWindow::onTestUpstreamClicked()
{
    const QString host = upstreamHost_ != nullptr ? upstreamHost_->text().trimmed() : QString();
    bool okPort = false;
    const quint16 port =
        upstreamPort_ != nullptr ? upstreamPort_->text().toUShort(&okPort) : static_cast<quint16>(0);
    const QHostAddress addr(host);
    if (addr.isNull() || !okPort || port == 0) {
        QMessageBox::warning(this, QStringLiteral("Modo prueba upstream"),
                             QStringLiteral("Indica IP literal IPv4/IPv6 y puerto > 0 en los campos del servidor real."));
        return;
    }

    appendProxyLog(QStringLiteral("[PRUEBA UPSTREAM] Ping ICMP → %1 …").arg(host));

#ifdef Q_OS_WIN
    auto* pingProc = new QProcess(this);
    connect(pingProc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this, pingProc, host, port](int exitCode, QProcess::ExitStatus) {
                const QString out = QString::fromLocal8Bit(pingProc->readAllStandardOutput()).trimmed();
                const QString err = QString::fromLocal8Bit(pingProc->readAllStandardError()).trimmed();
                if (!out.isEmpty()) {
                    appendProxyLog(QStringLiteral("[PRUEBA UPSTREAM] Salida ping:\n") + out);
                }
                if (!err.isEmpty()) {
                    appendProxyLog(QStringLiteral("[PRUEBA UPSTREAM] stderr ping:\n") + err);
                }
                appendProxyLog(QStringLiteral("[PRUEBA UPSTREAM] Ping terminó (código %1). Siguiente: TCP…")
                                   .arg(exitCode));
                pingProc->deleteLater();
                runUpstreamTcpProbe(host, port);
            });
    pingProc->start(QStringLiteral("ping"),
                    QStringList{QStringLiteral("-n"), QStringLiteral("1"), QStringLiteral("-w"),
                                QStringLiteral("4000"), host});
    if (!pingProc->waitForStarted(3000)) {
        appendProxyLog(QStringLiteral("[PRUEBA UPSTREAM] No se pudo iniciar ping; solo TCP…"));
        pingProc->deleteLater();
        runUpstreamTcpProbe(host, port);
    }
#else
    runUpstreamTcpProbe(host, port);
#endif
}

void MainWindow::openDiagnosticsLogWindow()
{
    if (diagLogWin_ == nullptr) {
        diagLogWin_ = new DiagnosticsLogWindow(this);
        diagLogWin_->setWindowFlags(Qt::Window | Qt::WindowMinimizeButtonHint | Qt::WindowMaximizeButtonHint
                                    | Qt::WindowCloseButtonHint);
        if (proxyLog_ != nullptr && !proxyLog_->toPlainText().isEmpty()) {
            diagLogWin_->appendLine(QStringLiteral("=== Copia del registro ya mostrado en «Registro» ==="));
            diagLogWin_->appendLine(proxyLog_->toPlainText());
            diagLogWin_->appendLine(QStringLiteral("=== A partir de aquí, líneas nuevas en tiempo real ==="));
        }
    }
    diagLogWin_->show();
    diagLogWin_->raise();
    diagLogWin_->activateWindow();
}

void MainWindow::reloadDirectionMapClicked()
{
    tryLoadDirectionMapFromField(true);
}

void MainWindow::tryLoadDirectionMapFromField(bool logOk)
{
    const QString path = dirMapJsonPath_->text().trimmed();
    if (path.isEmpty()) {
        mapModelSummaryLbl_->setText(QStringLiteral("Indica direcciones_map.json"));
        if (logOk) {
            QMessageBox::information(this, QStringLiteral("Modelo"),
                                     QStringLiteral("Escribe la ruta al JSON."));
        }
        return;
    }

    QString err;
    if (!iriEmu_.loadFromFile(path, &err)) {
        mapModelSummaryLbl_->setText(QStringLiteral("Error: ") + err);
        if (logOk) {
            QMessageBox::warning(this, QStringLiteral("direcciones_map.json"), err);
        }
        return;
    }

    const DirectionMapModel* m = iriEmu_.model();
    if (m != nullptr) {
        QStringList templateDiag;
        for (auto it = m->plantillasPorCardinal.constBegin(); it != m->plantillasPorCardinal.constEnd(); ++it) {
            const IriPacketAnalysis ta = analyzeIriPayload(it.value(), m);
            if (!ta.overallAcceptableForInjection()) {
                const QString bits = ta.errors.isEmpty()
                    ? ta.warnings.join(QLatin1String("; "))
                    : ta.errors.join(QLatin1String("; "));
                templateDiag << QStringLiteral("%1: %2").arg(it.key(), bits);
            }
        }
        QString extraDiag;
        if (!templateDiag.isEmpty()) {
            extraDiag = QStringLiteral("\n\n⚠ Validación ☆iri: ") + templateDiag.join(QLatin1String(" | "));
        }
        mapModelSummaryLbl_->setText(QStringLiteral(
            "OK — plantillas ☆iri: %1 · offset JSON: %2 · tipo: %3\n%4%5")
                                        .arg(m->plantillasPorCardinal.size())
                                        .arg(m->offset)
                                        .arg(m->tipo)
                                        .arg(QDir::toNativeSeparators(iriEmu_.loadedPath_))
                                        .arg(extraDiag));
        if (logOk) {
            appendProxyLog(QStringLiteral("[MOV] Modelo cargado: ") + iriEmu_.loadedPath_);
        }
    }
    refreshIriDiagnostics();
}

void MainWindow::updateTunnelStatus(bool tunnelReadyWithClient)
{
    const bool was = tunnelReady_;
    tunnelReady_ = tunnelReadyWithClient;
    if (was != tunnelReady_) {
        appendProxyLog(QStringLiteral("[PROXY] %1")
                             .arg(tunnelReady_
                                      ? QStringLiteral("listo (cliente local y upstream enlazados)")
                                      : QStringLiteral("no listo (esperando cliente o upstream / sesión reiniciada)")));
    }

    if (reconnectHintLbl_ != nullptr) {
        reconnectHintLbl_->setVisible(proxyRunning_ && !tunnelReady_);
    }

    if (tunnelReady_) {
        tunnelStatusLbl_->setText(QStringLiteral(
            "<b>Estado:</b> <span style=\"color:#4ade80;font-weight:bold\">Túnel listo — podés usar N/S/E/O si el modelo "
            "☆iri está cargado.</span>"));
    } else if (proxyRunning_) {
        tunnelStatusLbl_->setText(QStringLiteral(
            "<b>Estado:</b> <span style=\"color:#fbbf24;font-weight:bold\">Esperando cliente en el proxy…"
            "</span><br/><span style=\"color:#cbd5e1\">Listener <b>127.0.0.1:%1</b> · ¿DLL inyectada y "
            "<code>connect</code> hacia :5555?</span>")
            .arg(QString::number(kLocalProxyMustPort)));
    } else {
    tunnelReady_ = false;
    tunnelStatusLbl_->setText(QStringLiteral(
            "<b>Estado:</b> <span style=\"color:#9ca3af\">Sin proxy.</span> Pulsa «Iniciar proxy»."));
    }
    refreshMovementButtonsEnabled();
}

void MainWindow::applyCardinal(const QString& cardinalEs)
{
    if (iriEmu_.model() == nullptr) {
        QMessageBox::warning(this, QStringLiteral("Modelo"),
                             QStringLiteral("Carga direcciones_map.json primero."));
        return;
    }
    if (transparentProxyChk_ != nullptr && transparentProxyChk_->isChecked()) {
        QMessageBox::information(
            this,
            QStringLiteral("Modo transparente"),
            QStringLiteral("Desactiva «Modo transparente» para inyectar plantillas de movimiento manualmente."));
        return;
    }

    const DirectionMapModel* mdl = iriEmu_.model();
    QByteArray base;
    QString srcDesc;

    const QByteArray live = proxy_->lastOutboundFromClient();
    if (mdl != nullptr && !live.isEmpty() && payloadHasAnkamaIri(live)
        && live.size() > qMax(0, mdl->offset)) {
        base = live;
        srcDesc = QStringLiteral("último TCP C→S con ☆iri");
    } else if (!iriEmu_.pickCrossBase(cardinalEs, &base, &srcDesc)) {
        QMessageBox::information(
            this,
            QStringLiteral("Plantillas ☆iri"),
            QStringLiteral("No hay suficientes ejemplos_hex en JSON (ni tráfico C→S con iri vivo). Cardinal pedido: %1")
                .arg(cardinalEs));
        return;
    }

    QByteArray patched;
    QString dbg;
    if (!iriEmu_.patchTowardCardinal(base, cardinalEs, &patched, &dbg)) {
        QMessageBox::information(this, QStringLiteral("Parche"), dbg.isEmpty() ? QStringLiteral("Sin cambio.") : dbg);
        return;
    }

    const QByteArray liveRef = proxy_->lastOutboundFromClient();
    const QString preErr = movementInjectionPrecheck(patched, liveRef);
    if (!preErr.isEmpty()) {
        QMessageBox::warning(
            this,
            QStringLiteral("Movimiento · validación"),
            QStringLiteral("No se envía el paquete.\n\n%1").arg(preErr));
        appendProxyLog(QStringLiteral("[MOV] Bloqueado por validación: ") + preErr);
        return;
    }

    const QString injectErr = proxy_->injectTowardServer(patched);
    if (!injectErr.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Inyección TCP"), injectErr);
        appendProxyLog(QStringLiteral("[MOV] ") + dbg);
        return;
    }

    appendProxyLog(QStringLiteral("[MOV] %1 · base=(%2) · %3").arg(cardinalEs, srcDesc, dbg));
}

QString MainWindow::movementInjectionPrecheck(const QByteArray& patched, const QByteArray& liveOptional) const
{
    const DirectionMapModel* mdl = iriEmu_.model();
    const IriPacketAnalysis pa = analyzeIriPayload(patched, mdl);
    if (patched.size() <= 50) {
        return QStringLiteral("El paquete tiene %1 B; se requiere tamaño > 50 B.").arg(patched.size());
    }
    if (!pa.validStrictUrl) {
        return pa.errors.isEmpty() ? QStringLiteral("Falta type.ankama.com/iri o hay URL de otro mensaje.")
                                   : pa.errors.join(QLatin1Char('\n'));
    }
    if (!pa.routeLengthOk) {
        return QStringLiteral(
                   "Ruta demasiado corta (~%1 B desde el índice 22). Suele provocar «invalid route» en el servidor.")
            .arg(pa.routeByteCount);
    }
    if (!pa.payloadSizeOk) {
        return QStringLiteral("Tamaño %1 B fuera del rango heurístico 50–70 B.").arg(pa.payloadSize);
    }
    if (!liveOptional.isEmpty() && payloadHasAnkamaIri(liveOptional)) {
        const IriPacketAnalysis liv = analyzeIriPayload(liveOptional, nullptr);
        if (liv.sessionToken5.size() == 5 && pa.sessionToken5.size() == 5
            && liv.sessionToken5 != pa.sessionToken5) {
            return QStringLiteral(
                "Token de sesión distinto al último paquete ☆iri capturado (C→S). Muévete con teclado o actualiza "
                "plantillas desde un log de esta sesión.");
        }
    }
    return {};
}

bool MainWindow::packetKindIsClientMapTransitMacro(PacketKind k) const
{
    switch (k) {
    case PacketKind::ItrMapTransitClient:
    case PacketKind::ItoMapTransitClient:
    case PacketKind::MapHopJnrIspClient:
        return true;
    default:
        return false;
    }
}

QString MainWindow::defaultMapTransitMacroPath() const
{
    return QDir(QCoreApplication::applicationDirPath())
        .absoluteFilePath(QStringLiteral("map_transition_macro.json"));
}

void MainWindow::saveMapTransitMacroFromSelection()
{
    if (protocolLogTree_ == nullptr) {
        return;
    }
    const QList<QTreeWidgetItem*> sel = protocolLogTree_->selectedItems();
    if (sel.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Macro cambio de mapa"),
                                 QStringLiteral("Selecciona uno o más paquetes en Logs (Ctrl+clic)."));
        return;
    }
    QVector<int> vix;
    vix.reserve(sel.size());
    for (QTreeWidgetItem* it : sel) {
        const int ix = it->data(0, kProtoVecRole).toInt();
        if (ix >= 0 && ix < protocolRecords_.size()) {
            vix.push_back(ix);
        }
    }
    std::sort(vix.begin(), vix.end());

    QJsonArray steps;
    QStringList skipped;
    for (int ix : vix) {
        const ProtocolPacketRecord& r = protocolRecords_.at(ix);
        if (!r.fromClient) {
            skipped << QStringLiteral("#%1 (S→C omitido)").arg(r.index);
            continue;
        }
        if (!packetKindIsClientMapTransitMacro(r.kind)) {
            skipped << QStringLiteral("#%1 %2").arg(r.index).arg(r.kindLabel);
            continue;
        }
        QJsonObject o;
        o[QStringLiteral("packetIndex")] = r.index;
        o[QStringLiteral("kind")] = packetKindDisplayString(r.kind);
        o[QStringLiteral("payloadBase64")] = QLatin1String(r.rawPayload.toBase64());
        steps.append(o);
    }
    if (steps.isEmpty()) {
        QMessageBox::warning(
            this,
            QStringLiteral("Macro cambio de mapa"),
            QStringLiteral("No quedaron pasos válidos.\nSelecciona solo paquetes <b>cliente→servidor</b> clasificados "
                           "como <b>ITR</b>, <b>ITO</b> o <b>PASO MAPA (JNR+ISP)</b>.\n\nOmitidos:\n• ")
                + skipped.join(QStringLiteral("\n• ")));
        return;
    }
    const QString defaultPath = defaultMapTransitMacroPath();
    const QString path =
        QFileDialog::getSaveFileName(this,
                                     QStringLiteral("Guardar macro cambio de mapa"),
                                     defaultPath,
                                     QStringLiteral("JSON (*.json);;Todos (*.*)"));
    if (path.isEmpty()) {
        return;
    }
    const int delayMs = mapTransitMacroDelaySpin_ != nullptr ? mapTransitMacroDelaySpin_->value() : 250;
    QJsonObject root;
    root[QStringLiteral("version")] = 1;
    root[QStringLiteral("savedAt")] = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    root[QStringLiteral("delayMsBetweenSteps")] = delayMs;
    root[QStringLiteral("steps")] = steps;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::warning(this, QStringLiteral("Macro cambio de mapa"),
                             QStringLiteral("No se pudo escribir:\n%1").arg(path));
        return;
    }
    f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    f.close();

    QString msg = QStringLiteral("Guardados %1 paso(s).").arg(steps.size());
    if (!skipped.isEmpty()) {
        msg += QStringLiteral("\n\nFilas omitidas:\n• ") + skipped.join(QStringLiteral("\n• "));
    }
    QMessageBox::information(this, QStringLiteral("Macro cambio de mapa"), msg);
    appendProxyLog(QStringLiteral("[MAP-MACRO] Guardado JSON: %1 (%2 pasos).")
                         .arg(QDir::toNativeSeparators(path))
                         .arg(steps.size()));
    statusBar()->showMessage(QStringLiteral("Macro mapa guardada: %1").arg(QDir::toNativeSeparators(path)), 5000);
}

void MainWindow::replayMapTransitMacroFromDialog()
{
    if (mapMacroReplayActive_) {
        QMessageBox::information(this, QStringLiteral("Macro cambio de mapa"),
                                 QStringLiteral("Ya hay una reproducción en curso."));
        return;
    }
    if (transparentProxyChk_ != nullptr && transparentProxyChk_->isChecked()) {
        QMessageBox::information(
            this,
            QStringLiteral("Modo transparente"),
            QStringLiteral("Desactivá «Modo transparente» para inyectar la macro."));
        return;
    }
    if (proxy_ == nullptr) {
        return;
    }

    const QString path =
        QFileDialog::getOpenFileName(this,
                                     QStringLiteral("Reproducir macro cambio de mapa"),
                                     defaultMapTransitMacroPath(),
                                     QStringLiteral("JSON (*.json);;Todos (*.*)"));
    if (path.isEmpty()) {
        return;
    }
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, QStringLiteral("Macro cambio de mapa"),
                             QStringLiteral("No se pudo abrir:\n%1").arg(path));
        return;
    }
    QJsonParseError jerr{};
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &jerr);
    f.close();
    if (!doc.isObject()) {
        QMessageBox::warning(
            this,
            QStringLiteral("Macro cambio de mapa"),
            QStringLiteral("JSON inválido (%1 línea %2).").arg(jerr.errorString()).arg(jerr.offset));
        return;
    }
    const QJsonObject root = doc.object();
    int delayMs = mapTransitMacroDelaySpin_ != nullptr ? mapTransitMacroDelaySpin_->value() : 250;
    if (root.contains(QStringLiteral("delayMsBetweenSteps"))) {
        delayMs = root.value(QStringLiteral("delayMsBetweenSteps")).toInt(delayMs);
    }
    QVector<QByteArray> queue;
    const QJsonArray arr = root.value(QStringLiteral("steps")).toArray();
    for (const QJsonValue& v : arr) {
        if (!v.isObject()) {
            continue;
        }
        const QByteArray pl = QByteArray::fromBase64(v.toObject().value(QStringLiteral("payloadBase64")).toString().toLatin1());
        if (!pl.isEmpty()) {
            queue.push_back(pl);
        }
    }
    if (queue.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Macro cambio de mapa"),
                             QStringLiteral("El archivo no tiene «steps» con payloadBase64 válido."));
        return;
    }

    mapMacroReplayQueue_ = std::move(queue);
    mapMacroReplayNextIndex_ = 0;
    mapMacroReplayDelayMs_ = qBound(0, delayMs, 60000);
    mapMacroReplayActive_ = true;
    refreshMovementButtonsEnabled();
    appendProxyLog(QStringLiteral("[MAP-MACRO] Reproducir desde %1 — %2 pasos, pausa %3 ms.")
                         .arg(QDir::toNativeSeparators(path))
                         .arg(mapMacroReplayQueue_.size())
                         .arg(mapMacroReplayDelayMs_));
    continueMapMacroReplayChain();
}

void MainWindow::continueMapMacroReplayChain()
{
    if (!mapMacroReplayActive_) {
        return;
    }
    if (mapMacroReplayNextIndex_ >= mapMacroReplayQueue_.size()) {
        mapMacroReplayActive_ = false;
        appendProxyLog(QStringLiteral("[MAP-MACRO] Fin (%1 pasos).").arg(mapMacroReplayQueue_.size()));
        refreshMovementButtonsEnabled();
        statusBar()->showMessage(QStringLiteral("Macro cambio de mapa: reproducción terminada."), 4000);
        return;
    }
    const QByteArray pl = mapMacroReplayQueue_.at(mapMacroReplayNextIndex_);
    const int stepNo = mapMacroReplayNextIndex_ + 1;
    ++mapMacroReplayNextIndex_;
    const QString err = proxy_->injectTowardServer(pl);
    if (!err.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Macro cambio de mapa"),
                             QStringLiteral("Paso %1/%2 — no se envió:\n\n%3")
                                 .arg(stepNo)
                                 .arg(mapMacroReplayQueue_.size())
                                 .arg(err));
        mapMacroReplayActive_ = false;
        refreshMovementButtonsEnabled();
        return;
    }
    appendProxyLog(QStringLiteral("[MAP-MACRO] Paso %1/%2 (%3 B)")
                       .arg(stepNo)
                       .arg(mapMacroReplayQueue_.size())
                       .arg(pl.size()));
    QTimer::singleShot(mapMacroReplayDelayMs_, this, &MainWindow::continueMapMacroReplayChain);
}

void MainWindow::refreshIriDiagnostics()
{
    if (iriTokenStatusLbl_ == nullptr || iriTemplateCheckLbl_ == nullptr || proxy_ == nullptr) {
        return;
    }
    const QByteArray live = proxy_->lastOutboundFromClient();
    if (live.isEmpty()) {
        iriTokenStatusLbl_->setText(QStringLiteral("Último C→S al proxy: vacío (aún no hay tráfico)."));
        iriTemplateCheckLbl_->setText(QStringLiteral("Plantillas vs sesión: —"));
        return;
    }

    const IriPacketAnalysis liveA = analyzeIriPayload(live, iriEmu_.model());
    if (!payloadHasAnkamaIri(live)) {
        iriTokenStatusLbl_->setText(QStringLiteral(
            "Último C→S: %1 B — sin marca ☆iri (no es movimiento de mapa).").arg(live.size()));
    } else {
        const QString tok = liveA.sessionToken5.size() == 5
            ? formatSessionTokenHex(liveA.sessionToken5)
            : QStringLiteral("(no extraído)");
        const QString warnExtra =
            (!liveA.errors.isEmpty() || !liveA.warnings.isEmpty())
                ? QStringLiteral(" · ⚠ ")
                      + (liveA.errors.isEmpty() ? liveA.warnings.join(QLatin1Char(' ')) : liveA.errors.join(QLatin1Char(' ')))
                : QString();
        iriTokenStatusLbl_->setText(QStringLiteral("☆iri reciente: token %1 · %2 B payload · ruta ~%3 B%4")
                                        .arg(tok)
                                        .arg(liveA.payloadSize)
                                        .arg(liveA.routeByteCount)
                                        .arg(warnExtra));
    }

    const DirectionMapModel* m = iriEmu_.model();
    QStringList issues;
    if (m != nullptr) {
        if (payloadHasAnkamaIri(live) && liveA.sessionToken5.size() == 5) {
            for (auto it = m->plantillasPorCardinal.constBegin(); it != m->plantillasPorCardinal.constEnd(); ++it) {
                const IriPacketAnalysis ta = analyzeIriPayload(it.value(), m);
                if (!ta.overallAcceptableForInjection()) {
                    issues << QStringLiteral("%1 inválida").arg(it.key());
                } else if (ta.sessionToken5.size() == 5 && ta.sessionToken5 != liveA.sessionToken5) {
                    issues << QStringLiteral("%1: token ≠ sesión actual").arg(it.key());
                }
            }
        } else if (!m->plantillasPorCardinal.isEmpty()) {
            issues << QStringLiteral("Sin ☆iri en último C→S; no se puede comparar token.");
        }
    }
    if (issues.isEmpty()) {
        iriTemplateCheckLbl_->setStyleSheet(QStringLiteral("color:#86efac;"));
        iriTemplateCheckLbl_->setText(QStringLiteral("Plantillas vs sesión: sin conflictos detectados."));
    } else {
        iriTemplateCheckLbl_->setStyleSheet(QStringLiteral("color:#fca5a5;"));
        iriTemplateCheckLbl_->setText(QStringLiteral("⚠ %1").arg(issues.join(QLatin1String(" · "))));
    }
}

void MainWindow::onImportMovementLogClicked()
{
    QString startDir = QFileInfo(dirMapJsonPath_->text().trimmed()).absolutePath();
    const QString exportGuess = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("exportados"));
    if (QFileInfo::exists(exportGuess)) {
        startDir = QFileInfo(exportGuess).canonicalFilePath();
    }
    const QString path = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("Importar log de movimiento"),
        startDir,
        QStringLiteral("Texto (*.txt);;Todos (*.*)"));
    if (path.isEmpty()) {
        return;
    }

    QByteArray raw;
    int pktNum = -1;
    IriPacketAnalysis a;
    QString err;
    if (!findFirstValidIriInExportLog(path, &raw, &pktNum, &a, &err)) {
        QMessageBox::warning(this, QStringLiteral("Importar"), err);
        return;
    }
    if (iriEmu_.model() != nullptr) {
        a = analyzeIriPayload(raw, iriEmu_.model());
    }

    const QString pktStr = pktNum >= 0 ? QString::number(pktNum) : QStringLiteral("?");
    const QString summary =
        QStringLiteral("Paquete #%1\n"
                       "· Tamaño: %2 B\n"
                       "· Token (ofs 17): %3\n"
                       "· Bytes de ruta (desde índice 22): %4\n"
                       "· Cardinal inferido (JSON): %5\n")
            .arg(pktStr,
                 QString::number(a.payloadSize),
                 formatSessionTokenHex(a.sessionToken5),
                 QString::number(a.routeByteCount),
                 a.inferredCardinal.isEmpty() ? QStringLiteral("—") : a.inferredCardinal);

    QMessageBox::information(this, QStringLiteral("IRI válido en log"), summary);

    const QStringList items{QStringLiteral("Norte"), QStringLiteral("Sur"), QStringLiteral("Este"),
                            QStringLiteral("Oeste")};
    bool okPick = false;
    const QString cardinal =
        QInputDialog::getItem(this,
                              QStringLiteral("Guardar plantilla"),
                              QStringLiteral("Cardinal para esta plantilla:"),
                              items,
                              1,
                              false,
                              &okPick);
    if (!okPick) {
        return;
    }

    const QString dmPath = dirMapJsonPath_->text().trimmed();
    if (!dmPath.isEmpty()) {
        const auto ans = QMessageBox::question(
            this,
            QStringLiteral("Fusionar en direcciones_map.json"),
            QStringLiteral("¿Añadir / sustituir ejemplos_hex[\"%1\"] en:\n%2")
                .arg(cardinal, QDir::toNativeSeparators(dmPath)),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::Yes);
        if (ans == QMessageBox::Yes) {
            QString mergeErr;
            if (!mergeEjemploHexIntoDirectionMapJson(dmPath, cardinal, raw, &mergeErr)) {
                QMessageBox::warning(this, QStringLiteral("direcciones_map.json"), mergeErr);
            } else {
                appendProxyLog(QStringLiteral("[MOV] Fusionado ejemplo_hex para %1 en JSON del mapa.").arg(cardinal));
                tryLoadDirectionMapFromField(true);
            }
        }
    }

    QString sideErr;
    if (dmPath.isEmpty()) {
        QMessageBox::information(
            this,
            QStringLiteral("templates.json"),
            QStringLiteral("Indica la ruta a direcciones_map.json arriba para poder guardar templates.json junto a él."));
    } else if (!saveTemplatesJsonSidecar(dmPath, cardinal, raw, a, path, &sideErr)) {
        QMessageBox::warning(this, QStringLiteral("templates.json"), sideErr);
    } else {
        appendProxyLog(QStringLiteral("[MOV] Copia en templates.json (%1).").arg(cardinal));
    }
}

void MainWindow::syncUpstreamFromUiToProxy()
{
    bool okPort = false;
    quint16 upPort = upstreamPort_ != nullptr ? upstreamPort_->text().toUShort(&okPort) : static_cast<quint16>(0);
    if (!okPort || upPort == 0) {
        upPort = kUpstreamDefaultPort;
    }
    const QString host = upstreamHost_ != nullptr ? upstreamHost_->text().trimmed() : QString();
    const QHostAddress up(host);
    if (!up.isNull()
        && (up.protocol() == QHostAddress::IPv4Protocol || up.protocol() == QHostAddress::IPv6Protocol)) {
        proxy_->setRemoteEndpoint(host, upPort);
    } else {
        proxy_->setRemoteEndpoint(QString(), 0);
    }
}

void MainWindow::ensureUpstreamRealIpFromUi()
{
    syncUpstreamFromUiToProxy();
    if (!proxy_->upstreamTargetConfigured()) {
        appendProxyLog(QStringLiteral(
            "[PROXY] Upstream manual vacío/no válido: se intentará auto-detección (log DLL primero; "
            "fallback de archivo solo si es reciente)."));
    }
    updateUpstreamQuickLabel();
}

void MainWindow::saveUpstreamIpToSharedFile()
{
    const QString host = upstreamHost_ != nullptr ? upstreamHost_->text().trimmed() : QString();
    const QHostAddress addr(host);
    if (addr.isNull()
        || (addr.protocol() != QHostAddress::IPv4Protocol && addr.protocol() != QHostAddress::IPv6Protocol)) {
        return;
    }
    QFile f(QStringLiteral("C:/dofus_upstream_ip.txt"));
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        appendProxyLog(QStringLiteral("[PROXY] No se pudo escribir C:\\dofus_upstream_ip.txt"));
        return;
    }
    f.write(host.toUtf8());
    f.close();
    appendProxyLog(QStringLiteral("[PROXY] Guardado C:\\dofus_upstream_ip.txt para próximos arranques / DLL."));
}

void MainWindow::updateProxyToolbarState()
{
    if (startProxySoloBtn_ != nullptr) {
        startProxySoloBtn_->setEnabled(!proxyRunning_);
    }
    if (stopProxyBtn_ != nullptr) {
        stopProxyBtn_->setEnabled(proxyRunning_);
    }
    if (startAllBtn_ != nullptr) {
        startAllBtn_->setEnabled(!proxyRunning_);
    }
#ifdef Q_OS_WIN
    const bool monRunning = (processMonitor_ != nullptr && processMonitor_->isRunning());
#else
    const bool monRunning = false;
#endif
    if (stopAllBtn_ != nullptr) {
        stopAllBtn_->setEnabled(proxyRunning_ || monRunning);
    }
#ifdef Q_OS_WIN
    if (startProxyWithDllBtn_ != nullptr) {
        startProxyWithDllBtn_->setEnabled(!proxyRunning_);
    }
#endif
    refreshMovementButtonsEnabled();
}

void MainWindow::refreshMovementButtonsEnabled()
{
    const bool echo = echoProxyChk_ != nullptr && echoProxyChk_->isChecked();
    const bool minimal = minimalProxyChk_ != nullptr && minimalProxyChk_->isChecked();
    const bool proxyOk =
        proxyRunning_ && tunnelReady_ && proxy_ != nullptr && !echo && !minimal;
    if (arrowN_btn_ != nullptr) {
        arrowN_btn_->setEnabled(proxyOk);
        arrowS_btn_->setEnabled(proxyOk);
        arrowE_btn_->setEnabled(proxyOk);
        arrowO_btn_->setEnabled(proxyOk);
    }
    const bool transparent =
        transparentProxyChk_ != nullptr && transparentProxyChk_->isChecked();
    const bool harvestOk = proxyOk && !transparent;
    if (recolectHarvestBtn_ != nullptr) {
        recolectHarvestBtn_->setEnabled(harvestOk);
    }
    if (replayMapTransitMacroBtn_ != nullptr) {
        replayMapTransitMacroBtn_->setEnabled(harvestOk && !mapMacroReplayActive_);
    }
}

void MainWindow::updateUpstreamQuickLabel()
{
    if (upstreamQuickLbl_ == nullptr) {
        return;
    }
    if (proxy_ != nullptr && proxyRunning_ && proxy_->upstreamTargetConfigured()) {
        upstreamQuickLbl_->setText(
            QStringLiteral("Upstream: %1:%2 (detectado)")
                .arg(proxy_->remoteHostString())
                .arg(proxy_->remotePortValue()));
        upstreamQuickLbl_->setStyleSheet(QStringLiteral("color:#4ade80;font-size:12px;"));
        return;
    }
    upstreamQuickLbl_->setText(QStringLiteral("Upstream: [Detectando...]  Estado: Esperando conexión"));
    upstreamQuickLbl_->setStyleSheet(QStringLiteral("color:#fbbf24;font-size:12px;"));
}

void MainWindow::onStartProxySoloClicked()
{
    if (proxyRunning_) {
        return;
    }

    syncProxyOptionsFromUi();
    proxy_->setTrafficLogging(logTcpCheckbox_->isChecked(), 128);
    ensureUpstreamRealIpFromUi();
    proxy_->stop();
    proxy_->setMinimalReceiveOnlyMode(minimalProxyChk_ != nullptr && minimalProxyChk_->isChecked());
    const bool started = proxy_->startListenOnly(QStringLiteral("0.0.0.0"), kLocalProxyMustPort);
    if (!started) {
        QMessageBox mb(QMessageBox::Warning,
                         QStringLiteral("Puerto 5555 ocupado"),
                         QStringLiteral(
                             "No se pudo escuchar en 0.0.0.0:5555 (¿otro proceso o netsh portproxy?).\n\n"
                             "Prueba: netstat -ano | findstr :5555"),
                         QMessageBox::Ok,
                         this);
        mb.exec();
        return;
    }

    outboundTcpClosedLastStart_ = 0;
    proxyRunning_ = true;
    tunnelReady_ = false;
    updateProxyToolbarState();
    updateTunnelStatus(false);
    updateUpstreamQuickLabel();
    appendProxyLog(QStringLiteral("[PROXY] Proxy iniciado correctamente. Revisa arriba «Escuchando … — upstream …». "
                                    "Luego abre Dofus."));
}

void MainWindow::onStopProxyClicked()
{
    if (!proxyRunning_) {
        return;
    }
    shutdownProxyAndCleanup();
}

void MainWindow::onStartAllClicked()
{
    // Proxy
    if (!proxyRunning_) {
        onStartProxySoloClicked();
    }

#ifdef Q_OS_WIN
    // Monitor de procesos
    if (processMonitor_ != nullptr && !processMonitor_->isRunning()) {
        onProcessMonitorStart();
    }
#endif

    if (tunnelStatusLbl_ != nullptr) {
        tunnelStatusLbl_->setText(QStringLiteral(
            "<b>Estado:</b> <span style=\"color:#4ade80;font-weight:bold\">✅ Proxy activo</span> — "
            "<span style=\"color:#fbbf24;font-weight:bold\">Esperando conexión…</span>"));
    }
    updateProxyToolbarState();
}

void MainWindow::onStopAllClicked()
{
#ifdef Q_OS_WIN
    if (processMonitor_ != nullptr && processMonitor_->isRunning()) {
        onProcessMonitorStop();
    }
#endif
    if (proxyRunning_) {
        shutdownProxyAndCleanup();
    }
    updateProxyToolbarState();
}

void MainWindow::onApplyUpstreamClicked()
{
    syncUpstreamFromUiToProxy();
    const QHostAddress up(upstreamHost_ != nullptr ? upstreamHost_->text().trimmed() : QString());
    if (up.isNull()
        || (up.protocol() != QHostAddress::IPv4Protocol && up.protocol() != QHostAddress::IPv6Protocol)) {
        QMessageBox::warning(this, QStringLiteral("IP del servidor real"),
                             QStringLiteral("Indica una dirección literal IPv4 o IPv6 en «IP del servidor real "
                                            "(upstream)» (sin DNS)."));
        return;
    }
    proxy_->connectUpstreamForCurrentSession();
    saveUpstreamIpToSharedFile();
    updateUpstreamQuickLabel();
}

void MainWindow::onForceUpstreamRedetectClicked()
{
    if (proxy_ == nullptr) {
        return;
    }
    proxy_->forceUpstreamRedetect();
    updateUpstreamQuickLabel();
}

#ifdef Q_OS_WIN
void MainWindow::onStartProxyWithDllClicked()
{
    if (proxyRunning_) {
        return;
    }

    syncProxyOptionsFromUi();
    proxy_->setTrafficLogging(logTcpCheckbox_->isChecked(), 128);
    ensureUpstreamRealIpFromUi();

    if (!winIsElevatedAdministrator()) {
        QMessageBox::critical(
            this,
            QStringLiteral("Administrador"),
            QStringLiteral("Hace falta «Ejecutar como administrador» para inyectar la DLL."));
        return;
    }
    quint32 gamePid = 0;
    if (!tryGetSelectedPid(&gamePid)) {
        QMessageBox::warning(this, QStringLiteral("PID"),
                             QStringLiteral("Selecciona una fila en la tabla (p. ej. Dofus.exe) antes de iniciar."));
        return;
    }
    const bool echoOn = echoProxyChk_ != nullptr && echoProxyChk_->isChecked();
    const bool minimalOn = minimalProxyChk_ != nullptr && minimalProxyChk_->isChecked();
    if (!echoOn && !minimalOn) {
        const QHostAddress up(upstreamHost_->text().trimmed());
        if (up.isNull()
            || (up.protocol() != QHostAddress::IPv4Protocol && up.protocol() != QHostAddress::IPv6Protocol)) {
            QMessageBox::warning(
                this, QStringLiteral("IP del servidor real"),
                QStringLiteral("Escribe la IP literal del servidor (IPv4/IPv6) en «IP del servidor real (upstream)»; no "
                               "se resuelve DNS (archivo hosts)."));
            return;
        }
    }

    bool okUp = false;
    quint16 upPort = upstreamPort_->text().toUShort(&okUp);
    if (!okUp || upPort == 0) {
        upPort = kUpstreamDefaultPort;
    }

    if (autoInjectDllChk_ == nullptr || autoInjectDllChk_->isChecked()) {
        QString injErr;
        const QString dllPath = dllPathEdit_ != nullptr ? dllPathEdit_->text().trimmed() : QString();
        const QString usePath = dllPath.isEmpty() ? defaultRedirectDllPath() : dllPath;
        if (!winInjectDllIntoProcess(gamePid, usePath, &injErr)) {
            QMessageBox::warning(this, QStringLiteral("Inyección DLL"),
                                 QStringLiteral("No se pudo inyectar DofusRedirect.dll.\n\n%1").arg(injErr));
            return;
        }
        injectedDllPid_ = gamePid;
        appendProxyLog(QStringLiteral("[DLL+] Inyectada en PID %1 — %2")
                             .arg(gamePid)
                             .arg(QDir::toNativeSeparators(usePath)));
        kickGamePort5555AfterInject(gamePid, true);
        if (massCloseOutboundTcpAfterInjectChk_ != nullptr && massCloseOutboundTcpAfterInjectChk_->isChecked()) {
            kickAllOutboundAfterInject(gamePid);
        }
    }

    proxy_->stop();
    syncUpstreamFromUiToProxy();
    proxy_->setMinimalReceiveOnlyMode(minimalProxyChk_ != nullptr && minimalProxyChk_->isChecked());
    {
        bool okPf = false;
        quint16 upPortFinal = upstreamPort_->text().toUShort(&okPf);
        if (!okPf || upPortFinal == 0) {
            upPortFinal = kUpstreamDefaultPort;
        }
        upPort = upPortFinal;
    }
    const bool started =
        proxy_->start(QStringLiteral("0.0.0.0"), kLocalProxyMustPort, upstreamHost_->text().trimmed(), upPort);
    if (!started) {
        QMessageBox mb(QMessageBox::Warning,
                         QStringLiteral("Puerto 5555 ocupado"),
                         QStringLiteral(
                             "Windows no deja abrir el proxy en 0.0.0.0:5555 porque algo ya escucha en :5555 "
                             "(netstat -ano | findstr :5555 muestra el PID en la columna final).\n\n"
                             "Pasos (CMD/PowerShell como administrador):\n"
                             "1) Ver qué es: tasklist /FI \"PID eq TU_PID\"\n"
                             "2) Si es un sniffer antiguo: cierra esa ventana.\n"
                             "3) Si antes usaste netsh portproxy en 5555:\n"
                             "   netsh interface portproxy show all\n"
                             "   Borrar si sigue ahí:\n"
                             "   netsh interface portproxy delete v4tov4 listenport=5555 listenaddress=0.0.0.0\n\n"
                             ":5555 tiene que quedar LIBRE para este programa."),
                         QMessageBox::Ok,
                         this);
        mb.exec();
        return;
    }

    outboundTcpClosedLastStart_ = 0;
    proxyRunning_ = true;
    tunnelReady_ = false;
    updateProxyToolbarState();
    updateTunnelStatus(false);
    updateUpstreamQuickLabel();
    appendProxyLog(QStringLiteral(
        "[PROXY] Listener activo (DLL+PID). Upstream %1:%2 — las nuevas connect(:5555) del juego deben ir a "
        "127.0.0.1:%3.")
            .arg(upstreamHost_->text().trimmed())
            .arg(upPort)
            .arg(kLocalProxyMustPort));
}
#endif

void MainWindow::closeEvent(QCloseEvent* event)
{
#ifdef Q_OS_WIN
    if (processMonitor_ != nullptr) {
        processMonitor_->stopSafely();
    }
    if (pendingMonitorInjectTimer_ != nullptr) {
        pendingMonitorInjectTimer_->stop();
    }
    pendingMonitorInjectPid_ = 0;
#endif
    if (diagLogWin_ != nullptr) {
        diagLogWin_->hide();
    }
    shutdownProxyAndCleanup();
    QMainWindow::closeEvent(event);
}

void MainWindow::shutdownProxyAndCleanup()
{
    const bool had = proxyRunning_;
    proxyRunning_ = false;
    tunnelReady_ = false;
    outboundTcpClosedLastStart_ = 0;
    updateProxyToolbarState();
    updateUpstreamQuickLabel();
    if (had) {
        proxy_->stop();
    }
#ifdef Q_OS_WIN
    lastMonitorFlowLine_.clear();
    prevProxyLoopbackEstablished_ = false;
    pendingMonitorInjectPid_ = 0;
    if (pendingMonitorInjectTimer_ != nullptr) {
        pendingMonitorInjectTimer_->stop();
    }
#else
    Q_UNUSED(had);
#endif
}

void MainWindow::refreshConnectionMonitor()
{
    updateUpstreamQuickLabel();
    if (tcpConnDumpLbl_ == nullptr || memIpReadLbl_ == nullptr) {
        return;
    }

#ifdef Q_OS_WIN
    quint32 monPid = 0;
    if (!tryGetSelectedPid(&monPid)) {
        tcpConnDumpLbl_->setText(
            QStringLiteral("<span style=\"color:#bdbdbd\">Selecciona un PID en la tabla.</span>"));
        memIpReadLbl_->setText(QStringLiteral("<span style=\"color:#bae6fd\">Hook DLL: —</span>"));
        if (diagProxyIndLbl_ != nullptr) {
            diagProxyIndLbl_->setText(QStringLiteral("127.0.0.1:5555 — — (sin PID)"));
        }
        if (diagLastFlowLbl_ != nullptr) {
            diagLastFlowLbl_->setText(QStringLiteral("Última conexión relevante: —"));
        }
        if (upstreamDetectedLbl_ != nullptr) {
            upstreamDetectedLbl_->setText(QStringLiteral("Upstream visto en TCP: — (sin PID)"));
        }
        if (hookDiagPanel_ != nullptr) {
            hookDiagPanel_->setText(buildHookDiagHtmlFromDllLog());
        }
        return;
    }

    bool okUpPort = false;
    const quint16 upPortFld = upstreamPort_->text().toUShort(&okUpPort);
    const quint16 upPortDisp = okUpPort && upPortFld > 0 ? upPortFld : kUpstreamDefaultPort;
    const QString upHostStr = upstreamHost_->text().trimmed();

    const QHostAddress upAddrGuess(upHostStr);
    const bool haveUpstreamIpv4 =
        (!upAddrGuess.isNull()) && upAddrGuess.protocol() == QHostAddress::IPv4Protocol;
    const quint32 upstreamIpHost =
        haveUpstreamIpv4 ? upAddrGuess.toIPv4Address() : static_cast<quint32>(0);

    QVector<TcpRowPidIpv4> rows = winEnumerateTcpIpv4RowsForOwningPid(monPid);

    QString upstreamSeenTcp;
    for (const TcpRowPidIpv4& row : rows) {
        if (row.tcpState != 5 && row.tcpState != 3) { // ESTABLISHED o SYN_SENT
            continue;
        }
        if (row.remotePort != upPortDisp) {
            continue;
        }
        const QString remStr = QHostAddress(qFromBigEndian(row.remoteAddrIpv4BE)).toString();
        if (QHostAddress(remStr).isLoopback()) {
            continue;
        }
        upstreamSeenTcp = QStringLiteral("%1:%2").arg(remStr).arg(row.remotePort);
        break;
    }
    if (upstreamDetectedLbl_ != nullptr) {
        if (!upstreamSeenTcp.isEmpty()) {
            upstreamDetectedLbl_->setText(
                QStringLiteral("Upstream visto en TCP (PID %1): <b>%2</b> — debe coincidir con el campo «Upstream» "
                               "o el túnel puede fallar.")
                    .arg(monPid)
                    .arg(upstreamSeenTcp));
        } else {
            upstreamDetectedLbl_->setText(
                QStringLiteral("Upstream visto en TCP: sin conexión %1 → no-loopback para este PID (SYN/EST).")
                    .arg(upPortDisp));
        }
    }

    constexpr quint32 kEst = 5;
    constexpr quint32 kSynSent = 3;
    QString html;
    html += QLatin1String(
        "<style>td{padding:5px;} .ok{color:#4ade80;} .bad{color:#f87171;} .slow{color:#fbbf24;} "
        ".muted{color:#9ca3af;}</style>");
    html += QStringLiteral("<p><span style=\"font-size:larger\">🔗</span> <span class=\"muted\">TCP IPv4 proceso "
                           "<b>%1</b> · upstream UI <b>%2:%3</b> · esperado proxy "
                           "<b>127.0.0.1:%4</b></span></p>")
                .arg(monPid)
                .arg(upHostStr.isEmpty() ? QLatin1String("?") : upHostStr)
                .arg(upPortDisp)
                .arg(kLocalProxyMustPort);

    html += QLatin1String("<table width=\"100%\">");
    html += QLatin1String("<tr style=\"border-bottom:1px solid #3a3a3a;color:#e5e5e5\"><td> </td><td>Remoto</td>"
                            "<td>Local</td><td>TCP estado</td><td>Interpretación</td></tr>");

    bool proxyEst = false;
    bool srvEst = false;

    auto dwordToIpv4QString = [](quint32 dwordBe) -> QString {
        const quint32 h = qFromBigEndian(dwordBe);
        return QHostAddress(h).toString();
    };

    for (const TcpRowPidIpv4& row : rows) {
        const QString remStr = dwordToIpv4QString(row.remoteAddrIpv4BE);
        const QString locStr = dwordToIpv4QString(row.localAddrIpv4BE);
        const QString stNm = winTcpIpv4StateName(row.tcpState);
        QHostAddress remAddr(remStr);

        const bool isLoop = remAddr.isLoopback();
        const bool isEst = (row.tcpState == kEst);

        QString sym = QStringLiteral("◌");
        QString diag = QStringLiteral("—");
        QString rowStyle = QStringLiteral("slow");

        if (isEst && isLoop && row.remotePort == kLocalProxyMustPort) {
            sym = QStringLiteral("✅");
            diag = QStringLiteral("Por el PROXY · 127.0.0.1:%1").arg(kLocalProxyMustPort);
            rowStyle = QStringLiteral("ok");
            proxyEst = true;
        } else if (isEst && !isLoop && row.remotePort == upPortDisp) {
            bool ipMatch = false;
            if (haveUpstreamIpv4) {
                ipMatch = (remAddr.toIPv4Address() == upstreamIpHost);
            } else {
                ipMatch = QString::compare(remStr, upHostStr, Qt::CaseInsensitive) == 0;
            }

            if (ipMatch) {
                sym = QStringLiteral("❌");
                diag =
                    QStringLiteral("Directo a servidor esperado (%1:%2) sin pasar proxy local")
                        .arg(upHostStr)
                        .arg(upPortDisp);
                rowStyle = QStringLiteral("bad");
                srvEst = true;
            } else {
                sym = QStringLiteral("⚠");
                diag =
                    QStringLiteral("Otro host en puerto servidor %1 (no coincide upstream UI)")
                        .arg(upPortDisp);
                rowStyle = QStringLiteral("slow");
            }
        } else if (isEst && (!isLoop) && row.remotePort != upPortDisp) {
            diag = QStringLiteral("Otro servicio establecido");
            rowStyle = QStringLiteral("slow");
        } else if (isEst && isLoop) {
            diag = QStringLiteral("Loopback distinto (: %1)")
                       .arg(row.remotePort);
            rowStyle = QStringLiteral("slow");
        }

        QString rowColor = QStringLiteral("#fbbf24");
        if (rowStyle == QStringLiteral("ok")) {
            rowColor = QStringLiteral("#4ade80");
        } else if (rowStyle == QStringLiteral("bad")) {
            rowColor = QStringLiteral("#f87171");
        }

        html += QStringLiteral("<tr style=\"color:%1\"><td>%2</td><td>%3:%4</td><td>%5:%6</td><td>%7</td><td>%8</td></tr>")
                    .arg(rowColor,
                         sym,
                         remStr,
                         QString::number(row.remotePort),
                         locStr,
                         QString::number(row.localPort),
                         stNm,
                         diag);
    }

    if (rows.isEmpty()) {
        html += QStringLiteral("<tr><td colspan=\"5\" style=\"color:#fbbf24\">Sin filas TCP IPv4 con owner PID — "
                               "¿IPv6 o sin sockets?</td></tr>");
    }

    html += QLatin1String("</table>");
    html += QLatin1String("<hr style=\"border-color:#3a3a3a\"/>");
    if (proxyEst) {
        html += QStringLiteral("<p style=\"color:#4ade80\"><b>✅</b> Hay al menos un <b>ESTABLISHED</b> hacia "
                               "<b>127.0.0.1:%1</b> (proxy).</p>")
                    .arg(kLocalProxyMustPort);
    } else {
        html += QStringLiteral("<p style=\"color:#fbbf24\"><b>⚠</b> Aún no aparece <b>127.0.0.1:%1</b> en "
                               "ESTABLISHED (reintentando UI / manual).</p>")
                    .arg(kLocalProxyMustPort);
    }

    if (srvEst) {
        html += QStringLiteral("<p style=\"color:#f87171\"><b>❌</b> Conexión estable hacia <b>%1:%2</b> (si el hook "
                               "está activo, debería ir a 127.0.0.1 — revisa la DLL y el log).</p>")
                    .arg(upHostStr)
                    .arg(upPortDisp);
    } else {
        html += QStringLiteral("<p style=\"color:#737373\">Sin conexión estable (ESTABLISHED) obvia hacia <b>%1:%2</b> "
                               "en esta tabla.</p>")
                    .arg(upHostStr)
                    .arg(upPortDisp);
    }

    QString monitorFlowSummary;
    if (!proxyRunning_) {
        monitorFlowSummary = QStringLiteral("Proxy detenido.");
    } else if (proxyEst) {
        monitorFlowSummary =
            QStringLiteral("127.0.0.1:%1 ESTABLISHED → PROXY (hook + listener OK)").arg(kLocalProxyMustPort);
    } else {
        monitorFlowSummary =
            QStringLiteral("Sin ESTABLISHED a 127.0.0.1:%1").arg(kLocalProxyMustPort);
        for (const TcpRowPidIpv4& row : rows) {
            const QString remStr = QHostAddress(qFromBigEndian(row.remoteAddrIpv4BE)).toString();
            const QHostAddress remAddr(remStr);
            if ((row.tcpState == kEst || row.tcpState == kSynSent) && row.remotePort == upPortDisp
                && !remAddr.isLoopback()) {
                monitorFlowSummary =
                    QStringLiteral("%1:%2 %3 → conexión directa al puerto juego (¿hook DLL cargado?)")
                        .arg(remStr, QString::number(row.remotePort), winTcpIpv4StateName(row.tcpState));
                break;
            }
        }
    }
    if (monitorFlowSummary != lastMonitorFlowLine_) {
        lastMonitorFlowLine_ = monitorFlowSummary;
        appendMonitorLine(QStringLiteral("Conexión relevante: ").append(monitorFlowSummary));
    }

    const QString dllHookLine = peekLastDllLogHookLine();
    if (!dllHookLine.isEmpty() && dllHookLine != lastDllLogMonitorLine_) {
        lastDllLogMonitorLine_ = dllHookLine;
        appendMonitorLine(QStringLiteral("Hook activo (log DLL): ").append(dllHookLine));
    }

    const bool hookFlowOk =
        proxyRunning_ && monPid == injectedDllPid_ && injectedDllPid_ != 0 && proxyEst;
    if (hookFlowOk && !prevProxyLoopbackEstablished_) {
        MessageBeep(MB_OK);
        appendProxyLog(QStringLiteral(
            "[MONITOR] ¡Hook funcionando! Conexión redirigida: 127.0.0.1:%1 ESTABLISHED al proxy.")
                .arg(kLocalProxyMustPort));
    }
    prevProxyLoopbackEstablished_ = hookFlowOk;

    if (diagProxyIndLbl_ != nullptr) {
        if (!proxyRunning_) {
            diagProxyIndLbl_->setText(QStringLiteral(
                "<span style=\"color:#9ca3af\">127.0.0.1:%1 — Inicia el proxy para el semáforo.</span>")
                .arg(kLocalProxyMustPort));
        } else if (proxyEst) {
            diagProxyIndLbl_->setText(QStringLiteral(
                "<span style=\"color:#4ade80;font-weight:bold\">127.0.0.1:%1 · CONECTADO AL PROXY</span>")
                .arg(kLocalProxyMustPort));
        } else {
            diagProxyIndLbl_->setText(QStringLiteral(
                "<span style=\"color:#f87171;font-weight:bold\">127.0.0.1:%1 · sin enlace ESTABLISHED al proxy</span>")
                .arg(kLocalProxyMustPort));
        }
    }
    if (diagLastFlowLbl_ != nullptr) {
        diagLastFlowLbl_->setText(
            QStringLiteral("Última conexión relevante: <b>%1</b>").arg(monitorFlowSummary));
    }

    tcpConnDumpLbl_->setText(html);

    {
        QString hookHtml = QStringLiteral("<span style=\"color:#bae6fd\"><b>DofusRedirect.dll</b></span><br>");
        if (injectedDllPid_ != 0) {
            hookHtml += QStringLiteral("Última inyección: PID <b>%1</b>. Log: <code>%2</code><br>")
                            .arg(injectedDllPid_)
                            .arg(QDir::toNativeSeparators(
                                QDir(QDir::tempPath()).absoluteFilePath(QStringLiteral("dofus_redirect_log.txt"))));
        } else {
            hookHtml += QStringLiteral(
                "Sin inyección en esta sesión — <b>Inyectar DLL ahora</b> o <b>Iniciar proxy + DLL (PID)</b> "
                "(checkbox en el grupo DLL).<br>");
        }
        if (!dllHookLine.isEmpty()) {
            hookHtml += QStringLiteral("<span style=\"color:#86efac\">Última señal en log: %1</span>")
                            .arg(dllHookLine.toHtmlEscaped());
        } else {
            hookHtml += QStringLiteral(
                "<span style=\"color:#9ca3af\">Sin líneas recientes de redirect/hook en el log (¿DLL cargada? "
                "¿ruta correcta?).</span>");
        }
        memIpReadLbl_->setText(hookHtml);
    }

    if (hookDiagPanel_ != nullptr) {
        hookDiagPanel_->setText(buildHookDiagHtmlFromDllLog());
    }

#else
    Q_UNUSED(kLocalProxyMustPort);
    tcpConnDumpLbl_->setText(QStringLiteral("<span style=\"color:#9ca3af\">Monitor TCP: solo Windows.</span>"));
    memIpReadLbl_->setText(QStringLiteral("—"));
    if (upstreamDetectedLbl_ != nullptr) {
        upstreamDetectedLbl_->setText(QStringLiteral("Upstream visto en TCP: solo Windows."));
    }
#endif
    refreshIriDiagnostics();
}

QColor MainWindow::protocolKindColor(PacketKind k) const
{
    // Colores por familia de paquete (tabla y detalle)
    switch (k) {
    case PacketKind::IriMovement:
        return Qt::green;
    case PacketKind::IeeHarvest:
        return QColor(34, 139, 34); // forest green
    case PacketKind::IsoResources:
    case PacketKind::ItxMapHeavyServer:
    case PacketKind::MapGatherIerSnapshotServer:
    case PacketKind::MapGatherIevTapClient:
    case PacketKind::MapGatherIeuBundleServer:
        return QColor(255, 200, 100);
    case PacketKind::IrxMonsters:
        return Qt::red;
    case PacketKind::IrlList:
        return Qt::cyan;
    case PacketKind::IdrItemReceived:
        return QColor(100, 255, 100);
    case PacketKind::IdyItemDisplayed:
        return QColor(255, 215, 120);
    case PacketKind::IdwItemVanished:
        return QColor(255, 160, 120);
    case PacketKind::IslEntities:
        return QColor(200, 150, 255);
    case PacketKind::IsuClientSync:
    case PacketKind::IrkSyncResponse:
    case PacketKind::IspSync:
        return QColor(120, 180, 255);
    case PacketKind::MapHopJnrIspClient:
        return QColor(34, 211, 153);
    case PacketKind::IsaPingClient:
    case PacketKind::ItrMapTransitClient:
    case PacketKind::ItoMapTransitClient:
    case PacketKind::JsaPulseClient:
        return QColor(125, 211, 252);
    case PacketKind::IshMapTinyServer:
    case PacketKind::MapHydrateTripleServer:
    case PacketKind::KtaKeyedServer:
    case PacketKind::JsbPulseServer:
        return QColor(147, 197, 253);
    case PacketKind::ItvInteraction:
        return QColor(160, 230, 190);
    case PacketKind::KjCompression:
        return QColor(255, 120, 200);
    case PacketKind::JmwMonsterCmd:
        return QColor(255, 165, 70);
    case PacketKind::CommandData:
        return QColor(255, 140, 90);
    case PacketKind::JrrCommandResponse:
        return QColor(255, 185, 110);
    case PacketKind::DataGeneric:
        return QColor(220, 220, 220);
    default:
        return Qt::white;
    }
}

QString MainWindow::packetTypeEmoji(PacketKind k) const
{
    switch (k) {
    case PacketKind::IriMovement:
        return QStringLiteral("🚶");
    case PacketKind::IeeHarvest:
        return QStringLiteral("🌾");
    case PacketKind::IsoResources:
    case PacketKind::ItxMapHeavyServer:
    case PacketKind::MapGatherIerSnapshotServer:
    case PacketKind::MapGatherIevTapClient:
    case PacketKind::MapGatherIeuBundleServer:
        return QStringLiteral("📦");
    case PacketKind::IrxMonsters:
        return QStringLiteral("👾");
    case PacketKind::IrlList:
        return QStringLiteral("📋");
    case PacketKind::IdrItemReceived:
        return QStringLiteral("✅");
    case PacketKind::IdyItemDisplayed:
        return QStringLiteral("📌");
    case PacketKind::IdwItemVanished:
        return QStringLiteral("👋");
    case PacketKind::IslEntities:
        return QStringLiteral("📑");
    case PacketKind::IsuClientSync:
    case PacketKind::IrkSyncResponse:
    case PacketKind::IspSync:
        return QStringLiteral("🔄");
    case PacketKind::MapHopJnrIspClient:
        return QStringLiteral("🗺");
    case PacketKind::IsaPingClient:
    case PacketKind::ItrMapTransitClient:
    case PacketKind::ItoMapTransitClient:
    case PacketKind::JsaPulseClient:
        return QStringLiteral("➡");
    case PacketKind::IshMapTinyServer:
    case PacketKind::MapHydrateTripleServer:
    case PacketKind::KtaKeyedServer:
    case PacketKind::JsbPulseServer:
        return QStringLiteral("📥");
    case PacketKind::ItvInteraction:
        return QStringLiteral("🖱");
    case PacketKind::KjCompression:
        return QStringLiteral("🗜");
    case PacketKind::JmwMonsterCmd:
        return QStringLiteral("🎯");
    case PacketKind::CommandData:
        return QStringLiteral("⚙");
    case PacketKind::JrrCommandResponse:
        return QStringLiteral("📨");
    case PacketKind::DataGeneric:
        return QStringLiteral("📄");
    default:
        return QStringLiteral("❔");
    }
}

QString MainWindow::buildProtocolPacketDetailHtml(const ProtocolPacketRecord& rec) const
{
    const QVector<IdRangeRule> rules = mergedAliasRulesForAnalysis();
    const QHash<quint64, QString>* notes = &idDatabase_.customNotesById();
    const QString emoji = packetTypeEmoji(rec.kind);
    const QColor tc = protocolKindColor(rec.kind);

    QString html;
    html += QStringLiteral("<html><body style=\"color:#e5e7eb;background:#111827;\">");
    html += QStringLiteral("<h3 style=\"margin:0;\">%1 Paquete #%2</h3>")
                .arg(emoji)
                .arg(rec.index);
    html += QStringLiteral("<p style=\"margin:6px 0;color:#94a3b8;\">%1 · %2 · %3 bytes · "
                           "<span style=\"color:%4\"><b>%5</b></span></p>")
                .arg(rec.received.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")),
                     rec.fromClient ? QStringLiteral("Cliente→Servidor") : QStringLiteral("Servidor→Cliente"),
                     QString::number(rec.byteSize),
                     tc.name(),
                     rec.kindLabel.toHtmlEscaped());

    if (detailPanelHighlightsInteraction(rec)) {
        html += QStringLiteral(
            "<p style=\"color:#f472b6;margin:8px 0 4px;\">🎯 <b>Interacción / farmeo</b> — aquí suele estar el "
            "ID del recurso que tocaste; usa «Guardar ID (clic)» antes del HEX.</p>");
    }

    html += QStringLiteral("<p><b style=\"color:#fbbf24;\">Análisis</b><br>");
    switch (rec.kind) {
    case PacketKind::IriMovement:
        html += QStringLiteral("• Movimiento del personaje (IRI)<br>");
        break;
    case PacketKind::IeeHarvest:
        html += QStringLiteral("• Recolección de recurso (IEE)<br>");
        break;
    case PacketKind::IsoResources:
        html += QStringLiteral("• Información de recursos en el mapa (ISO)<br>");
        break;
    case PacketKind::MapGatherIerSnapshotServer:
        html += QStringLiteral("• Estado / snapshot servidor con <code>ier</code> típico al farmear "
                             "(IDs de recurso en varints incluidos en el agregado de la tabla).<br>");
        break;
    case PacketKind::MapGatherIevTapClient:
        html += QStringLiteral("• Toque cliente <code>iev</code> antes de la respuesta de mapa recurso.<br>");
        break;
    case PacketKind::MapGatherIeuBundleServer:
        html += QStringLiteral("• Bundles <code>ieu</code>/<code>iet</code>/<code>ies</code> servidor con IDs de recurso.<br>");
        break;
    case PacketKind::IrxMonsters:
        html += QStringLiteral("• Lista / datos de monstruos en el mapa (IRX)<br>");
        break;
    case PacketKind::IrlList:
        html += QStringLiteral("• Lista relacionada (IRL)<br>");
        break;
    case PacketKind::IdrItemReceived:
        html += QStringLiteral("• Ítem recibido en inventario (IDR)<br>");
        break;
    case PacketKind::IslEntities:
        html += QStringLiteral("• Entidades / ISL<br>");
        break;
    case PacketKind::IdyItemDisplayed:
        html += QStringLiteral("• Ítem desplegado en el mapa (IDY)<br>");
        break;
    case PacketKind::IdwItemVanished:
        html += QStringLiteral("• Ítem que desaparece (IDW)<br>");
        break;
    case PacketKind::IsuClientSync:
        html += QStringLiteral("• Sincronización cliente (ISU)<br>");
        break;
    case PacketKind::IrkSyncResponse:
        html += QStringLiteral("• Respuesta de sincronización (IRK)<br>");
        break;
    case PacketKind::IspSync:
        html += QStringLiteral("• Sincronización / ISP (sin par JNR en el mismo mensaje)<br>");
        break;
    case PacketKind::MapHopJnrIspClient:
        html += QStringLiteral("• Paso entre mapas típico del cliente: mismo payload combina <code>jnr</code> e "
                             "<code>isp</code> (~88 B). Suele ir detrás de la secuencia ITR/ISH/ITO + hidrato "
                             "servidor.<br>");
        break;
    case PacketKind::IsaPingClient:
        html += QStringLiteral("• ISA — arranque sesión / estado mapa (cliente).<br>");
        break;
    case PacketKind::ItrMapTransitClient:
        html += QStringLiteral("• ITR — tramo cliente→servidor dentro de la transición entre mapas.<br>");
        break;
    case PacketKind::IshMapTinyServer:
        html += QStringLiteral("• ISH — respuesta corta servidor en el tramo de mapa.<br>");
        break;
    case PacketKind::ItoMapTransitClient:
        html += QStringLiteral("• ITO — tramo cliente tras ISH (compromiso / orientación).<br>");
        break;
    case PacketKind::MapHydrateTripleServer:
        html += QStringLiteral("• Paquete servidor con <code>iue</code>, <code>iuc</code> y/o <code>knw</code> "
                             "(contexto / coordenadas de mapa antes del paso JNR+ISP).<br>");
        break;
    case PacketKind::ItxMapHeavyServer:
        html += QStringLiteral("• ITX — carga voluminosa de datos de mapa en el servidor.<br>");
        break;
    case PacketKind::KtaKeyedServer:
        html += QStringLiteral("• KTA — clave / payload asociado al mapa en el servidor.<br>");
        break;
    case PacketKind::JsaPulseClient:
        html += QStringLiteral("• JSA — pulso corto cliente antes de continuar el tramo.<br>");
        break;
    case PacketKind::JsbPulseServer:
        html += QStringLiteral("• JSB — pulso corto servidor (respuesta al JSA).<br>");
        break;
    case PacketKind::ItvInteraction:
        html += QStringLiteral("• ITV — transferencia de información (no es recolección; IEE = recolección)<br>");
        break;
    case PacketKind::KjCompression:
        html += QStringLiteral("• Posible compresión / KJ<br>");
        break;
    case PacketKind::JmwMonsterCmd:
        html += QStringLiteral("• Comando relacionado con monstruos (JMW)<br>");
        break;
    case PacketKind::CommandData:
        html += QStringLiteral("• Comando / jrt<br>");
        break;
    case PacketKind::JrrCommandResponse:
        html += QStringLiteral("• Respuesta de comando (JRR)<br>");
        break;
    case PacketKind::DataGeneric:
        html += QStringLiteral("• Datos genéricos sin URL Ankama conocida<br>");
        break;
    default:
        html += QStringLiteral("• Tipo no clasificado automáticamente<br>");
        break;
    }
    html += QStringLiteral("</p>");

    if (!rec.stringsFound.isEmpty()) {
        html += QStringLiteral("<p><b style=\"color:#93c5fd;\">Strings</b><br>");
        for (const QString& s : rec.stringsFound) {
            html += QStringLiteral("«%1»<br>").arg(s.toHtmlEscaped());
        }
        html += QStringLiteral("</p>");
    }

    // Protobuf wire-format (best-effort). No requiere .proto; solo tag/wire types con heurística.
    {
        const QString ctx = !rec.primaryUrl.isEmpty()
                                ? rec.primaryUrl
                                : detectPacketContext(rec.rawPayload);
        ProtobufParser parser;
        const QList<ProtoField> fields = parser.parse(rec.rawPayload);
        if (!fields.isEmpty()) {
            QString proto = formatProtoFields(fields, 0, ctx);
            const int maxChars = 12000;
            if (proto.size() > maxChars) {
                proto = proto.left(maxChars) + QStringLiteral("\n… (truncado)\n");
            }
            if (!proto.trimmed().isEmpty()) {
                html += QStringLiteral("<p><b style=\"color:#93c5fd;\">📦 ESTRUCTURA PROTOBUF (indentada)</b></p>");
                html += QStringLiteral("<pre style=\"white-space:pre-wrap;font-family:Consolas,monospace;"
                                       "font-size:10pt;color:#e0f2fe;background:#0b1220;padding:8px;"
                                       "border:1px solid #1f2937;border-radius:8px;\">%1</pre>")
                            .arg(proto.toHtmlEscaped());
            }
        }
    }

    html += QStringLiteral("<p><b style=\"color:#86efac;\">IDs / varints</b> (hasta 40 con alias)<br>");
    const int idLim = qMin(40, rec.numericIds.size());
    for (int i = 0; i < idLim; ++i) {
        const quint64 id = rec.numericIds.at(i);
        QString cat;
        const QString al = resolveIdWithRules(id, rules, &cat);
        QString line = QStringLiteral("[%1] %2").arg(i).arg(id);
        if (!al.isEmpty()) {
            line += QStringLiteral(" → %1").arg(al.toHtmlEscaped());
            if (!cat.isEmpty()) {
                line += QStringLiteral(" (%1)").arg(cat.toHtmlEscaped());
            }
        }
        const QString note = notes->value(id);
        if (!note.isEmpty()) {
            line += QStringLiteral(" — nota: %1").arg(note.toHtmlEscaped());
        }
        html += line + QStringLiteral("<br>");
    }
    if (rec.numericIds.size() > idLim) {
        html += QStringLiteral("… +%1 más<br>").arg(rec.numericIds.size() - idLim);
    }
    html += QStringLiteral("</p>");

    if (rec.kind == PacketKind::IrxMonsters || rec.kind == PacketKind::IslEntities) {
        const IrxVarintBuckets buck = classifyIrxStyleVarints(rec.numericIds);
        auto listIds = [](const QList<quint64>& lst) {
            QString s;
            for (quint64 id : lst) {
                s += QStringLiteral("&nbsp;• %1 (posible monstruo / criatura)<br>").arg(id);
            }
            return s;
        };
        auto listPlayers = [](const QList<quint64>& lst) {
            QString s;
            for (quint64 id : lst) {
                s += QStringLiteral("&nbsp;• %1<br>").arg(id);
            }
            return s;
        };
        auto listStruct = [](const QList<quint64>& lst) {
            QString s;
            for (quint64 id : lst) {
                s += QStringLiteral("%1, ").arg(id);
            }
            if (!s.isEmpty()) {
                s.chop(2);
            }
            return s;
        };
        html += QStringLiteral("<p><b style=\"color:#fca5a5;\">👾 Monstruos típicos (IDs ≥ 1.000.000)</b></p>");
        html += buck.monsters.isEmpty()
                    ? QStringLiteral("<p style=\"color:#64748b;\">Sin IDs en ese rango.</p>")
                    : (QStringLiteral("<p style=\"color:#fde68a;\">") + listIds(buck.monsters)
                       + QStringLiteral("</p>"));
        html += QStringLiteral(
            "<p><b style=\"color:#93c5fd;\">👤 Personajes / jugadores (aprox. 1.000 – 9.999)</b></p>");
        html += buck.players.isEmpty()
                    ? QStringLiteral("<p style=\"color:#64748b;\">Sin IDs en ese rango.</p>")
                    : QStringLiteral("<p style=\"color:#bfdbfe;\">")
                          + listPlayers(buck.players)
                          + QStringLiteral("</p>"
                                           "<p style=\"color:#f87171;font-size:11px;\">⚠ No son automáticamente "
                                           "«monstruos de mapa»; suelen referirse a jugadores u otras entidades.</p>");
        html += QStringLiteral("<p><b style=\"color:#94a3b8;\">🔧 Estructura interna típica (IDs &lt; 1.000)</b></p>");
        {
            QString structLine = listStruct(buck.structure);
            if (structLine.isEmpty()) {
                structLine = QStringLiteral("—");
            }
            html += QStringLiteral("<p style=\"color:#cbd5e1;font-size:10pt;font-family:Consolas,monospace;\">")
                + structLine.toHtmlEscaped()
                + QStringLiteral("</p>"
                             "<p style=\"color:#64748b;font-size:10px;\">Suelen ser campos de protocolo; "
                             "ignóralos salvo investigación binaria.</p>");
        }

        const QString irxBlock = analyzeIrxStyleVarintBuckets(rec.numericIds);
        if (!irxBlock.isEmpty()) {
            html += QStringLiteral("<p><b style=\"color:#fca5a5;\">Resumen texto legible</b></p><pre style="
                                   "white-space:pre-wrap;font-family:Consolas,monospace;font-size:10pt;color:#fdba74;\">%1</pre>")
                        .arg(irxBlock.toHtmlEscaped());
        }
    }

    {
        QSet<quint64> saveLinkIds;
        for (quint64 id : rec.numericIds) {
            if (isHeuristicResourceCandidateId(id)) {
                saveLinkIds.insert(id);
            }
        }
        for (quint64 id : filterResourceCandidateIds(rec.numericIds, parsedAndDatabaseRulesForResourceFilter())) {
            saveLinkIds.insert(id);
        }
        if (!saveLinkIds.isEmpty()) {
            QList<quint64> sorted = saveLinkIds.values();
            std::sort(sorted.begin(), sorted.end());
            QStringList anchors;
            for (quint64 sid : sorted) {
                anchors << QStringLiteral("<a href=\"dofusid://save/%1\" style=\"color:#7dd3fc;font-weight:bold;"
                                          "text-decoration:underline;\">%1</a>")
                             .arg(sid);
            }
            html +=
                QStringLiteral("<p style=\"margin:14px 0 6px;\"><b style=\"color:#86efac;\">Guardar ID (clic)</b></p>"
                               "<p style=\"margin:4px 0;line-height:1.7;font-size:12pt;font-family:Consolas,monospace;\">"
                               "%1</p>"
                               "<p style=\"color:#64748b;font-size:11px;margin:8px 0 2px;\">Cada número abre un menú: "
                               "guardar como recurso o monstruo en <code>ids_database.json</code>.</p>")
                    .arg(anchors.join(QStringLiteral(" · ")));
        }
    }

    constexpr int kMaxHexUiBytes = 512 * 1024;
    const int payloadSz = rec.rawPayload.size();
    const bool truncPanel = payloadSz > kMaxHexUiBytes;
    const int hexTake = truncPanel ? kMaxHexUiBytes : payloadSz;
    const QString hexDump = formatHexDumpWireshark(rec.rawPayload, hexTake);
    const QString truncNote =
        truncPanel ? QStringLiteral(" — en panel solo los primeros %1 B; exportar selección para volcado completo")
                         .arg(kMaxHexUiBytes)
                   : QString();
    html += QStringLiteral("<p><b style=\"color:#fca5a5;\">HEX</b> (%1 bytes%2)</p>"
                           "<pre style=\"white-space:pre-wrap;font-family:Consolas,monospace;font-size:10pt;"
                           "color:#c7d2fe;\">%3</pre>")
                .arg(payloadSz)
                .arg(truncNote)
                .arg(QString(hexDump).toHtmlEscaped());

    html += QStringLiteral("</body></html>");
    return html;
}

QVector<IdRangeRule> MainWindow::parsedUserIdRulesFromUi() const
{
    if (idAliasRulesEdit_ == nullptr) {
        return {};
    }
    return parseIdAliasRulesText(idAliasRulesEdit_->toPlainText());
}

QVector<IdRangeRule> MainWindow::mergedAliasRulesForAnalysis() const
{
    QVector<IdRangeRule> m = parsedUserIdRulesFromUi();
    m += idDatabase_.toRangeRules();
    m += defaultBuiltinIdRules();
    return m;
}

QVector<IdRangeRule> MainWindow::parsedAndDatabaseRulesForResourceFilter() const
{
    QVector<IdRangeRule> m = parsedUserIdRulesFromUi();
    m += idDatabase_.toRangeRules();
    return m;
}

void MainWindow::reloadIdDatabaseFromDisk()
{
    const QString p = IdDatabase::defaultStoragePath();
    if (!QFile::exists(p)) {
        return;
    }
    QString err;
    if (!idDatabase_.loadFromFile(p, &err) && !err.isEmpty()) {
        appendProxyLog(QStringLiteral("[IDS] %1").arg(err));
    }
    refreshSavedResMonUi();
    refreshResourceCandidatesUi();
}

void MainWindow::reloadHarvestTemplateFromDisk()
{
    harvestTemplatePayload_.clear();
    QFile f(harvestTemplateBinPath());
    if (f.open(QIODevice::ReadOnly)) {
        harvestTemplatePayload_ = f.readAll();
    }
    if (harvestStatusLbl_ != nullptr) {
        if (harvestTemplatePayload_.isEmpty()) {
            harvestStatusLbl_->setText(
                QStringLiteral("Plantilla IEE: (ninguna) — guarda un IEE o coloca plantilla_recolectar.bin"));
        } else {
            harvestStatusLbl_->setText(QStringLiteral("Plantilla IEE: %1 B · %2")
                                           .arg(harvestTemplatePayload_.size())
                                           .arg(QDir::toNativeSeparators(harvestTemplateBinPath())));
        }
    }
}

QString MainWindow::harvestTemplateBinPath() const
{
    return QCoreApplication::applicationDirPath() + QStringLiteral("/plantilla_recolectar.bin");
}

void MainWindow::setupLibraryTab(QWidget* tab)
{
    auto* layout = new QVBoxLayout(tab);
    auto* infoLabel = new QLabel(QStringLiteral(
        "Archivos generados con «Guardar selección con nombre y nota» o exportaciones en "
        "<code>exported_logs</code> junto al ejecutable."));
    infoLabel->setWordWrap(true);
    layout->addWidget(infoLabel);

    layout->addWidget(new QLabel(QStringLiteral("📁 Archivos guardados:")));
    libraryLogList_ = new QListWidget;
    libraryLogList_->setSelectionMode(QAbstractItemView::SingleSelection);
    layout->addWidget(libraryLogList_, 1);

    layout->addWidget(new QLabel(QStringLiteral("📄 Vista previa (primeras líneas):")));
    libraryPreviewEdit_ = new QTextEdit;
    libraryPreviewEdit_->setReadOnly(true);
    libraryPreviewEdit_->setMaximumHeight(220);
    {
        auto fnt = libraryPreviewEdit_->font();
        fnt.setFamily(QStringLiteral("Consolas"));
        libraryPreviewEdit_->setFont(fnt);
    }
    layout->addWidget(libraryPreviewEdit_);

    layout->addWidget(new QLabel(QStringLiteral(
        "<b>Búsqueda</b> en todos los archivos dentro de <code>exported_logs</code> (*.txt).")));
    {
        auto* h = new QHBoxLayout;
        librarySearchEdit_ = new QLineEdit;
        librarySearchEdit_->setPlaceholderText(QStringLiteral("texto (# paquete, HEX, substring URL…)"));
        librarySearchBtn_ = new QPushButton(QStringLiteral("🔍 Buscar"));
        librarySearchResults_ = new QListWidget;
        librarySearchResults_->setMinimumHeight(100);
        librarySearchResults_->setMaximumHeight(180);
        h->addWidget(librarySearchEdit_, 1);
        h->addWidget(librarySearchBtn_);
        layout->addLayout(h);
        layout->addWidget(librarySearchResults_);
        libraryImportLogBtn_ = new QPushButton(QStringLiteral("📥 Importar log seleccionado (lista o resultado) "
                                                              "→ pestaña Logs"));
        libraryImportLogBtn_->setToolTip(QStringLiteral("Preferencia: entrada seleccionada en resultados "
                                                         "de búsqueda; si no hay, el archivo destacado."));
        layout->addWidget(libraryImportLogBtn_);
        connect(librarySearchBtn_, &QPushButton::clicked, this, &MainWindow::librarySearchAcrossExportedLogs);
        connect(librarySearchResults_, &QListWidget::itemDoubleClicked, this,
                [this](QListWidgetItem* it) {
                    if (it == nullptr) {
                        return;
                    }
                    const QVariant v = it->data(Qt::UserRole + 101);
                    if (v.canConvert<QString>() && QFile::exists(v.toString())) {
                        importExportedLogFromPath(v.toString());
                    }
                });
        connect(libraryImportLogBtn_, &QPushButton::clicked, this, [this]() {
            QListWidgetItem* it = nullptr;
            if (librarySearchResults_ != nullptr && librarySearchResults_->currentItem() != nullptr) {
                it = librarySearchResults_->currentItem();
            }
            if (it != nullptr) {
                const QVariant v = it->data(Qt::UserRole + 101);
                if (v.canConvert<QString>() && QFile::exists(v.toString())) {
                    importExportedLogFromPath(v.toString());
                    return;
                }
            }
            if (libraryLogList_ != nullptr && libraryLogList_->currentItem() != nullptr) {
                const QString dirPath =
                    QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QStringLiteral("exported_logs"));
                const QString path =
                    QDir(dirPath).filePath(libraryLogList_->currentItem()->text());
                if (QFile::exists(path)) {
                    importExportedLogFromPath(path);
                }
            }
        });
    }

    auto* btnLayout = new QHBoxLayout;
    auto* openBtn = new QPushButton(QStringLiteral("📂 Abrir en editor externo"));
    auto* deleteBtn = new QPushButton(QStringLiteral("🗑 Eliminar"));
    auto* refreshBtn = new QPushButton(QStringLiteral("🔄 Actualizar"));
    btnLayout->addWidget(openBtn);
    btnLayout->addWidget(deleteBtn);
    btnLayout->addWidget(refreshBtn);
    btnLayout->addStretch(1);
    layout->addLayout(btnLayout);

    connect(libraryLogList_, &QListWidget::currentItemChanged, this,
            [this](QListWidgetItem* item, QListWidgetItem* /*previous*/) {
                if (libraryPreviewEdit_ == nullptr || item == nullptr) {
                    return;
                }
                const QString dirPath =
                    QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QStringLiteral("exported_logs"));
                const QString path = QDir(dirPath).filePath(item->text());
                QFile file(path);
                if (!file.open(QIODevice::ReadOnly)) {
                    libraryPreviewEdit_->setPlainText(QStringLiteral("(no se pudo leer el archivo)"));
                    return;
                }
                const QString content = QString::fromUtf8(file.readAll());
                file.close();
                const QStringList lines = content.split(QLatin1Char('\n'));
                const QString head = lines.mid(0, 30).join(QLatin1Char('\n'));
                libraryPreviewEdit_->setPlainText(head
                                                   + (lines.size() > 30 ? QStringLiteral("\n\n... (truncado)")
                                                                         : QString()));
            });

    connect(openBtn, &QPushButton::clicked, this, [this]() {
        if (libraryLogList_ == nullptr || libraryLogList_->currentItem() == nullptr) {
            return;
        }
        const QString dirPath =
            QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QStringLiteral("exported_logs"));
        const QString path = QDir(dirPath).filePath(libraryLogList_->currentItem()->text());
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });

    connect(deleteBtn, &QPushButton::clicked, this, [this]() {
        if (libraryLogList_ == nullptr || libraryLogList_->currentItem() == nullptr) {
            return;
        }
        const QString name = libraryLogList_->currentItem()->text();
        if (QMessageBox::question(this, QStringLiteral("Confirmar"),
                                  QStringLiteral("¿Eliminar «%1»?").arg(name))
            != QMessageBox::Yes) {
            return;
        }
        const QString dirPath =
            QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QStringLiteral("exported_logs"));
        const QString path = QDir(dirPath).filePath(name);
        QFile::remove(path);
        refreshExportedLogsList();
        if (libraryPreviewEdit_ != nullptr) {
            libraryPreviewEdit_->clear();
        }
    });

    connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::refreshExportedLogsList);
    refreshExportedLogsList();
}

void MainWindow::refreshExportedLogsList()
{
    if (libraryLogList_ == nullptr) {
        return;
    }
    libraryLogList_->clear();
    const QString dirPath =
        QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QStringLiteral("exported_logs"));
    QDir dir(dirPath);
    if (!dir.exists()) {
        dir.mkpath(QStringLiteral("."));
    }
    const QFileInfoList infos =
        dir.entryInfoList(QStringList() << QStringLiteral("*.txt"), QDir::Files, QDir::Time | QDir::Reversed);
    for (const QFileInfo& fi : infos) {
        auto* item = new QListWidgetItem(fi.fileName());
        item->setToolTip(QStringLiteral("Modificado: %1\n%2")
                             .arg(fi.lastModified().toString(Qt::ISODateWithMs))
                             .arg(QDir::toNativeSeparators(fi.absoluteFilePath())));
        libraryLogList_->addItem(item);
    }
}

void MainWindow::openResourceEditor()
{
    ResourceAliasEditor dlg(this);
    dlg.loadFromMaps(idDatabase_.resourceOverrides(), idDatabase_.monsterNames(), idDatabase_.playerNames(),
                     idDatabase_.objectNames(), idDatabase_.customNotesById());
    if (dlg.exec() != QDialog::Accepted) {
        return;
    }

    QHash<quint64, QString> res;
    QHash<quint64, QString> mon;
    QHash<quint64, QString> pl;
    QHash<quint64, QString> obj;
    QHash<quint64, QString> notes;
    dlg.applyToMaps(&res, &mon, &pl, &obj, &notes);
    idDatabase_.setResourceOverrides(res);
    idDatabase_.setMonsterNames(mon);
    idDatabase_.setPlayerNames(pl);
    idDatabase_.setObjectNames(obj);
    idDatabase_.setCustomNotes(notes);

    QString err;
    if (!idDatabase_.saveToFile(IdDatabase::defaultStoragePath(), &err)) {
        QMessageBox::warning(this, QStringLiteral("Guardar"),
                             QStringLiteral("No se pudo guardar ids_database.json:\n%1").arg(err));
        return;
    }
    reloadIdDatabaseFromDisk();
    refreshResourceCandidatesUi();
    refreshProtocolDetailFromSelection();
    QMessageBox::information(this, QStringLiteral("Guardado"),
                             QStringLiteral("ids_database.json actualizado correctamente."));
}

void MainWindow::appendProtocolTreeItem(const ProtocolPacketRecord& r, int vectorIndex)
{
    if (protocolLogTree_ == nullptr) {
        return;
    }
    QSet<int> selectedVec;
    int currentVec = -1;
    bool doAutoScrollTail = false;
    {
        for (QTreeWidgetItem* s : protocolLogTree_->selectedItems()) {
            selectedVec.insert(s->data(0, kProtoVecRole).toInt());
        }
        if (QTreeWidgetItem* cur = protocolLogTree_->currentItem()) {
            currentVec = cur->data(0, kProtoVecRole).toInt();
        }
        if (protocolLogAutoScrollChk_ != nullptr && protocolLogAutoScrollChk_->isChecked()) {
            if (QScrollBar* sb = protocolLogTree_->verticalScrollBar()) {
                doAutoScrollTail = sb->value() >= sb->maximum() - 3;
            } else {
                doAutoScrollTail = true;
            }
        }
    }

    auto* it = new QTreeWidgetItem(protocolLogTree_);
    it->setData(0, Qt::UserRole, static_cast<int>(r.kind));
    it->setData(0, kProtoVecRole, vectorIndex);
    it->setText(0, QString::number(r.index));
    it->setText(1, r.received.toString(QStringLiteral("HH:mm:ss.zzz")));
    it->setText(2, r.fromClient ? QStringLiteral("→") : QStringLiteral("←"));
    it->setText(3, protocolTreeKindColumnText(r));
    it->setText(4, QString::number(r.byteSize));
    it->setText(5, r.primaryUrl.isEmpty() ? QStringLiteral("—") : r.primaryUrl);
    {
        const QVector<IdRangeRule> merged = mergedAliasRulesForAnalysis();
        QStringList previewParts;
        QStringList tipLines;
        for (int i = 0; i < qMin(3, r.numericIds.size()); ++i) {
            const quint64 id = r.numericIds.at(i);
            QString cat;
            const QString lab = resolveIdWithRules(id, merged, &cat);
            if (!lab.isEmpty()) {
                const QString kindTag = cat.isEmpty() ? QStringLiteral("recurso") : cat;
                previewParts << QStringLiteral("%1 → %2 (%3)").arg(id).arg(lab).arg(kindTag);
            } else {
                previewParts << QString::number(id);
            }
            const QString note = idDatabase_.customNotesById().value(id);
            if (!note.isEmpty()) {
                tipLines << QStringLiteral("%1: %2").arg(id).arg(note);
            }
        }
        it->setText(6, previewParts.isEmpty() ? QStringLiteral("—") : previewParts.join(QStringLiteral(", ")));
        it->setToolTip(6, tipLines.isEmpty() ? QString() : tipLines.join(QLatin1Char('\n')));
    }
    it->setTextAlignment(0, Qt::AlignRight | Qt::AlignVCenter);
    it->setTextAlignment(4, Qt::AlignRight | Qt::AlignVCenter);

    const QColor fgType = protocolKindColor(r.kind);
    const QColor dirFg = r.fromClient ? QColor(0x5e, 0xea, 0xd4) : QColor(0xfc, 0xa5, 0xa5);
    it->setForeground(0, QBrush(fgType));
    it->setForeground(1, QBrush(QColor(0xe5, 0xe7, 0xeb)));
    it->setForeground(2, QBrush(dirFg));
    it->setForeground(3, QBrush(fgType));
    it->setForeground(4, QBrush(QColor(0xe5, 0xe7, 0xeb)));
    it->setForeground(5, QBrush(QColor(0xfe, 0xf3, 0xc7)));
    it->setForeground(6, QBrush(QColor(0xdb, 0xea, 0xfe)));

    protocolLogTree_->resizeColumnToContents(0);
    protocolLogTree_->resizeColumnToContents(4);

    for (int i = 0; i < protocolLogTree_->topLevelItemCount(); ++i) {
        QTreeWidgetItem* ti = protocolLogTree_->topLevelItem(i);
        const int v = ti->data(0, kProtoVecRole).toInt();
        ti->setSelected(selectedVec.contains(v));
        if (v == currentVec) {
            protocolLogTree_->setCurrentItem(ti);
        }
    }
    if (doAutoScrollTail) {
        protocolLogTree_->scrollToItem(it, QAbstractItemView::PositionAtBottom);
        if (QScrollBar* sb = protocolLogTree_->verticalScrollBar()) {
            sb->setValue(sb->maximum());
        }
    }
}

void MainWindow::syncProtocolTreeItemFromRecord(int vecIndex)
{
    if (protocolLogTree_ == nullptr || vecIndex < 0 || vecIndex >= protocolRecords_.size()) {
        return;
    }
    const ProtocolPacketRecord& r = protocolRecords_[vecIndex];
    for (int i = 0; i < protocolLogTree_->topLevelItemCount(); ++i) {
        QTreeWidgetItem* it = protocolLogTree_->topLevelItem(i);
        if (it->data(0, kProtoVecRole).toInt() != vecIndex) {
            continue;
        }
        it->setData(0, Qt::UserRole, static_cast<int>(r.kind));
        it->setText(3, protocolTreeKindColumnText(r));
        const QColor fgType = protocolKindColor(r.kind);
        const QColor dirFg = r.fromClient ? QColor(0x5e, 0xea, 0xd4) : QColor(0xfc, 0xa5, 0xa5);
        it->setForeground(0, QBrush(fgType));
        it->setForeground(2, QBrush(dirFg));
        it->setForeground(3, QBrush(fgType));
        break;
    }
}

void MainWindow::applyPacketKindOverride(int vecIndex, const QString& label)
{
    if (vecIndex < 0 || vecIndex >= protocolRecords_.size()) {
        return;
    }
    ProtocolPacketRecord& r = protocolRecords_[vecIndex];
    packetTypeOverrides_.setLabelForPayload(r.rawPayload, label);
    QString err;
    if (!packetTypeOverrides_.save(&err)) {
        QMessageBox::warning(this, QStringLiteral("Guardar tipo"),
                             QStringLiteral("No se pudo guardar packet_type_overrides.json:\n%1").arg(err));
        return;
    }
    const PacketKind mapped = packetKindFromDisplayLabel(label);
    r.kind = (mapped != PacketKind::Unknown) ? mapped : PacketKind::DataGeneric;
    r.kindLabel = label;
    syncProtocolTreeItemFromRecord(vecIndex);
    refreshProtocolDetailFromSelection();
    applyProtocolLogFilters();
    statusBar()->showMessage(QStringLiteral("Tipo de paquete: %1").arg(label), 4000);
}

void MainWindow::clearPacketKindOverride(int vecIndex)
{
    if (vecIndex < 0 || vecIndex >= protocolRecords_.size()) {
        return;
    }
    ProtocolPacketRecord& r = protocolRecords_[vecIndex];
    packetTypeOverrides_.removeFingerprint(r.rawPayload);
    QString err;
    if (!packetTypeOverrides_.save(&err)) {
        QMessageBox::warning(this, QStringLiteral("Guardar tipo"),
                             QStringLiteral("No se pudo guardar packet_type_overrides.json:\n%1").arg(err));
        return;
    }
    const ProtocolPacketRecord rebuilt =
        buildRecordFromPayload(r.index, r.fromClient, r.rawPayload, &packetTypeOverrides_);
    r.kind = rebuilt.kind;
    r.kindLabel = rebuilt.kindLabel;
    syncProtocolTreeItemFromRecord(vecIndex);
    refreshProtocolDetailFromSelection();
    applyProtocolLogFilters();
    statusBar()->showMessage(QStringLiteral("Corrección manual eliminada; tipo automático aplicado."), 4000);
}

void MainWindow::refreshProtocolDetailFromSelection()
{
    if (protocolDetailText_ == nullptr || protocolLogTree_ == nullptr) {
        return;
    }
    QTreeWidgetItem* cur = protocolLogTree_->currentItem();
    if (cur == nullptr) {
        protocolDetailText_->clear();
        return;
    }
    bool okIdx = false;
    const int vix = cur->data(0, kProtoVecRole).toInt(&okIdx);
    if (!okIdx || vix < 0 || vix >= protocolRecords_.size()) {
        protocolDetailText_->clear();
        return;
    }
    const ProtocolPacketRecord& rec = protocolRecords_[vix];
    protocolDetailText_->setHtml(buildProtocolPacketDetailHtml(rec));
    updateIrxQuickClassifyUi(vix);
}

void MainWindow::onProtocolLogCurrentItemChanged(QTreeWidgetItem* current, QTreeWidgetItem* /*previous*/)
{
    Q_UNUSED(current);
    refreshProtocolDetailFromSelection();
}

void MainWindow::onProtocolLogContextMenu(const QPoint& pos)
{
    if (protocolLogTree_ == nullptr) {
        return;
    }
    QTreeWidgetItem* it = protocolLogTree_->itemAt(pos);
    if (it == nullptr) {
        return;
    }

    const QList<QTreeWidgetItem*> selBefore = protocolLogTree_->selectedItems();
    const QSet<QTreeWidgetItem*> selSet(selBefore.begin(), selBefore.end());

    if (selSet.isEmpty()) {
        it->setSelected(true);
        protocolLogTree_->setCurrentItem(it);
    } else if (selSet.size() > 1 && selSet.contains(it)) {
        if (auto* sm = protocolLogTree_->selectionModel(); sm != nullptr) {
            sm->setCurrentIndex(protocolLogTree_->indexFromItem(it), QItemSelectionModel::Current);
        }
    } else if (!selSet.contains(it)) {
        protocolLogTree_->clearSelection();
        it->setSelected(true);
        protocolLogTree_->setCurrentItem(it);
    } else {
        protocolLogTree_->setCurrentItem(it);
    }
    refreshProtocolDetailFromSelection();
    bool okIdx = false;
    const int vix = it->data(0, kProtoVecRole).toInt(&okIdx);

    QMenu menu(this);
    if (okIdx && vix >= 0 && vix < protocolRecords_.size()) {
        QMenu* typeMenu = menu.addMenu(QStringLiteral("✏ Corregir tipo de paquete"));
        const QStringList labels = standardPacketKindLabels();
        for (const QString& lab : labels) {
            typeMenu->addAction(lab, this, [this, vix, lab]() { applyPacketKindOverride(vix, lab); });
        }
        typeMenu->addSeparator();
        typeMenu->addAction(QStringLiteral("Quitar corrección manual (volver a detección)"), this,
                            [this, vix]() { clearPacketKindOverride(vix); });
        menu.addSeparator();
    }
    menu.addAction(QStringLiteral("Exportar selección (%1) a TXT…")
                       .arg(protocolLogTree_->selectedItems().size()),
                   this, &MainWindow::exportSelectedPackages);
    menu.addAction(QStringLiteral("Guardar selección con nombre y nota…"), this,
                   &MainWindow::onExportSelectedWithNote);
    menu.addSeparator();
    menu.addAction(QStringLiteral("Exportar paquete actual a JSON / TXT…"), this,
                   &MainWindow::exportSelectedPacketAsJsonOrTxt);
    menu.exec(protocolLogTree_->viewport()->mapToGlobal(pos));
}

void MainWindow::exportSelectedPackages()
{
    if (protocolLogTree_ == nullptr) {
        return;
    }
    QList<QTreeWidgetItem*> selected = protocolLogTree_->selectedItems();
    if (selected.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Sin selección"), QStringLiteral("No hay paquetes seleccionados."));
        return;
    }

    struct ItemRec {
        int index = 0;
        int vecIndex = -1;
    };
    QVector<ItemRec> items;
    items.reserve(selected.size());
    for (QTreeWidgetItem* it : selected) {
        if (!it) {
            continue;
        }
        bool ok = false;
        const int vix = it->data(0, kProtoVecRole).toInt(&ok);
        if (!ok || vix < 0 || vix >= protocolRecords_.size()) {
            continue;
        }
        const int idx = protocolRecords_[vix].index;
        items.push_back(ItemRec{idx, vix});
    }
    if (items.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Exportar"), QStringLiteral("La selección no contiene registros válidos."));
        return;
    }
    std::sort(items.begin(), items.end(), [](const ItemRec& a, const ItemRec& b) {
        if (a.index != b.index) {
            return a.index < b.index;
        }
        return a.vecIndex < b.vecIndex;
    });

    QString suggested = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("export_seleccion.txt"));
    const QString fileName = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("Guardar selección"),
        QDir::toNativeSeparators(suggested),
        QStringLiteral("Texto (*.txt);;Todos (*.*)"));
    if (fileName.isEmpty()) {
        return;
    }
    QFile f(fileName);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        QMessageBox::warning(this, QStringLiteral("Exportar"), QStringLiteral("No se pudo escribir:\n%1").arg(fileName));
        return;
    }

    QTextStream out(&f);
    const QVector<IdRangeRule> rules = mergedAliasRulesForAnalysis();
    const auto* notes = &idDatabase_.customNotesById();
    for (const ItemRec& ir : items) {
        const ProtocolPacketRecord& rec = protocolRecords_[ir.vecIndex];
        out << "========================================\n";
        out << "EXPORT paquete #" << rec.index << "\n";
        out << buildPacketAnalysisText(rec, rules, 512, notes);
        out << "\n";
    }
    f.close();
    statusBar()->showMessage(QStringLiteral("Exportados %1 paquetes → %2").arg(items.size()).arg(fileName), 8000);
}

void MainWindow::onExportSelectedWithNote()
{
    if (protocolLogTree_ == nullptr) {
        return;
    }
    QList<QTreeWidgetItem*> selected = protocolLogTree_->selectedItems();
    if (selected.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Sin selección"), QStringLiteral("No hay paquetes seleccionados."));
        return;
    }

    QDialog dlg(this);
    dlg.setWindowTitle(QStringLiteral("Guardar selección"));
    auto* form = new QFormLayout(&dlg);
    auto* nameEdit = new QLineEdit(&dlg);
    nameEdit->setPlaceholderText(QStringLiteral("nombre opcional"));
    auto* noteEdit = new QTextEdit(&dlg);
    noteEdit->setPlaceholderText(QStringLiteral("Nota / descripción…"));
    noteEdit->setMinimumHeight(100);
    form->addRow(QStringLiteral("Nombre del log:"), nameEdit);
    form->addRow(QStringLiteral("Nota / descripción:"), noteEdit);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    form->addRow(bb);
    QObject::connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    if (dlg.exec() != QDialog::Accepted) {
        return;
    }

    QString baseName = nameEdit->text().trimmed();
    if (baseName.isEmpty()) {
        baseName = QStringLiteral("log_%1").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_hhmmss")));
    }
    for (QChar& c : baseName) {
        if (c == QLatin1Char('/') || c == QLatin1Char('\\') || c == QLatin1Char(':') || c == QLatin1Char('*')
            || c == QLatin1Char('?') || c == QLatin1Char('"') || c == QLatin1Char('<') || c == QLatin1Char('>')
            || c == QLatin1Char('|')) {
            c = QLatin1Char('_');
        }
    }

    const QString exportDir =
        QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QStringLiteral("exported_logs"));
    QDir().mkpath(exportDir);
    const QString fileName = QDir(exportDir).filePath(baseName + QStringLiteral(".txt"));

    struct ItemRec {
        int index = 0;
        int vecIndex = -1;
    };
    QVector<ItemRec> items;
    items.reserve(selected.size());
    for (QTreeWidgetItem* it : selected) {
        if (!it) {
            continue;
        }
        bool ok = false;
        const int vix = it->data(0, kProtoVecRole).toInt(&ok);
        if (!ok || vix < 0 || vix >= protocolRecords_.size()) {
            continue;
        }
        const int idx = protocolRecords_[vix].index;
        items.push_back(ItemRec{idx, vix});
    }
    if (items.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Exportar"), QStringLiteral("La selección no contiene registros válidos."));
        return;
    }
    std::sort(items.begin(), items.end(), [](const ItemRec& a, const ItemRec& b) {
        if (a.index != b.index) {
            return a.index < b.index;
        }
        return a.vecIndex < b.vecIndex;
    });

    QFile f(fileName);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        QMessageBox::warning(this, QStringLiteral("Exportar"),
                             QStringLiteral("No se pudo escribir:\n%1").arg(fileName));
        return;
    }

    QTextStream out(&f);
    out << QStringLiteral("=== LOG EXPORTADO ===\n");
    out << QStringLiteral("Nombre: ") << baseName << QLatin1Char('\n');
    out << QStringLiteral("Fecha: ")
        << QDateTime::currentDateTime().toString(Qt::ISODateWithMs) << QLatin1Char('\n');
    out << QStringLiteral("Nota: ") << noteEdit->toPlainText() << QLatin1Char('\n');
    out << QStringLiteral("Paquetes: ") << items.size() << QLatin1Char('\n');
    out << QStringLiteral("===================\n\n");

    const QVector<IdRangeRule> rules = mergedAliasRulesForAnalysis();
    const auto* notes = &idDatabase_.customNotesById();
    for (const ItemRec& ir : items) {
        const ProtocolPacketRecord& rec = protocolRecords_[ir.vecIndex];
        out << QStringLiteral("========================================\n");
        out << QStringLiteral("EXPORT paquete #") << rec.index << QLatin1Char('\n');
        out << buildPacketAnalysisText(rec, rules, rec.rawPayload.size(), notes);
        out << QLatin1Char('\n');
    }
    f.close();
    refreshExportedLogsList();
    statusBar()->showMessage(QStringLiteral("Log guardado: %1").arg(QDir::toNativeSeparators(fileName)), 10000);
}

void MainWindow::onIdAliasRulesChanged()
{
    refreshProtocolDetailFromSelection();
}

void MainWindow::saveSelectedPacketAsTemplate(const QString& cardinalEs)
{
    QTreeWidgetItem* cur =
        protocolLogTree_ != nullptr ? protocolLogTree_->currentItem() : nullptr;
    if (cur == nullptr) {
        QMessageBox::information(this, QStringLiteral("Plantilla"),
                                 QStringLiteral("Selecciona un paquete en la tabla."));
        return;
    }
    const int vix = cur->data(0, kProtoVecRole).toInt();
    if (vix < 0 || vix >= protocolRecords_.size()) {
        return;
    }
    const ProtocolPacketRecord& rec = protocolRecords_[vix];
    if (rec.kind != PacketKind::IriMovement || !payloadHasAnkamaIri(rec.rawPayload)) {
        QMessageBox::warning(this, QStringLiteral("Plantilla"),
                             QStringLiteral("Solo paquetes IRI (MOVIMIENTO) con ☆iri se pueden fusionar como plantilla."));
        return;
    }
    const QString dmPath = dirMapJsonPath_->text().trimmed();
    if (dmPath.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Plantilla"),
                             QStringLiteral("Indica direcciones_map.json en pestaña Avanzado."));
        return;
    }

    const QString cardinal = cardinalEs;
    IriPacketAnalysis a = analyzeIriPayload(rec.rawPayload, iriEmu_.model());
    const QByteArray raw = rec.rawPayload;
    QString preview = QStringLiteral("¿Guardar plantilla cardinal «%1» desde paquete #%2 (%3 B)?\n\nValidación ☆iri: %4")
                            .arg(cardinal)
                            .arg(rec.index)
                            .arg(raw.size())
                            .arg(a.validStrictUrl ? QStringLiteral("OK estricto")
                                                   : QStringLiteral("con advertencias · revisar detalle"));
    const QMessageBox::StandardButton ans =
        QMessageBox::question(this, QStringLiteral("Confirmar plantilla"), preview,
                             QMessageBox::Yes | QMessageBox::No,
                             QMessageBox::No);
    if (ans != QMessageBox::Yes) {
        return;
    }

    const QMessageBox::StandardButton mergeAsk =
        QMessageBox::question(
            this,
            QStringLiteral("Fusionar ejemplos_hex"),
            QStringLiteral("¿Añadir/sustituir ejemplos_hex[\"%1\"] en direcciones_map.json?").arg(cardinal),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::Yes);
    if (mergeAsk == QMessageBox::Yes) {
        QString mergeErr;
        if (!mergeEjemploHexIntoDirectionMapJson(dmPath, cardinal, raw, &mergeErr)) {
            QMessageBox::warning(this, QStringLiteral("JSON"), mergeErr);
        } else {
            appendProxyLog(QStringLiteral("[LOGS] Fusionado ejemplo_hex %1 desde paquete #%2.")
                               .arg(cardinal)
                               .arg(rec.index));
            tryLoadDirectionMapFromField(true);
        }
    }

    QString sideErr;
    if (!saveTemplatesJsonSidecar(dmPath, cardinal, raw, a, QStringLiteral("(desde tabla logs)"),
                                  &sideErr)) {
        QMessageBox::warning(this, QStringLiteral("templates.json"), sideErr);
        return;
    }
    QMessageBox::information(this, QStringLiteral("Plantilla"),
                             QStringLiteral("Guardado templates.json («%1»).").arg(cardinal));
}

void MainWindow::exportSelectedPacketAsJsonOrTxt()
{
    if (protocolLogTree_ == nullptr) {
        return;
    }
    QTreeWidgetItem* cur = protocolLogTree_->currentItem();
    if (cur == nullptr) {
        return;
    }
    const int vix = cur->data(0, kProtoVecRole).toInt();
    if (vix < 0 || vix >= protocolRecords_.size()) {
        return;
    }
    const ProtocolPacketRecord& rec = protocolRecords_[vix];
    QString path =
        QFileDialog::getSaveFileName(this, QStringLiteral("Exportar paquete"),
                                      QStringLiteral("paquete_%1.json").arg(rec.index),
                                      QStringLiteral("JSON (*.json);;Texto (*.txt);;Todos (*.*)"));
    if (path.isEmpty()) {
        return;
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::warning(this, QStringLiteral("Exportar"),
                             QStringLiteral("No se puede escribir: %1").arg(path));
        return;
    }
    if (path.endsWith(QLatin1String(".txt"), Qt::CaseInsensitive)) {
        const QString body = buildPacketAnalysisText(rec, mergedAliasRulesForAnalysis(), 512,
                                                     &idDatabase_.customNotesById());
        f.write(QStringLiteral("EXPORT paquete #%1\n%2").arg(rec.index).arg(body).toUtf8());
    } else {
        QJsonObject o;
        o.insert(QStringLiteral("number"), rec.index);
        o.insert(QStringLiteral("time_iso"), rec.received.toString(Qt::ISODateWithMs));
        o.insert(QStringLiteral("direction_client_to_server"), rec.fromClient);
        o.insert(QStringLiteral("kind"), packetKindDisplayString(rec.kind));
        o.insert(QStringLiteral("bytes"), rec.byteSize);
        QJsonArray sarr;
        for (const QString& s : rec.stringsFound) {
            sarr.append(s);
        }
        o.insert(QStringLiteral("urls"), sarr);
        QJsonArray varr;
        for (quint64 v : rec.numericIds) {
            varr.append(static_cast<double>(v));
        }
        o.insert(QStringLiteral("varints"), varr);
        o.insert(QStringLiteral("payload_hex"), QString::fromLatin1(rec.rawPayload.toHex()));
        f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));
    }
    f.close();
}

void MainWindow::showImportLogPreviewDialog(const QString& path)
{
    QFile uf(path);
    if (!uf.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, QStringLiteral("Importar"),
                             QStringLiteral("No se puede leer:\n%1").arg(QDir::toNativeSeparators(path)));
        return;
    }
    const QString text = QString::fromUtf8(uf.readAll());
    uf.close();
    QVector<QPair<bool, QByteArray>> chunks;
    QString err;
    if (!parseExportedProxyLogText(text, &chunks, &err)) {
        QMessageBox::warning(this, QStringLiteral("Importar"), err);
        return;
    }

    auto* dlg = new QDialog(this);
    dlg->setWindowTitle(QStringLiteral("Vista previa importación"));
    dlg->setMinimumSize(720, 520);
    auto* lay = new QVBoxLayout(dlg);
    lay->addWidget(new QLabel(QStringLiteral("Archivo: %1 · %2 trozos reconstruidos")
                                  .arg(QDir::toNativeSeparators(path))
                                  .arg(chunks.size())));
    auto* prv = new QPlainTextEdit;
    prv->setReadOnly(true);
    {
        auto fn = prv->font();
        fn.setFamily(QStringLiteral("Consolas"));
        prv->setFont(fn);
    }
    if (!chunks.isEmpty()) {
        ProtocolPacketRecord previewRec =
            buildRecordFromPayload(1, chunks[0].first, chunks[0].second, &packetTypeOverrides_);
        prv->setPlainText(
            buildPacketAnalysisText(previewRec, mergedAliasRulesForAnalysis(), 128, &idDatabase_.customNotesById()));
    } else {
        prv->setPlainText(QStringLiteral("(sin contenido analizable)"));
    }
    prv->setMinimumHeight(260);
    lay->addWidget(prv);
    lay->addWidget(new QLabel(QStringLiteral(
        "Se vaciarán los paquetes actuales en la tabla y se importarán todos los trozos. ¿Continuar?")));
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    bb->button(QDialogButtonBox::Ok)->setText(QStringLiteral("Importar todo"));
    connect(bb, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, dlg, &QDialog::reject);
    lay->addWidget(bb);
    if (dlg->exec() != QDialog::Accepted) {
        dlg->deleteLater();
        return;
    }
    dlg->deleteLater();

    onClearProtocolLogClicked();
    for (const auto& ch : chunks) {
        appendProtocolCaptureRecord(ch.first, ch.second);
    }
    appendProxyLog(QStringLiteral("[IMPORT] %1 trozos desde %2.")
                       .arg(chunks.size())
                       .arg(QDir::toNativeSeparators(path)));
}

bool MainWindow::protocolKindPassesVisibleFilters(PacketKind k, int comboIndex) const
{
    if (protocolMultiKindFilterChk_ != nullptr && protocolMultiKindFilterChk_->isChecked()) {
        if (protocolMultiKindPickSet_.isEmpty()) {
            return true;
        }
        return protocolMultiKindPickSet_.contains(k);
    }
    return packetKindMatchesFilterCombo(k, comboIndex);
}

void MainWindow::openProtocolKindMultiFilterDialog()
{
    QDialog dlg(this);
    dlg.setWindowTitle(QStringLiteral("Tipos de paquete visibles"));
    dlg.resize(440, 480);
    auto* lay = new QVBoxLayout(&dlg);
    lay->addWidget(new QLabel(QStringLiteral(
        "Marca los tipos que quieres ver. Todas las casillas marcadas o ninguna marcada = ver todos los tipos.")));

    auto* scroll = new QScrollArea(&dlg);
    scroll->setWidgetResizable(true);
    auto* inner = new QWidget;
    auto* vbox = new QVBoxLayout(inner);
    const QStringList labels = standardPacketKindLabels();
    QVector<QCheckBox*> cbs;
    QVector<PacketKind> kinds;
    cbs.reserve(labels.size());
    kinds.reserve(labels.size());
    const bool relaxed = protocolMultiKindPickSet_.isEmpty();
    for (const QString& lab : labels) {
        const PacketKind pk = packetKindFromDisplayLabel(lab);
        auto* cb = new QCheckBox(lab);
        cb->setChecked(relaxed || protocolMultiKindPickSet_.contains(pk));
        cbs.push_back(cb);
        kinds.push_back(pk);
        vbox->addWidget(cb);
    }
    scroll->setWidget(inner);
    lay->addWidget(scroll);

    auto* presets = new QHBoxLayout;
    auto* markAll = new QPushButton(QStringLiteral("Marcar todos"));
    auto* markNone = new QPushButton(QStringLiteral("Desmarcar todos"));
    presets->addWidget(markAll);
    presets->addWidget(markNone);
    presets->addStretch(1);
    lay->addLayout(presets);

    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    bb->button(QDialogButtonBox::Ok)->setText(QStringLiteral("Aplicar"));
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    connect(markAll, &QPushButton::clicked, &dlg, [cbs]() {
        for (QCheckBox* cb : cbs) {
            cb->setChecked(true);
        }
    });
    connect(markNone, &QPushButton::clicked, &dlg, [cbs]() {
        for (QCheckBox* cb : cbs) {
            cb->setChecked(false);
        }
    });
    lay->addWidget(bb);

    if (dlg.exec() != QDialog::Accepted) {
        return;
    }

    QSet<PacketKind> nu;
    for (int i = 0; i < cbs.size(); ++i) {
        if (cbs.at(i)->isChecked()) {
            nu.insert(kinds.at(i));
        }
    }
    if (nu.size() == cbs.size() || nu.isEmpty()) {
        protocolMultiKindPickSet_.clear();
    } else {
        protocolMultiKindPickSet_ = std::move(nu);
    }
    applyProtocolLogFilters();
}

void MainWindow::applyProtocolLogFilters()
{
    if (protocolLogTree_ == nullptr) {
        return;
    }
    const QString needle = protocolSearchEdit_ != nullptr ? protocolSearchEdit_->text().trimmed().toLower()
                                                            : QString();
    const int fil = protocolKindFilter_ != nullptr ? protocolKindFilter_->currentIndex() : 0;

    for (int i = 0; i < protocolLogTree_->topLevelItemCount(); ++i) {
        QTreeWidgetItem* it = protocolLogTree_->topLevelItem(i);
        const auto k = static_cast<PacketKind>(it->data(0, Qt::UserRole).toInt());
        const bool okKind = protocolKindPassesVisibleFilters(k, fil);
        QString rowText;
        for (int c = 0; c < protocolLogTree_->columnCount(); ++c) {
            rowText += it->text(c);
        }
        const bool okSearch = needle.isEmpty() || rowText.toLower().contains(needle);
        it->setHidden(!(okKind && okSearch));
    }
}

void MainWindow::rebuildResourcesTableFromRecords()
{
    // NO reescaneamos paquetes para la tabla de candidatos: eso reinyectaba todo el histórico del log en el último
    // mapa y anulaba la vista «solo sesión en vivo». Solo sincronizamos la etiqueta de mapa desde la cola del log.
    quint64 runningMap = 0;
    for (int i = 0; i < protocolRecords_.size(); ++i) {
        const ProtocolPacketRecord& r = protocolRecords_.at(i);
        if (packetKindUpdatesMapGuess(r.kind)) {
            const quint64 m = guessMapIdHeuristic(r.rawPayload);
            if (m != 0) {
                runningMap = m;
            }
        }
    }
    lastMapGuess_ = runningMap;
    if (mapCurrentIdLbl_ != nullptr) {
        mapCurrentIdLbl_->setText(runningMap != 0 ? QStringLiteral("Mapa actual: %1").arg(runningMap)
                                                   : QStringLiteral("Mapa actual: —"));
    }
    // Sin reescanear candidatos: vaciar para no mezclar sesión en vivo con el mapa inferido del log.
    resourceCandidateHits_.clear();
    resourceCandidateInteractedHits_.clear();
    resourceCandidateSeenOnMap_.clear();
    resourceCandidateSourceHex_.clear();
    resourceCandidateLastInteractMs_.clear();
    resourceCandidateIntroLogLabel_.clear();
    resourceCandidateInteractLogLabel_.clear();
    refreshResourceCandidatesUi();
}

void MainWindow::refreshCharacterLabels()
{
    if (characterStatusBarLbl_ == nullptr) {
        return;
    }
    const QString lv =
        characterSnap_.level > 0 ? QString::number(characterSnap_.level) : QStringLiteral("—");
    const QString pkt =
        characterSnap_.sourcePacketIndex >= 0
            ? QStringLiteral(" (desde paquete #%1)").arg(characterSnap_.sourcePacketIndex)
            : QString();
    characterStatusBarLbl_->setText(QStringLiteral("Personaje: %1 · Nivel: %2%3 · Clase: %4")
                                        .arg(characterSnap_.name.isEmpty() ? QStringLiteral("—") : characterSnap_.name)
                                        .arg(lv)
                                        .arg(pkt)
                                        .arg(characterSnap_.classLine.isEmpty() ? QStringLiteral("—")
                                                                               : characterSnap_.classLine));
}

bool MainWindow::packetKindFeedsResourceTotals(PacketKind k) const
{
    switch (k) {
    case PacketKind::IsoResources:
    case PacketKind::ItxMapHeavyServer:
    case PacketKind::MapGatherIerSnapshotServer:
    case PacketKind::MapGatherIevTapClient:
    case PacketKind::MapGatherIeuBundleServer:
        return true;
    default:
        return false;
    }
}

bool MainWindow::packetKindIntroducesResourceCandidates(PacketKind k) const
{
    switch (k) {
    case PacketKind::IsoResources:
    case PacketKind::ItxMapHeavyServer:
    case PacketKind::MapGatherIerSnapshotServer:
    case PacketKind::MapGatherIevTapClient:
    case PacketKind::MapGatherIeuBundleServer:
        return true;
    default:
        return false;
    }
}

void MainWindow::updateGatherablesFromProtobufPayload(const QByteArray& payload, PacketKind sourceKind)
{
    QList<quint64> vars;
    // Para RECO (IEU/IER) el ID de recurso a veces no aparece como varint plano.
    // Usamos wire-format para extraer varint + fixed32 + fixed64 (y anidados best-effort).
    extractProtobufWireNumericScalars(payload, &vars);
    const QVector<IdRangeRule> merged = mergedAliasRulesForAnalysis();
    // IMPORTANTE: algunos paquetes de recolección (RECO) contienen varints grandes (p. ej. 514168)
    // que NO son ID de mapa. Si usamos la heurística de mapa aquí, se “resetea” la sesión y se
    // borra la lista de candidatos al recolectar. Por eso, solo actualizamos el mapa cuando el
    // paquete realmente sea de mapa (ISO/ITX/hidrato/paso mapa).
    const bool allowMapHeuristic =
        (sourceKind == PacketKind::IsoResources || sourceKind == PacketKind::ItxMapHeavyServer
         || sourceKind == PacketKind::MapHydrateTripleServer || sourceKind == PacketKind::MapHopJnrIspClient);
    if (allowMapHeuristic) {
        const quint64 prevMap = lastMapGuess_;
        const quint64 mid = guessMapIdHeuristic(payload);
        if (mid != 0 && mid != prevMap) {
            isoMapResourceTotals_.clear();
            resourceCandidateHits_.clear();
            resourceCandidateInteractedHits_.clear();
            resourceCandidateSeenOnMap_.clear();
            resourceCandidateSourceHex_.clear();
            resourceCandidateLastInteractMs_.clear();
            resourceCandidateIntroLogLabel_.clear();
            resourceCandidateInteractLogLabel_.clear();
        }
        if (mid != 0) {
            lastMapGuess_ = mid;
            if (mapCurrentIdLbl_ != nullptr) {
                mapCurrentIdLbl_->setText(QStringLiteral("Mapa actual: %1").arg(mid));
            }
        }
    }

    QSet<QString> touchedThisIsoDisplay;
    for (quint64 id : vars) {
        QString cat;
        const QString rn = displayNameForGatherableResource(id);
        if (rn.isEmpty()) {
            if (packetKindIntroducesResourceCandidates(sourceKind)) {
                considerResourceCandidateId(id, payload, sourceKind);
            }
            if (sourceKind == PacketKind::MapGatherIevTapClient
                || sourceKind == PacketKind::MapGatherIeuBundleServer) {
                // Si llegó el toque/bundle antes del snapshot ISO/ITX/IER, forzar que exista el candidato
                // para poder mostrar (RECO · IEU/IET/IES) / (RECO · IEV TOQUE) en la tabla.
                if (!resourceCandidateHits_.contains(id)) {
                    considerResourceCandidateId(id, payload, sourceKind);
                }
                markResourceCandidateInteracted(id, sourceKind);
            }
        }
        if (!rn.isEmpty()) {
            ++isoMapResourceTotals_[rn];
            touchedThisIsoDisplay.insert(rn);
        }

        QString rowLabel = rn;
        if (rowLabel.isEmpty()) {
            QList<quint64> filt = filterResourceCandidateIds(QList<quint64>{id}, parsedAndDatabaseRulesForResourceFilter());
            if (!filt.isEmpty()) {
                rowLabel = resolveIdWithRules(id, merged, &cat);
            }
        }

        if (rowLabel.isEmpty()) {
            continue;
        }
    }

    refreshIsoResourcesSummaryUi();
    if (!touchedThisIsoDisplay.isEmpty()) {
        QStringList summaryBits;
        for (const QString& n : touchedThisIsoDisplay) {
            summaryBits << QStringLiteral("%1: %2 u.")
                             .arg(n)
                             .arg(isoMapResourceTotals_.value(n));
        }
        appendResourceSessionSnapshot(summaryBits.join(QLatin1String(" · ")));
    }
    refreshResourceCandidatesUi();
}

void MainWindow::updateResourcesFromIsoPayload(const QByteArray& payload)
{
    updateGatherablesFromProtobufPayload(payload, PacketKind::IsoResources);
}

QString MainWindow::displayNameForGatherableResource(quint64 id) const
{
    QString cat;
    const QString fromRules =
        resolveIdWithRules(id, mergedAliasRulesForAnalysis(), &cat);
    if (!fromRules.isEmpty()
        && (cat.isEmpty() || cat == QStringLiteral("recurso"))) {
        return fromRules;
    }
    if (!fromRules.isEmpty()) {
        return {};
    }
    return ResourcePredictor::predict(id);
}

void MainWindow::refreshIsoResourcesSummaryUi()
{
    // Sección ISO agregada desactivada en UI; sigue procesándose estado internamente por si la reactivamos.
    if (resourcesMapSummary_ == nullptr || !resourcesMapSummary_->isVisible()) {
        return;
    }
    if (isoMapResourceTotals_.isEmpty()) {
        resourcesMapSummary_->setHtml(QStringLiteral("<p style=\"margin:8px;color:#94a3b8;\">"
                                                     "Aún sin varints clasificados como recurso de mapa en "
                                                     "esta sesión (esperando ISO, ITX o paquetes RECO · IEU/IEV/IER).</p>"));
    } else {
        int mx = 1;
        for (int tot : isoMapResourceTotals_) {
            mx = qMax(mx, tot);
        }
        QString tbl = QStringLiteral("<table style=\"margin:8px;color:#f8fafc;border-collapse:collapse;\">");
        for (auto it = isoMapResourceTotals_.constBegin(); it != isoMapResourceTotals_.constEnd(); ++it) {
            int ticks = 1;
            if (mx > 0) {
                ticks = qBound(1, (10 * it.value() + mx - 1) / mx, 10);
            }
            QString bar;
            for (int i = 0; i < ticks; ++i) {
                bar.append(QChar(0x2588));
            }
            for (int i = ticks; i < 10; ++i) {
                bar.append(QChar(0x2591));
            }
            tbl += QStringLiteral("<tr>"
                                  "<td style=\"padding:4px 10px;color:#fcd34d;white-space:nowrap;\"><b>%1</b>"
                                  "</td>"
                                  "<td style=\"padding:4px;font-family:Consolas;font-size:12px;\">%2</td>"
                                  "<td style=\"padding:4px;color:#bbf7d0;text-align:right;\">%3 u.</td>"
                                  "</tr>")
                       .arg(it.key().toHtmlEscaped(),
                            bar,
                            QString::number(it.value()));
        }
        tbl += QStringLiteral("</table>");
        resourcesMapSummary_->setHtml(tbl);
    }
    if (resourcesMapUpdatedLbl_ != nullptr && resourcesMapUpdatedLbl_->isVisible()) {
        resourcesMapUpdatedLbl_->setText(
            QStringLiteral("Última actualización desde ISO: %1 · Mapa esperado en UI: %2")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")),
                     lastMapGuess_ != 0 ? QString::number(lastMapGuess_) : QStringLiteral("—")));
    }
}

void MainWindow::appendResourceSessionSnapshot(const QString& summaryLine)
{
    if (resourceSessionHistory_ == nullptr || !resourceSessionHistory_->isVisible()) {
        return;
    }
    QString line = QStringLiteral("[%1 · map %2] %3")
                       .arg(QTime::currentTime().toString(QStringLiteral("HH:mm:ss")),
                            lastMapGuess_ != 0 ? QString::number(lastMapGuess_) : QStringLiteral("—"),
                            summaryLine);
    resourceSessionSnapshots_.prepend(line);
    const int limit = 64;
    while (resourceSessionSnapshots_.size() > limit) {
        resourceSessionSnapshots_.removeLast();
    }
    if (resourceSessionHistory_ != nullptr) {
        resourceSessionHistory_->setPlainText(resourceSessionSnapshots_.join(QLatin1Char('\n')));
    }
}

bool MainWindow::isHeuristicResourceCandidateId(quint64 id) const
{
    // Heurística simple: IDs de recursos (en nuestros dumps) viven cerca de 513xxx–514xxx.
    // Esto captura casos como 514168 (ortiga_pregunta) aunque no exista alias/rango aún.
    if (id < 513000 || id > 515000) {
        return false;
    }
    // Si ya está en la base o en reglas de recurso, no es candidato.
    if (displayNameForGatherableResource(id).isEmpty() == false) {
        return false;
    }
    return true;
}

void MainWindow::considerResourceCandidateId(quint64 id, const QByteArray& payload, PacketKind sourceKind)
{
    if (!isHeuristicResourceCandidateId(id)) {
        return;
    }
    // Mapa del propio paquete (IER/ISO/ITX pueden ir desfasados respecto a lastMapGuess_ si no pasó hidrato).
    const quint64 midPacket = guessMapIdHeuristic(payload);
    quint64 mapKey = midPacket != 0 ? midPacket : lastMapGuess_;
    if (mapKey == 0) {
        return;
    }
    if (lastMapGuess_ != 0 && mapKey != lastMapGuess_) {
        return;
    }
    const quint64 prevSeen = resourceCandidateSeenOnMap_.value(id, 0);
    if (prevSeen != mapKey) {
        resourceCandidateSeenOnMap_[id] = mapKey;
        resourceCandidateHits_[id] = 1;
        resourceCandidateInteractedHits_.remove(id);
        resourceCandidateLastInteractMs_.remove(id);
        resourceCandidateIntroLogLabel_[id] = packetKindDisplayString(sourceKind);
        resourceCandidateInteractLogLabel_.remove(id);
        resourceCandidateSourceHex_[id] = QString::fromLatin1(payload.toHex());
    }
}

void MainWindow::markResourceCandidateInteracted(quint64 id, PacketKind sourceKind)
{
    if (!isHeuristicResourceCandidateId(id)) {
        return;
    }
    if (lastMapGuess_ == 0) {
        return;
    }
    if (resourceCandidateSeenOnMap_.value(id, 0) != lastMapGuess_) {
        return;
    }
    resourceCandidateInteractedHits_[id] = 1;
    resourceCandidateLastInteractMs_[id] = QDateTime::currentMSecsSinceEpoch();
    resourceCandidateInteractLogLabel_[id] = packetKindDisplayString(sourceKind);
}

void MainWindow::refreshResourceCandidatesUi()
{
    if (resourceCandidatesTable_ == nullptr || resourceCandidatesHintLbl_ == nullptr) {
        return;
    }

    // Compactar: quitar IDs contados en otro mapa (por si no hubo evento de cambio explícito).
    if (lastMapGuess_ != 0) {
        QList<quint64> drop;
        for (auto it = resourceCandidateHits_.constBegin(); it != resourceCandidateHits_.constEnd(); ++it) {
            const quint64 id = it.key();
            if (resourceCandidateSeenOnMap_.value(id, 0) != lastMapGuess_) {
                drop.push_back(id);
            }
        }
        for (quint64 id : drop) {
            resourceCandidateHits_.remove(id);
            resourceCandidateSeenOnMap_.remove(id);
            resourceCandidateInteractedHits_.remove(id);
            resourceCandidateSourceHex_.remove(id);
            resourceCandidateLastInteractMs_.remove(id);
            resourceCandidateIntroLogLabel_.remove(id);
            resourceCandidateInteractLogLabel_.remove(id);
        }
    }

    // IDs que ya tienen nombre en BD ya no son candidatos heurísticos (p. ej. tras guardar).
    {
        QList<quint64> dropNamed;
        for (auto it = resourceCandidateHits_.constBegin(); it != resourceCandidateHits_.constEnd(); ++it) {
            if (!isHeuristicResourceCandidateId(it.key())) {
                dropNamed.push_back(it.key());
            }
        }
        for (quint64 id : dropNamed) {
            resourceCandidateHits_.remove(id);
            resourceCandidateSeenOnMap_.remove(id);
            resourceCandidateInteractedHits_.remove(id);
            resourceCandidateSourceHex_.remove(id);
            resourceCandidateLastInteractMs_.remove(id);
            resourceCandidateIntroLogLabel_.remove(id);
            resourceCandidateInteractLogLabel_.remove(id);
        }
    }

    QVector<quint64> candIds;
    candIds.reserve(resourceCandidateHits_.size());
    for (auto it = resourceCandidateHits_.constBegin(); it != resourceCandidateHits_.constEnd(); ++it) {
        const quint64 id = it.key();
        if (lastMapGuess_ == 0) {
            continue;
        }
        if (resourceCandidateSeenOnMap_.value(id, 0) != lastMapGuess_) {
            continue;
        }
        candIds.push_back(id);
    }
    std::sort(candIds.begin(), candIds.end(), [this](quint64 a, quint64 b) {
        const bool ia = resourceCandidateInteractedHits_.value(a, 0) > 0;
        const bool ib = resourceCandidateInteractedHits_.value(b, 0) > 0;
        if (ia != ib) {
            return ia > ib;
        }
        if (ia) {
            const qint64 ta = resourceCandidateLastInteractMs_.value(a, 0);
            const qint64 tb = resourceCandidateLastInteractMs_.value(b, 0);
            if (ta != tb) {
                return ta > tb;
            }
        }
        return a < b;
    });

    resourceCandidatesTable_->setRowCount(candIds.size());
    for (int row = 0; row < candIds.size(); ++row) {
        const quint64 id = candIds.at(row);
        auto* idCell = new QTableWidgetItem(QString::number(id));
        idCell->setData(kCandTableRowKindRole, kRowKindCandidate);
        idCell->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(id)));
        const QString hinted = displayNameForGatherableResource(id);
        auto* nameCell = new QTableWidgetItem(hinted.isEmpty() ? QStringLiteral("—") : hinted);
        const QString rawIntro = resourceCandidateIntroLogLabel_.value(id);
        const QString rawTouch = resourceCandidateInteractLogLabel_.value(id);
        QString logCellText = QStringLiteral("—");
        QString logTip;
        const bool hasInteracted = resourceCandidateInteractedHits_.value(id, 0) > 0;
        if (hasInteracted) {
            const QString touchLbl =
                rawTouch.isEmpty() ? QStringLiteral("RECO · toque") : rawTouch;
            logCellText = QStringLiteral("(%1)").arg(touchLbl);
            logTip =
                rawIntro.isEmpty()
                    ? QStringLiteral("Toque RECO — en el árbol de logs coincide con tipo «%1» (filtro RECO · IEV toque).")
                          .arg(touchLbl)
                    : QStringLiteral("%1 · detectado antes en snapshot: (%2)")
                          .arg(touchLbl, rawIntro);
        } else if (!rawIntro.isEmpty()) {
            logCellText = QStringLiteral("(%1)").arg(rawIntro);
            logTip =
                QStringLiteral("Misma etiqueta que la columna «tipo» del log al capturar este snapshot.");
        }
        auto* logKindCell = new QTableWidgetItem(logCellText);
        if (!logTip.isEmpty()) {
            logKindCell->setToolTip(logTip);
        }
        const QString fullHex = resourceCandidateSourceHex_.value(id);
        QString hexDisp =
            fullHex.isEmpty() ? QStringLiteral("—")
                              : (fullHex.size() > 36 ? fullHex.left(36).append(QStringLiteral("…")) : fullHex);
        auto* hexCell = new QTableWidgetItem(hexDisp);
        hexCell->setToolTip(fullHex.isEmpty()
                                ? QStringLiteral("Sin hex de snapshot (solo se guarda desde ISO / ITX / IER snapshot).")
                                : QStringLiteral("Hex completo (primer paquete de mapa):\n%1").arg(fullHex));
        const int interacted = resourceCandidateInteractedHits_.value(id, 0);
        auto* interCell = new QTableWidgetItem(interacted > 0 ? QStringLiteral("✅") : QStringLiteral("—"));
        if (interacted > 0) {
            interCell->setToolTip(QStringLiteral("Interactuado en este mapa (paquetes RECO IEV o IEU)."));
        }
        resourceCandidatesTable_->setItem(row, 0, idCell);
        resourceCandidatesTable_->setItem(row, 1, nameCell);
        resourceCandidatesTable_->setItem(row, 2, logKindCell);
        resourceCandidatesTable_->setItem(row, 3, hexCell);
        resourceCandidatesTable_->setItem(row, 4, interCell);
    }

    resourceCandidatesHintLbl_->setText(
        QStringLiteral(
            "Mapa UI %2 · %1 candidatos: solo IDs cuyo paquete ISO/ITX/IER infiere el mismo mapa que la UI (descarta IER desfasados). "
            "Orden: interactuados más recientes primero.")
            .arg(candIds.size())
            .arg(lastMapGuess_ != 0 ? QString::number(lastMapGuess_) : QStringLiteral("—")));
}

void MainWindow::addSelectedResourceCandidateAsOverride()
{
    if (resourceCandidatesTable_ == nullptr) {
        return;
    }
    const int row = resourceCandidatesTable_->currentRow();
    if (row < 0) {
        QMessageBox::information(this, QStringLiteral("Candidatos"), QStringLiteral("Selecciona un candidato primero."));
        return;
    }
    auto* idCell = resourceCandidatesTable_->item(row, 0);
    if (idCell == nullptr) {
        return;
    }
    bool ok = false;
    const quint64 id = idCell->text().toULongLong(&ok);
    if (!ok || id == 0) {
        return;
    }

    const QString name = promptPickResourceDisplayName(id);
    if (name.trimmed().isEmpty()) {
        return;
    }

    const QString srcHex = resourceCandidateSourceHex_.value(id);
    if (!srcHex.isEmpty()) {
        auto cap = idDatabase_.resourceCaptureHex();
        cap[id] = srcHex;
        idDatabase_.setResourceCaptureHex(cap);
    }
    {
        QString detail = QStringLiteral("origen=%1; interacción=%2; mapa_ui=%3")
                             .arg(resourceCandidateIntroLogLabel_.value(id, QStringLiteral("—")),
                                  resourceCandidateInteractLogLabel_.value(id, QStringLiteral("—")),
                                  lastMapGuess_ != 0 ? QString::number(lastMapGuess_) : QStringLiteral("—"));
        auto det = idDatabase_.resourceCaptureDetail();
        det[id] = detail;
        idDatabase_.setResourceCaptureDetail(det);
    }

    auto res = idDatabase_.resourceOverrides();
    res[id] = name.trimmed();
    idDatabase_.setResourceOverrides(res);
    QString err;
    if (!idDatabase_.saveToFile(IdDatabase::defaultStoragePath(), &err)) {
        QMessageBox::warning(this, QStringLiteral("Guardar"), err);
        return;
    }
    resourceCandidateHits_.remove(id);
    resourceCandidateSeenOnMap_.remove(id);
    resourceCandidateInteractedHits_.remove(id);
    resourceCandidateSourceHex_.remove(id);
    resourceCandidateLastInteractMs_.remove(id);
    resourceCandidateIntroLogLabel_.remove(id);
    resourceCandidateInteractLogLabel_.remove(id);
    reloadIdDatabaseFromDisk();
    refreshProtocolDetailFromSelection();
    refreshSavedResMonUi();
    statusBar()->showMessage(QStringLiteral("Recurso guardado: %1 → %2").arg(id).arg(name.trimmed()), 4500);
}

void MainWindow::addSelectedResourceCandidateAsMonster()
{
    if (resourceCandidatesTable_ == nullptr) {
        return;
    }
    const int row = resourceCandidatesTable_->currentRow();
    if (row < 0) {
        QMessageBox::information(this, QStringLiteral("Candidatos"), QStringLiteral("Selecciona un candidato primero."));
        return;
    }
    auto* idCell = resourceCandidatesTable_->item(row, 0);
    if (idCell == nullptr) {
        return;
    }
    bool ok = false;
    const quint64 id = idCell->text().toULongLong(&ok);
    if (!ok || id == 0) {
        return;
    }

    const QString name = promptPickMonsterDisplayName(id);
    if (name.trimmed().isEmpty()) {
        return;
    }

    const QString srcHex = resourceCandidateSourceHex_.value(id);
    if (!srcHex.isEmpty()) {
        auto cap = idDatabase_.monsterCaptureHex();
        cap[id] = srcHex;
        idDatabase_.setMonsterCaptureHex(cap);
    }
    {
        QString detail = QStringLiteral("origen=%1; interacción=%2; mapa_ui=%3")
                             .arg(resourceCandidateIntroLogLabel_.value(id, QStringLiteral("—")),
                                  resourceCandidateInteractLogLabel_.value(id, QStringLiteral("—")),
                                  lastMapGuess_ != 0 ? QString::number(lastMapGuess_) : QStringLiteral("—"));
        auto det = idDatabase_.monsterCaptureDetail();
        det[id] = detail;
        idDatabase_.setMonsterCaptureDetail(det);
    }

    auto mon = idDatabase_.monsterNames();
    mon[id] = name.trimmed();
    idDatabase_.setMonsterNames(mon);
    QString err;
    if (!idDatabase_.saveToFile(IdDatabase::defaultStoragePath(), &err)) {
        QMessageBox::warning(this, QStringLiteral("Guardar"), err);
        return;
    }
    resourceCandidateHits_.remove(id);
    resourceCandidateSeenOnMap_.remove(id);
    resourceCandidateInteractedHits_.remove(id);
    resourceCandidateSourceHex_.remove(id);
    resourceCandidateLastInteractMs_.remove(id);
    resourceCandidateIntroLogLabel_.remove(id);
    resourceCandidateInteractLogLabel_.remove(id);
    reloadIdDatabaseFromDisk();
    refreshProtocolDetailFromSelection();
    refreshSavedResMonUi();
    statusBar()->showMessage(QStringLiteral("Monstruo guardado: %1 → %2").arg(id).arg(name.trimmed()), 4500);
}

void MainWindow::hideSelectedResourceCandidate()
{
    if (resourceCandidatesTable_ == nullptr) {
        return;
    }
    const int row = resourceCandidatesTable_->currentRow();
    if (row < 0) {
        return;
    }
    auto* idCell = resourceCandidatesTable_->item(row, 0);
    if (idCell == nullptr) {
        return;
    }
    bool ok = false;
    const quint64 id = idCell->text().toULongLong(&ok);
    if (!ok || id == 0) {
        return;
    }
    resourceCandidateHits_.remove(id);
    resourceCandidateSeenOnMap_.remove(id);
    resourceCandidateInteractedHits_.remove(id);
    resourceCandidateSourceHex_.remove(id);
    resourceCandidateLastInteractMs_.remove(id);
    resourceCandidateIntroLogLabel_.remove(id);
    resourceCandidateInteractLogLabel_.remove(id);
    refreshResourceCandidatesUi();
}

void MainWindow::removeInteractedResourceCandidates()
{
    QList<quint64> drop;
    for (auto it = resourceCandidateInteractedHits_.constBegin(); it != resourceCandidateInteractedHits_.constEnd();
         ++it) {
        if (it.value() > 0) {
            drop.push_back(it.key());
        }
    }
    for (quint64 id : drop) {
        resourceCandidateHits_.remove(id);
        resourceCandidateSeenOnMap_.remove(id);
        resourceCandidateInteractedHits_.remove(id);
        resourceCandidateSourceHex_.remove(id);
        resourceCandidateLastInteractMs_.remove(id);
        resourceCandidateIntroLogLabel_.remove(id);
        resourceCandidateInteractLogLabel_.remove(id);
    }
    refreshResourceCandidatesUi();
    statusBar()->showMessage(
        QStringLiteral("Quitados %1 candidatos interactuados.").arg(drop.size()), 3500);
}

QString MainWindow::promptPickResourceDisplayName(quint64 id)
{
    QDialog dlg(this);
    dlg.setWindowTitle(QStringLiteral("Guardar recurso"));
    dlg.setMinimumWidth(420);
    auto* lay = new QVBoxLayout(&dlg);
    lay->addWidget(new QLabel(QStringLiteral(
        "ID %1 — elegí un nombre ya guardado en «recursos» para reutilizar la etiqueta en otro ID, "
        "o escribí uno nuevo en el campo editable.")
                                    .arg(QString::number(id))));
    auto* combo = new QComboBox;
    combo->setEditable(true);
    combo->setMinimumWidth(400);
    QSet<QString> uniq;
    for (auto it = idDatabase_.resourceOverrides().constBegin(); it != idDatabase_.resourceOverrides().constEnd();
         ++it) {
        const QString s = it.value().trimmed();
        if (!s.isEmpty()) {
            uniq.insert(s);
        }
    }
    QStringList items = uniq.values();
    items.sort(Qt::CaseInsensitive);
    combo->addItems(items);
    combo->setCurrentText(QStringLiteral("Recurso %1").arg(id));
    lay->addWidget(combo);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    lay->addWidget(bb);
    if (dlg.exec() != QDialog::Accepted) {
        return {};
    }
    return combo->currentText().trimmed();
}

QString MainWindow::promptPickMonsterDisplayName(quint64 id)
{
    QDialog dlg(this);
    dlg.setWindowTitle(QStringLiteral("Guardar monstruo"));
    dlg.setMinimumWidth(420);
    auto* lay = new QVBoxLayout(&dlg);
    lay->addWidget(new QLabel(QStringLiteral(
        "ID %1 — elegí un nombre ya guardado en «monstruos» o escribí uno nuevo.")
                                    .arg(QString::number(id))));
    auto* combo = new QComboBox;
    combo->setEditable(true);
    combo->setMinimumWidth(400);
    QSet<QString> uniq;
    for (auto it = idDatabase_.monsterNames().constBegin(); it != idDatabase_.monsterNames().constEnd(); ++it) {
        const QString s = it.value().trimmed();
        if (!s.isEmpty()) {
            uniq.insert(s);
        }
    }
    QStringList items = uniq.values();
    items.sort(Qt::CaseInsensitive);
    combo->addItems(items);
    combo->setCurrentText(QStringLiteral("Monstruo %1").arg(id));
    lay->addWidget(combo);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    lay->addWidget(bb);
    if (dlg.exec() != QDialog::Accepted) {
        return {};
    }
    return combo->currentText().trimmed();
}

void MainWindow::promptSaveIdFromPacketDetail(quint64 id)
{
    if (id == 0) {
        return;
    }
    // Guardamos con hex + detalle desde el paquete actualmente seleccionado.
    ProtocolPacketRecord curRec;
    bool haveCurRec = false;
    if (protocolLogTree_ != nullptr && protocolLogTree_->currentItem() != nullptr) {
        const int vix = protocolLogTree_->currentItem()->data(0, kProtoVecRole).toInt();
        if (vix >= 0 && vix < protocolRecords_.size()) {
            curRec = protocolRecords_.at(vix);
            haveCurRec = true;
        }
    }
    QMenu menu(this);
    QAction* actRes =
        menu.addAction(QStringLiteral("💾 Guardar como recurso…"));
    QAction* actMon =
        menu.addAction(QStringLiteral("👾 Guardar como monstruo…"));
    QAction* chosen = menu.exec(QCursor::pos());
    if (chosen == nullptr) {
        return;
    }
    auto saveName = [this, id, haveCurRec, curRec](bool asMonster) -> bool {
        const QString name =
            asMonster ? promptPickMonsterDisplayName(id) : promptPickResourceDisplayName(id);
        if (name.trimmed().isEmpty()) {
            return false;
        }
        QString err;
        if (asMonster) {
            auto mon = idDatabase_.monsterNames();
            mon[id] = name.trimmed();
            idDatabase_.setMonsterNames(mon);
            if (haveCurRec) {
                auto hx = idDatabase_.monsterCaptureHex();
                hx[id] = QString::fromLatin1(curRec.rawPayload.toHex());
                idDatabase_.setMonsterCaptureHex(hx);
                auto det = idDatabase_.monsterCaptureDetail();
                QString body = buildPacketAnalysisText(curRec, mergedAliasRulesForAnalysis(), 512,
                                                      &idDatabase_.customNotesById());
                ProtobufParser parser;
                const QString ctx = !curRec.primaryUrl.isEmpty() ? curRec.primaryUrl : detectPacketContext(curRec.rawPayload);
                const QList<ProtoField> fields = parser.parse(curRec.rawPayload);
                if (!fields.isEmpty()) {
                    QString proto = formatProtoFields(fields, 0, ctx);
                    if (!proto.trimmed().isEmpty()) {
                        body += QStringLiteral("\n\n📦 ESTRUCTURA PROTOBUF (indentada):\n");
                        body += proto;
                    }
                }
                const int maxChars = 20000;
                if (body.size() > maxChars) {
                    body = body.left(maxChars) + QStringLiteral("\n… (truncado)\n");
                }
                det[id] = body;
                idDatabase_.setMonsterCaptureDetail(det);
            }
        } else {
            auto res = idDatabase_.resourceOverrides();
            res[id] = name.trimmed();
            idDatabase_.setResourceOverrides(res);
            if (haveCurRec) {
                auto hx = idDatabase_.resourceCaptureHex();
                hx[id] = QString::fromLatin1(curRec.rawPayload.toHex());
                idDatabase_.setResourceCaptureHex(hx);
                auto det = idDatabase_.resourceCaptureDetail();
                QString body = buildPacketAnalysisText(curRec, mergedAliasRulesForAnalysis(), 512,
                                                      &idDatabase_.customNotesById());
                ProtobufParser parser;
                const QString ctx = !curRec.primaryUrl.isEmpty() ? curRec.primaryUrl : detectPacketContext(curRec.rawPayload);
                const QList<ProtoField> fields = parser.parse(curRec.rawPayload);
                if (!fields.isEmpty()) {
                    QString proto = formatProtoFields(fields, 0, ctx);
                    if (!proto.trimmed().isEmpty()) {
                        body += QStringLiteral("\n\n📦 ESTRUCTURA PROTOBUF (indentada):\n");
                        body += proto;
                    }
                }
                const int maxChars = 20000;
                if (body.size() > maxChars) {
                    body = body.left(maxChars) + QStringLiteral("\n… (truncado)\n");
                }
                det[id] = body;
                idDatabase_.setResourceCaptureDetail(det);
            }
        }
        if (!idDatabase_.saveToFile(IdDatabase::defaultStoragePath(), &err)) {
            QMessageBox::warning(this, QStringLiteral("Guardar"), err);
            return false;
        }
        statusBar()->showMessage(QStringLiteral("Guardado ID %1 · %2").arg(id).arg(name.trimmed()), 4500);
        return true;
    };
    if (chosen == actRes) {
        if (!saveName(false)) {
            return;
        }
    } else if (chosen == actMon) {
        if (!saveName(true)) {
            return;
        }
    } else {
        return;
    }
    resourceCandidateHits_.remove(id);
    resourceCandidateSeenOnMap_.remove(id);
    resourceCandidateInteractedHits_.remove(id);
    resourceCandidateSourceHex_.remove(id);
    resourceCandidateLastInteractMs_.remove(id);
    resourceCandidateIntroLogLabel_.remove(id);
    resourceCandidateInteractLogLabel_.remove(id);
    reloadIdDatabaseFromDisk();
    refreshProtocolDetailFromSelection();
}

void MainWindow::refreshSavedResMonUi()
{
    if (savedResMonTable_ == nullptr) {
        return;
    }
    struct Row {
        QString kind;
        quint64 id = 0;
        QString name;
    };
    QVector<Row> rows;
    rows.reserve(idDatabase_.resourceOverrides().size() + idDatabase_.monsterNames().size());
    for (auto it = idDatabase_.resourceOverrides().constBegin(); it != idDatabase_.resourceOverrides().constEnd(); ++it) {
        rows.push_back(Row{QStringLiteral("recurso"), it.key(), it.value()});
    }
    for (auto it = idDatabase_.monsterNames().constBegin(); it != idDatabase_.monsterNames().constEnd(); ++it) {
        rows.push_back(Row{QStringLiteral("monstruo"), it.key(), it.value()});
    }
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        if (a.kind != b.kind) return a.kind < b.kind;
        if (a.name != b.name) return a.name < b.name;
        return a.id < b.id;
    });

    savedResMonTable_->setRowCount(rows.size());
    for (int i = 0; i < rows.size(); ++i) {
        savedResMonTable_->setItem(i, 0, new QTableWidgetItem(rows.at(i).kind));
        savedResMonTable_->setItem(i, 1, new QTableWidgetItem(QString::number(rows.at(i).id)));
        auto* nameIt = new QTableWidgetItem(rows.at(i).name);
        const quint64 rid = rows.at(i).id;
        QString tip;
        if (rows.at(i).kind == QStringLiteral("recurso")) {
            const QString hx = idDatabase_.resourceCaptureHex().value(rid);
            if (!hx.isEmpty()) {
                tip = QStringLiteral("Hex de captura (recurso):\n%1")
                          .arg(hx.size() > 900 ? hx.left(900).append(QStringLiteral("…")) : hx);
            }
            const QString det = idDatabase_.resourceCaptureDetail().value(rid);
            if (!det.isEmpty()) {
                tip += QStringLiteral("\n\nDetalle:\n%1")
                           .arg(det.size() > 2200 ? det.left(2200).append(QStringLiteral("\n…")) : det);
            }
        } else if (rows.at(i).kind == QStringLiteral("monstruo")) {
            const QString hx = idDatabase_.monsterCaptureHex().value(rid);
            if (!hx.isEmpty()) {
                tip = QStringLiteral("Hex de captura (monstruo):\n%1")
                          .arg(hx.size() > 900 ? hx.left(900).append(QStringLiteral("…")) : hx);
            }
            const QString det = idDatabase_.monsterCaptureDetail().value(rid);
            if (!det.isEmpty()) {
                tip += QStringLiteral("\n\nDetalle:\n%1")
                           .arg(det.size() > 2200 ? det.left(2200).append(QStringLiteral("\n…")) : det);
            }
        }
        if (!tip.isEmpty()) {
            nameIt->setToolTip(tip);
        }
        savedResMonTable_->setItem(i, 2, nameIt);
    }
}

void MainWindow::addSavedResourceDialog()
{
    bool ok = false;
    const quint64 id = QInputDialog::getInt(this, QStringLiteral("Agregar recurso"), QStringLiteral("ID:"), 0, 0, INT_MAX, 1, &ok);
    if (!ok || id == 0) return;
    const QString name = QInputDialog::getText(this, QStringLiteral("Agregar recurso"), QStringLiteral("Nombre:"), QLineEdit::Normal);
    if (name.trimmed().isEmpty()) return;
    auto res = idDatabase_.resourceOverrides();
    res[id] = name.trimmed();
    idDatabase_.setResourceOverrides(res);
    QString err;
    if (!idDatabase_.saveToFile(IdDatabase::defaultStoragePath(), &err)) {
        QMessageBox::warning(this, QStringLiteral("Guardar"), err);
        return;
    }
    reloadIdDatabaseFromDisk();
    refreshSavedResMonUi();
}

void MainWindow::addSavedMonsterDialog()
{
    bool ok = false;
    const quint64 id = QInputDialog::getInt(this, QStringLiteral("Agregar monstruo"), QStringLiteral("ID:"), 0, 0, INT_MAX, 1, &ok);
    if (!ok || id == 0) return;
    const QString name = QInputDialog::getText(this, QStringLiteral("Agregar monstruo"), QStringLiteral("Nombre:"), QLineEdit::Normal);
    if (name.trimmed().isEmpty()) return;
    auto mon = idDatabase_.monsterNames();
    mon[id] = name.trimmed();
    idDatabase_.setMonsterNames(mon);
    QString err;
    if (!idDatabase_.saveToFile(IdDatabase::defaultStoragePath(), &err)) {
        QMessageBox::warning(this, QStringLiteral("Guardar"), err);
        return;
    }
    reloadIdDatabaseFromDisk();
    refreshSavedResMonUi();
}

void MainWindow::removeSelectedSavedEntry()
{
    if (savedResMonTable_ == nullptr) return;
    const int row = savedResMonTable_->currentRow();
    if (row < 0) return;
    auto* kindCell = savedResMonTable_->item(row, 0);
    auto* idCell = savedResMonTable_->item(row, 1);
    if (!kindCell || !idCell) return;
    const QString kind = kindCell->text();
    bool ok = false;
    const quint64 id = idCell->text().toULongLong(&ok);
    if (!ok || id == 0) return;
    if (QMessageBox::question(this, QStringLiteral("Eliminar"),
                              QStringLiteral("¿Eliminar %1 ID %2?").arg(kind).arg(id))
        != QMessageBox::Yes) {
        return;
    }
    if (kind == QStringLiteral("recurso")) {
        auto res = idDatabase_.resourceOverrides();
        res.remove(id);
        idDatabase_.setResourceOverrides(res);
        auto hx = idDatabase_.resourceCaptureHex();
        hx.remove(id);
        idDatabase_.setResourceCaptureHex(hx);
        auto det = idDatabase_.resourceCaptureDetail();
        det.remove(id);
        idDatabase_.setResourceCaptureDetail(det);
    } else if (kind == QStringLiteral("monstruo")) {
        auto mon = idDatabase_.monsterNames();
        mon.remove(id);
        idDatabase_.setMonsterNames(mon);
        auto hx = idDatabase_.monsterCaptureHex();
        hx.remove(id);
        idDatabase_.setMonsterCaptureHex(hx);
        auto det = idDatabase_.monsterCaptureDetail();
        det.remove(id);
        idDatabase_.setMonsterCaptureDetail(det);
    } else {
        return;
    }
    QString err;
    if (!idDatabase_.saveToFile(IdDatabase::defaultStoragePath(), &err)) {
        QMessageBox::warning(this, QStringLiteral("Guardar"), err);
        return;
    }
    reloadIdDatabaseFromDisk();
    refreshSavedResMonUi();
}

void MainWindow::exportGatheredResourcesCsvDialog()
{
    if (isoMapResourceTotals_.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("CSV"),
                                 QStringLiteral("Sin datos agregados todavía (captura ISO primero)."));
        return;
    }
    QString path = QFileDialog::getSaveFileName(
        this, QStringLiteral("Exportar recursos en mapa actual"),
        QDir(QCoreApplication::applicationDirPath())
            .filePath(QStringLiteral("recursos_mapa_%1.csv").arg(lastMapGuess_ != 0
                                                                    ? QString::number(lastMapGuess_)
                                                                    : QLatin1String("sin_mapa"))),
        QStringLiteral("CSV (*.csv);;Todos (*.*)"));
    if (path.isEmpty()) {
        return;
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::warning(this, QStringLiteral("CSV"),
                             QStringLiteral("No se pudo crear el archivo."));
        return;
    }
    QTextStream sw(&f);
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    sw.setEncoding(QStringConverter::Utf8);
#else
    sw.setCodec("UTF-8");
#endif
    sw << "map_id;recurso;cantidad\n";
    const QString mapTok =
        lastMapGuess_ != 0 ? QString::number(lastMapGuess_) : QLatin1String("desconocido");
    for (auto it = isoMapResourceTotals_.constBegin(); it != isoMapResourceTotals_.constEnd(); ++it) {
        sw << mapTok << QLatin1Char(';') << it.key() << QLatin1Char(';') << it.value() << QLatin1Char('\n');
    }
    f.close();
    appendProxyLog(QStringLiteral("[CSV] Recursos exportados a %1")
                       .arg(QDir::toNativeSeparators(path)));
}

void MainWindow::librarySearchAcrossExportedLogs()
{
    if (librarySearchEdit_ == nullptr || librarySearchResults_ == nullptr) {
        return;
    }
    const QString needleRaw = librarySearchEdit_->text();
    librarySearchResults_->clear();
    if (needleRaw.trimmed().isEmpty()) {
        return;
    }
    const QString needle = needleRaw.trimmed().toLower();
    const QString dirPath =
        QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QStringLiteral("exported_logs"));
    const QFileInfoList infos =
        QDir(dirPath).entryInfoList(QStringList(QStringLiteral("*.txt")), QDir::Files);
    constexpr int limitItems = 200;
    int added = 0;
    const QRegularExpression reNeedle(QRegularExpression::escape(needleRaw.trimmed()),
                                    QRegularExpression::CaseInsensitiveOption);
    for (const QFileInfo& fi : infos) {
        if (added >= limitItems) {
            break;
        }
        QFile f(fi.absoluteFilePath());
        if (!f.open(QIODevice::ReadOnly)) {
            continue;
        }
        qint64 lineno = 0;
        QTextStream ss(&f);
        while (!ss.atEnd()) {
            const QString line = ss.readLine();
            ++lineno;
            if (line.contains(reNeedle) || line.toLower().contains(needle)) {
                auto* it = new QListWidgetItem(QStringLiteral("%1:L%2: %3")
                                                    .arg(fi.fileName())
                                                    .arg(lineno)
                                                    .arg(line.trimmed().left(160)));
                it->setData(Qt::UserRole + 101, fi.absoluteFilePath());
                librarySearchResults_->addItem(it);
                ++added;
                if (added >= limitItems) {
                    break;
                }
            }
        }
    }
}

void MainWindow::importExportedLogFromPath(const QString& path)
{
    if (path.trimmed().isEmpty() || !QFile::exists(path)) {
        QMessageBox::warning(this, QStringLiteral("Importar"), QStringLiteral("Archivo inválido o inexistente."));
        return;
    }
    showImportLogPreviewDialog(path);
}

void MainWindow::updateIrxQuickClassifyUi(int vecIndex)
{
    if (irxClassifyFrame_ == nullptr || irxIdCombo_ == nullptr) {
        return;
    }
    if (vecIndex < 0 || vecIndex >= protocolRecords_.size()) {
        irxClassifyFrame_->setVisible(false);
        return;
    }
    const ProtocolPacketRecord& rec = protocolRecords_[vecIndex];
    if (rec.kind != PacketKind::IrxMonsters && rec.kind != PacketKind::IslEntities) {
        irxClassifyFrame_->setVisible(false);
        return;
    }
    IrxVarintBuckets b = classifyIrxStyleVarints(rec.numericIds);
    irxIdCombo_->clear();
    QList<quint64> prio;
    prio += b.monsters;
    prio += b.players;
    prio += b.other;
    prio += b.structure;
    for (quint64 id : prio) {
        QString tag;
        if (id >= 1000000ULL) {
            tag = QStringLiteral("≥1M");
        } else if (id >= 1000ULL && id <= 9999ULL) {
            tag = QStringLiteral("jug?");
        } else if (id < 1000ULL) {
            tag = QStringLiteral("est.");
        }
        irxIdCombo_->addItem(QStringLiteral("%1 — %2").arg(QString::number(id)).arg(tag),
                             QString::number(id));
    }
    irxClassifyFrame_->setVisible(!prio.isEmpty());
}

void MainWindow::persistSelectedIrxId(bool asMonster)
{
    if (irxIdCombo_ == nullptr || irxNameEdit_ == nullptr) {
        return;
    }
    bool ok = false;
    const quint64 id = irxIdCombo_->currentData().toString().toULongLong(&ok);
    if (!ok || id == 0) {
        return;
    }
    QString name = irxNameEdit_->text().trimmed();
    if (name.isEmpty()) {
        name = asMonster ? QStringLiteral("Monstruo %1").arg(QString::number(id))
                         : QStringLiteral("Personaje %1").arg(QString::number(id));
    }
    auto mon = idDatabase_.monsterNames();
    auto pl = idDatabase_.playerNames();
    if (asMonster) {
        mon[id] = name;
        pl.remove(id);
    } else {
        pl[id] = name;
        mon.remove(id);
    }
    idDatabase_.setMonsterNames(mon);
    idDatabase_.setPlayerNames(pl);

    QString err;
    if (!idDatabase_.saveToFile(IdDatabase::defaultStoragePath(), &err)) {
        QMessageBox::warning(this, QStringLiteral("IDS"), err);
        return;
    }
    reloadIdDatabaseFromDisk();
    refreshProtocolDetailFromSelection();
    if (protocolLogTree_ != nullptr && protocolLogTree_->currentItem() != nullptr) {
        const int vix = protocolLogTree_->currentItem()->data(0, kProtoVecRole).toInt();
        if (vix >= 0 && vix < protocolRecords_.size()) {
            syncProtocolTreeItemFromRecord(vix);
        }
    }
    refreshResourceCandidatesUi();
    statusBar()->showMessage(QStringLiteral("ID %2 guardado como %1.")
                                 .arg(asMonster ? QStringLiteral("monstruo") : QStringLiteral("personaje"))
                                 .arg(id),
                             4500);
}

void MainWindow::onProtocolPayloadCaptured(bool fromClient, const QByteArray& payload)
{
    if (protocolPauseTableCaptureChk_ != nullptr && protocolPauseTableCaptureChk_->isChecked()) {
        return;
    }
    appendProtocolCaptureRecord(fromClient, payload);
}

void MainWindow::appendProtocolCaptureRecord(bool fromClient, const QByteArray& payload)
{
    ++protocolPacketSeq_;
    ProtocolPacketRecord r = buildRecordFromPayload(protocolPacketSeq_, fromClient, payload, &packetTypeOverrides_);
    protocolRecords_.push_back(r);
    appendProtocolTreeItem(r, protocolRecords_.size() - 1);
    applyProtocolLogFilters();

    if (packetKindFeedsResourceTotals(r.kind)) {
        updateGatherablesFromProtobufPayload(payload, r.kind);
    }

    if (r.kind == PacketKind::IrxMonsters && monstersMapLbl_ != nullptr) {
        monstersMapLbl_->setText(QStringLiteral("Monstruos (IRX): %1")
                                     .arg(formatIrxMonsterSummaryLine(r, mergedAliasRulesForAnalysis())));
    }

    if (harvestAwaitingIdr_ && !fromClient && r.kind == PacketKind::IdrItemReceived) {
        harvestAwaitingIdr_ = false;
        if (harvestWatchTimer_ != nullptr) {
            harvestWatchTimer_->stop();
        }
        if (harvestStatusLbl_ != nullptr) {
            harvestStatusLbl_->setText(QStringLiteral("✅ Recolección exitosa (IDR)."));
        }
        appendProxyLog(
            QStringLiteral("[RECOLECTA] IDR recibido — paquete #%1.").arg(protocolPacketSeq_));
    }

    if (!fromClient) {
        ++serverPayloadOrdinal_;
        guessCharacterFromServerPayload(payload, protocolPacketSeq_, &characterSnap_);
        refreshCharacterLabels();
    }
}

void MainWindow::onRefreshResourcesFromLogsClicked()
{
    rebuildResourcesTableFromRecords();
}

void MainWindow::onImportExportedLogClicked()
{
    const QString path =
        QFileDialog::getOpenFileName(this, QStringLiteral("Importar log exportado"),
                                     QString(), QStringLiteral("Texto (*.txt);;Todos (*.*)"));
    if (path.isEmpty()) {
        return;
    }
    showImportLogPreviewDialog(path);
}

void MainWindow::onClearProtocolLogClicked()
{
    protocolRecords_.clear();
    protocolPacketSeq_ = 0;
    serverPayloadOrdinal_ = 0;
    lastMapGuess_ = 0;
    characterSnap_ = CharacterSnapshot();
    if (protocolLogTree_ != nullptr) {
        protocolLogTree_->clear();
    }
    if (monstersMapLbl_ != nullptr) {
        monstersMapLbl_->setText(QStringLiteral("Monstruos (IRX): —"));
    }
    if (protocolDetailText_ != nullptr) {
        protocolDetailText_->clear();
    }
    isoMapResourceTotals_.clear();
    resourceSessionSnapshots_.clear();
    if (resourceSessionHistory_ != nullptr) {
        resourceSessionHistory_->clear();
    }
    refreshIsoResourcesSummaryUi();
    updateIrxQuickClassifyUi(-1);
    if (mapCurrentIdLbl_ != nullptr) {
        mapCurrentIdLbl_->setText(QStringLiteral("Mapa actual: —"));
    }
    refreshCharacterLabels();
    resourceCandidateHits_.clear();
    resourceCandidateInteractedHits_.clear();
    resourceCandidateSeenOnMap_.clear();
    resourceCandidateSourceHex_.clear();
    resourceCandidateLastInteractMs_.clear();
    resourceCandidateIntroLogLabel_.clear();
    resourceCandidateInteractLogLabel_.clear();
    refreshResourceCandidatesUi();
}

void MainWindow::onProtocolFilterChanged()
{
    applyProtocolLogFilters();
}

#ifdef Q_OS_WIN
void MainWindow::appendMonitorLine(const QString& body)
{
    appendProxyLog(QStringLiteral("[MONITOR] ").append(body));
}

QString MainWindow::defaultRedirectDllPath() const
{
    const QString desktopCandidate =
        QDir::toNativeSeparators(QDir::home().absoluteFilePath(QStringLiteral("Desktop/DofusRedirect.dll")));
    if (QFileInfo::exists(desktopCandidate)) {
        return desktopCandidate;
    }
    return QDir::toNativeSeparators(
        QFileInfo(QCoreApplication::applicationDirPath() + QStringLiteral("/DofusRedirect.dll"))
            .absoluteFilePath());
}

QString MainWindow::defaultTestDllPath() const
{
    return QDir::toNativeSeparators(
        QFileInfo(QCoreApplication::applicationDirPath() + QStringLiteral("/DofusTestDll.dll"))
                      .absoluteFilePath());
}

void MainWindow::onApplyHostsClicked()
{
    const QString path = systemHostsFilePath();
    QFile hf(path);
    if (!hf.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(
            this, QStringLiteral("Archivo hosts"),
            QStringLiteral("No se pudo leer %1. Ejecuta el programa como administrador.").arg(path));
        return;
    }
    QString all = QString::fromUtf8(hf.readAll());
    hf.close();

    const QString bak = hostsBackupFilePath();
    if (!QFile::exists(bak)) {
        QFile bf(bak);
        if (!bf.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QMessageBox::critical(
                this, QStringLiteral("Archivo hosts"),
                QStringLiteral("No se pudo crear la copia de seguridad %1 (permisos de administrador).").arg(bak));
            return;
        }
        bf.write(all.toUtf8());
        bf.close();
        appendProxyLog(QStringLiteral("[HOSTS] Copia de seguridad: ") + QDir::toNativeSeparators(bak));
    }

    appendOrReplaceHostsBlock(&all);

    QFile out(path);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::critical(
            this, QStringLiteral("Archivo hosts"),
            QStringLiteral("No se pudo escribir %1. Ejecuta el programa como administrador.").arg(path));
        return;
    }
    out.write(all.toUtf8());
    out.close();
    appendProxyLog(QStringLiteral("[HOSTS] Bloque aplicado (127.0.0.1 → dominios Ankama). Reinicia Dofus; proxy en "
                                    "127.0.0.1:5555."));
    QMessageBox::information(this, QStringLiteral("Archivo hosts"),
                               QStringLiteral("Listo. Deja el proxy escuchando en 127.0.0.1:5555 y reinicia Dofus."));
}

void MainWindow::onRestoreHostsClicked()
{
    const QString bak = hostsBackupFilePath();
    const QString path = systemHostsFilePath();
    if (QFile::exists(bak)) {
        QFile bf(bak);
        if (!bf.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, QStringLiteral("Archivo hosts"),
                                 QStringLiteral("No se pudo leer la copia de seguridad."));
            return;
        }
        const QByteArray raw = bf.readAll();
        bf.close();
        QFile out(path);
        if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QMessageBox::critical(
                this, QStringLiteral("Archivo hosts"),
                QStringLiteral("No se pudo escribir %1 (administrador).").arg(path));
            return;
        }
        out.write(raw);
        out.close();
        appendProxyLog(QStringLiteral("[HOSTS] Restaurado desde copia de seguridad."));
        QMessageBox::information(this, QStringLiteral("Archivo hosts"),
                                 QStringLiteral("hosts restaurado desde la copia de seguridad."));
        return;
    }

    QFile hf(path);
    if (!hf.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(
            this, QStringLiteral("Archivo hosts"),
            QStringLiteral("No se pudo leer %1 (administrador).").arg(path));
        return;
    }
    QString all = QString::fromUtf8(hf.readAll());
    hf.close();
    if (!stripHostsProxyBlock(&all)) {
        QMessageBox::information(
            this, QStringLiteral("Archivo hosts"),
            QStringLiteral("No hay copia %1 y no se encontró el bloque marcado en hosts.")
                .arg(QDir::toNativeSeparators(bak)));
        return;
    }
    QFile out(path);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::critical(
            this, QStringLiteral("Archivo hosts"),
            QStringLiteral("No se pudo escribir %1 (administrador).").arg(path));
        return;
    }
    out.write(all.toUtf8());
    out.close();
    appendProxyLog(QStringLiteral("[HOSTS] Bloque marcado eliminado (sin backup previo)."));
    QMessageBox::information(this, QStringLiteral("Archivo hosts"),
                             QStringLiteral("Se quitó el bloque marcado del archivo hosts."));
}

void MainWindow::onInjectDllClicked()
{
    if (!winIsElevatedAdministrator()) {
        QMessageBox::critical(
            this,
            QStringLiteral("Administrador"),
            QStringLiteral("Hace falta «Ejecutar como administrador» para inyectar la DLL."));
        return;
    }
    quint32 gamePid = 0;
    if (!tryGetSelectedPid(&gamePid)) {
        QMessageBox::warning(this, QStringLiteral("PID"),
                             QStringLiteral("Selecciona una fila en la tabla (p. ej. Dofus.exe)."));
        return;
    }
    QString dllPath = dllPathEdit_ != nullptr ? dllPathEdit_->text().trimmed() : QString();
    if (dllPath.isEmpty()) {
        dllPath = defaultRedirectDllPath();
    }
    QString injErr;
    if (!winInjectDllIntoProcess(gamePid, dllPath, &injErr)) {
        QMessageBox::warning(this, QStringLiteral("Inyección DLL"),
                             QStringLiteral("No se pudo inyectar la DLL.\n\n%1").arg(injErr));
        return;
    }
    injectedDllPid_ = gamePid;
    appendProxyLog(QStringLiteral("[DLL+] Inyectada en PID %1 — %2")
                         .arg(gamePid)
                         .arg(QDir::toNativeSeparators(dllPath)));
    kickGamePort5555AfterInject(gamePid, true);
    if (massCloseOutboundTcpAfterInjectChk_ != nullptr && massCloseOutboundTcpAfterInjectChk_->isChecked()) {
        kickAllOutboundAfterInject(gamePid);
    }
}

void MainWindow::onInjectTestDllClicked()
{
    if (!winIsElevatedAdministrator()) {
        QMessageBox::critical(
            this,
            QStringLiteral("Administrador"),
            QStringLiteral("Hace falta «Ejecutar como administrador» para inyectar la DLL."));
        return;
    }
    quint32 gamePid = 0;
    if (!tryGetSelectedPid(&gamePid)) {
        QMessageBox::warning(this, QStringLiteral("PID"),
                             QStringLiteral("Selecciona una fila en la tabla (p. ej. Dofus.exe)."));
        return;
    }
    const QString dllPath = defaultTestDllPath();
    if (!QFileInfo::exists(dllPath)) {
        QMessageBox::warning(this, QStringLiteral("DofusTestDll.dll"),
                             QStringLiteral("No existe:\n%1\n\nCompila el proyecto; se copia junto al .exe.")
                                 .arg(QDir::toNativeSeparators(dllPath)));
        return;
    }
    QString injErr;
    if (!winInjectDllIntoProcess(gamePid, dllPath, &injErr)) {
        QMessageBox::warning(this, QStringLiteral("Inyección DLL de prueba"),
                             QStringLiteral("Fallo:\n\n%1").arg(injErr));
        appendProxyLog(QStringLiteral("[INJECT] DofusTestDll fallida PID %1 — %2").arg(gamePid).arg(injErr));
        return;
    }
    appendProxyLog(QStringLiteral(
        "[INJECT] DofusTestDll.dll inyectada en PID %1. Revisa C:\\test_dll_log.txt y C:\\dofus_debug_log.txt.")
                       .arg(gamePid));
}

void MainWindow::onManualWinsockConnectClicked()
{
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        appendProxyLog(QStringLiteral("[TEST] Test connect a 127.0.0.1:5555 resultado: FALLO (WSAStartup)"));
        return;
    }
    const SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        appendProxyLog(QStringLiteral("[TEST] Test connect a 127.0.0.1:5555 resultado: FALLO: %1")
                           .arg(WSAGetLastError()));
        WSACleanup();
        return;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5555);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    const int result =
        ::connect(s, reinterpret_cast<sockaddr*>(&addr), static_cast<int>(sizeof(addr)));
    const QString tail =
        (result == 0) ? QStringLiteral("OK") : QStringLiteral("FALLO: %1").arg(WSAGetLastError());
    appendProxyLog(QStringLiteral("[TEST] Test connect a 127.0.0.1:5555 resultado: ") + tail);
    closesocket(s);
    WSACleanup();
}

void MainWindow::onNetstat5555Clicked()
{
    auto* proc = new QProcess(this);
    connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this, proc](int /*exitCode*/, QProcess::ExitStatus /*st*/) {
                const QByteArray out = proc->readAllStandardOutput();
                const QByteArray err = proc->readAllStandardError();
                if (!out.isEmpty()) {
                    appendProxyLog(QStringLiteral("[NETSTAT]\n") + QString::fromUtf8(out));
                }
                if (!err.isEmpty()) {
                    appendProxyLog(QStringLiteral("[NETSTAT stderr]\n") + QString::fromUtf8(err));
                }
                if (out.isEmpty() && err.isEmpty()) {
                    appendProxyLog(QStringLiteral("[NETSTAT] Sin salida (¿ninguna fila para 127.0.0.1:5555?)."));
                }
                proc->deleteLater();
            });
    proc->start(QStringLiteral("cmd.exe"),
                QStringList{QStringLiteral("/c"), QStringLiteral("netstat -ano | findstr 127.0.0.1:5555")});
}

void MainWindow::kickGamePort5555AfterInject(quint32 pid, bool logIfZero)
{
    if (pid == 0) {
        return;
    }
    QString tcpErr;
    const int nk = closePidOutboundTcpOnRemotePort(pid, 5555, &tcpErr, false);
    if (nk < 0) {
        appendProxyLog(QStringLiteral("[TCP] No se pudieron abortar sockets :5555 — ")
                         + (tcpErr.isEmpty() ? QStringLiteral("(sin detalle)") : tcpErr));
        return;
    }
    if (nk > 0) {
        appendProxyLog(QStringLiteral(
            "[TCP] Cerradas %1 conexión(es) saliente(s) del PID %2 al puerto remoto 5555 (reconexión vía hook).")
                             .arg(nk)
                             .arg(pid));
    } else if (logIfZero) {
        appendProxyLog(QStringLiteral(
            "[TCP] Ningún socket IPv4 del PID %1 al remoto :5555 que cerrar (aún no conectado o ya por loopback).")
                             .arg(pid));
    }
}

void MainWindow::kickAllOutboundAfterInject(quint32 pid)
{
    if (pid == 0) {
        return;
    }
    QString tcpErr;
    const int na = closePidAllOutboundTcpConnections(pid, &tcpErr, true);
    if (na < 0) {
        appendProxyLog(QStringLiteral("[TCP] Cierre masivo saliente: error — ")
                         + (tcpErr.isEmpty() ? QStringLiteral("(sin detalle)") : tcpErr));
    } else if (na > 0) {
        appendProxyLog(QStringLiteral(
            "[TCP] Cerradas %1 conexión(es) TCP salientes IPv4 del PID %2 (se preservó loopback 127.0.0.0/8).")
                             .arg(na)
                             .arg(pid));
    }
}

QString MainWindow::buildHookDiagHtmlFromDllLog() const
{
    const QString path =
        QDir(QDir::tempPath()).absoluteFilePath(QStringLiteral("dofus_redirect_log.txt"));
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        return QStringLiteral("<span style=\"color:#f87171\">No se puede leer <code>%1</code></span>")
            .arg(path.toHtmlEscaped());
    }
    const qint64 sz = f.size();
    constexpr qint64 kTail = 32768;
    QString text;
    if (sz > kTail) {
        f.seek(sz - kTail);
        f.readLine();
        text = QString::fromUtf8(f.readAll());
    } else {
        text = QString::fromUtf8(f.readAll());
    }
    QString resumenLine;
    const QStringList lines = text.split(QLatin1Char('\n'), Qt::KeepEmptyParts);
    for (int i = lines.size() - 1; i >= 0; --i) {
        const QString t = lines.at(i).trimmed();
        if (t.contains(QStringLiteral("Resumen hooks"), Qt::CaseInsensitive)) {
            resumenLine = t;
            break;
        }
    }
    if (resumenLine.isEmpty()) {
        return QStringLiteral(
            "<p style=\"color:#fbbf24\">Aún no hay línea <code>[DLL] Resumen hooks: …</code> en el log. Inyecta la "
            "última <b>DofusRedirect.dll</b> y reinicia Dofus.</p>");
    }
    static const QString hdr = QStringLiteral("Resumen hooks:");
    const int ix = resumenLine.indexOf(hdr, 0, Qt::CaseInsensitive);
    QString payload = ix >= 0 ? resumenLine.mid(ix + hdr.length()).trimmed() : resumenLine;
    QString html = QStringLiteral("<p style=\"margin:0 0 8px 0;color:#93c5fd\"><b>Resumen DLL</b> (último en "
                                  "log)</p><table cellspacing=\"0\" cellpadding=\"4\">");
    const QStringList tok = payload.split(QLatin1Char(' '), Qt::SkipEmptyParts);
    for (const QString& p : tok) {
        const int eq = p.indexOf(QLatin1Char('='));
        if (eq <= 0) {
            continue;
        }
        const QString key = p.left(eq);
        const QString val = p.mid(eq + 1);
        const bool ok = (val.compare(QStringLiteral("OK"), Qt::CaseInsensitive) == 0);
        const QString col = ok ? QStringLiteral("#4ade80") : QStringLiteral("#fbbf24");
        html += QStringLiteral("<tr><td style=\"color:#cbd5e1\">%1</td><td style=\"color:%3;font-weight:bold\">%2</td>"
                               "</tr>")
                    .arg(key.toHtmlEscaped(), val.toHtmlEscaped(), col);
    }
    html += QStringLiteral("</table>");
    html += QStringLiteral("<p style=\"margin:8px 0 0 0;color:#9ca3af;font-size:12px\">%1</p>")
                .arg(resumenLine.toHtmlEscaped());
    return html;
}

void MainWindow::onHarvestWaitTimeout()
{
    if (!harvestAwaitingIdr_) {
        return;
    }
    harvestAwaitingIdr_ = false;
    if (harvestStatusLbl_ != nullptr) {
        harvestStatusLbl_->setText(
            QStringLiteral("❌ Sin IDR en 2 s — revisa posición, recurso o plantilla IEE."));
    }
    appendProxyLog(QStringLiteral("[RECOLECTA] Timeout esperando IDR."));
}

void MainWindow::onSaveIeeTemplateClicked()
{
    QTreeWidgetItem* cur =
        protocolLogTree_ != nullptr ? protocolLogTree_->currentItem() : nullptr;
    if (cur == nullptr) {
        QMessageBox::information(this, QStringLiteral("Plantilla IEE"),
                                 QStringLiteral("Selecciona un paquete IEE en la tabla."));
        return;
    }
    const int vix = cur->data(0, kProtoVecRole).toInt();
    if (vix < 0 || vix >= protocolRecords_.size()) {
        return;
    }
    const ProtocolPacketRecord& rec = protocolRecords_[vix];
    if (rec.kind != PacketKind::IeeHarvest || !rec.rawPayload.contains(QByteArrayLiteral("type.ankama.com/iee"))) {
        QMessageBox::warning(this, QStringLiteral("Plantilla IEE"),
                             QStringLiteral("El paquete debe ser IEE (recolectar)."));
        return;
    }
    const QMessageBox::StandardButton ok =
        QMessageBox::question(this,
                              QStringLiteral("Guardar plantilla_recolectar.bin"),
                              QStringLiteral("¿Guardar %1 bytes del paquete #%2 como plantilla_recolectar.bin junto al "
                                             "ejecutable?")
                                  .arg(rec.rawPayload.size())
                                  .arg(rec.index),
                              QMessageBox::Yes | QMessageBox::No,
                              QMessageBox::Yes);
    if (ok != QMessageBox::Yes) {
        return;
    }
    const QString path = harvestTemplateBinPath();
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::warning(this, QStringLiteral("Plantilla IEE"),
                             QStringLiteral("No se puede escribir:\n%1").arg(path));
        return;
    }
    f.write(rec.rawPayload);
    f.close();
    harvestTemplatePayload_ = rec.rawPayload;
    reloadHarvestTemplateFromDisk();
    appendProxyLog(QStringLiteral("[RECOLECTA] Guardado plantilla IEE (%1 B).").arg(rec.rawPayload.size()));
    QMessageBox::information(this, QStringLiteral("Plantilla IEE"),
                             QStringLiteral("Guardado en:\n%1").arg(QDir::toNativeSeparators(path)));
}

void MainWindow::onRecolectHarvestClicked()
{
    if (proxy_ == nullptr || !proxyRunning_ || !tunnelReady_) {
        QMessageBox::warning(this, QStringLiteral("Recolectar"),
                             QStringLiteral("El proxy debe estar en marcha y el túnel listo."));
        return;
    }
    if (transparentProxyChk_ != nullptr && transparentProxyChk_->isChecked()) {
        QMessageBox::information(this, QStringLiteral("Modo transparente"),
                                 QStringLiteral("Desactiva «Modo transparente» para inyectar al servidor."));
        return;
    }
    if (harvestTemplatePayload_.isEmpty()) {
        QMessageBox::warning(
            this,
            QStringLiteral("Recolectar"),
            QStringLiteral("No hay plantilla IEE. Selecciona un paquete IEE en Logs y pulsa «Guardar IEE → "
                           "plantilla_recolectar.bin»."));
        return;
    }
    const QString err = proxy_->injectTowardServer(harvestTemplatePayload_);
    if (!err.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Inyección"), err);
        return;
    }
    harvestAwaitingIdr_ = true;
    if (harvestStatusLbl_ != nullptr) {
        harvestStatusLbl_->setText(QStringLiteral("… Inyectado IEE — esperando IDR (2 s)"));
    }
    appendProxyLog(QStringLiteral("[RECOLECTA] IEE inyectado; esperando IDR…"));
    if (harvestWatchTimer_ != nullptr) {
        harvestWatchTimer_->stop();
        harvestWatchTimer_->start(harvestWaitMs_);
    }
}

void MainWindow::onEditIdsClicked()
{
    QDialog dlg(this);
    dlg.setWindowTitle(QStringLiteral("Editar IDs — ids_database.json"));
    dlg.setMinimumSize(720, 420);
    auto* lay = new QVBoxLayout(&dlg);
    lay->addWidget(new QLabel(
        QStringLiteral("Ruta: %1").arg(QDir::toNativeSeparators(IdDatabase::defaultStoragePath()))));
    auto* tbl = new QTableWidget(0, 4);
    tbl->setHorizontalHeaderLabels(
        {QStringLiteral("ID"), QStringLiteral("Nombre"), QStringLiteral("Tipo"),
         QStringLiteral("Notas")});
    tbl->horizontalHeader()->setStretchLastSection(true);

    QSet<quint64> idUnion;
    for (quint64 k : idDatabase_.resourceOverrides().keys()) {
        idUnion.insert(k);
    }
    for (quint64 k : idDatabase_.monsterNames().keys()) {
        idUnion.insert(k);
    }
    for (quint64 k : idDatabase_.playerNames().keys()) {
        idUnion.insert(k);
    }
    for (quint64 k : idDatabase_.objectNames().keys()) {
        idUnion.insert(k);
    }
    for (quint64 k : idDatabase_.customNotesById().keys()) {
        idUnion.insert(k);
    }
    QList<quint64> sorted;
    for (quint64 v : idUnion) {
        sorted.append(v);
    }
    std::sort(sorted.begin(), sorted.end());
    for (quint64 id : sorted) {
        const int row = tbl->rowCount();
        tbl->insertRow(row);
        tbl->setItem(row, 0, new QTableWidgetItem(QString::number(id)));
        QString tipo = QStringLiteral("recurso");
        QString nom;
        if (idDatabase_.monsterNames().contains(id)) {
            nom = idDatabase_.monsterNames().value(id);
            tipo = QStringLiteral("monstruo");
        } else if (idDatabase_.playerNames().contains(id)) {
            nom = idDatabase_.playerNames().value(id);
            tipo = QStringLiteral("personaje");
        } else if (idDatabase_.resourceOverrides().contains(id)) {
            nom = idDatabase_.resourceOverrides().value(id);
            tipo = QStringLiteral("recurso");
        } else if (idDatabase_.objectNames().contains(id)) {
            nom = idDatabase_.objectNames().value(id);
            tipo = QStringLiteral("objeto");
        }
        tbl->setItem(row, 1, new QTableWidgetItem(nom));
        tbl->setItem(row, 2, new QTableWidgetItem(tipo));
        tbl->setItem(row, 3, new QTableWidgetItem(idDatabase_.customNotesById().value(id)));
    }

    auto* addBtn = new QPushButton(QStringLiteral("Añadir fila"));
    connect(addBtn, &QPushButton::clicked, this, [tbl]() {
        const int row = tbl->rowCount();
        tbl->insertRow(row);
        tbl->setItem(row, 0, new QTableWidgetItem(QString()));
        tbl->setItem(row, 1, new QTableWidgetItem(QString()));
        tbl->setItem(row, 2, new QTableWidgetItem(QStringLiteral("recurso")));
        tbl->setItem(row, 3, new QTableWidgetItem(QString()));
    });
    auto* btnRow = new QHBoxLayout;
    btnRow->addWidget(addBtn);
    btnRow->addStretch(1);
    lay->addWidget(tbl, 1);
    lay->addLayout(btnRow);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    bb->button(QDialogButtonBox::Save)->setText(QStringLiteral("Guardar y cerrar"));
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    lay->addWidget(bb);
    if (dlg.exec() != QDialog::Accepted) {
        return;
    }

    QHash<quint64, QString> resOut;
    QHash<quint64, QString> monOut;
    QHash<quint64, QString> plOut;
    QHash<quint64, QString> objOut;
    QHash<quint64, QString> notesOut;
    for (int r = 0; r < tbl->rowCount(); ++r) {
        auto* idCell = tbl->item(r, 0);
        if (idCell == nullptr) {
            continue;
        }
        bool ok = false;
        const quint64 id = idCell->text().trimmed().toULongLong(&ok);
        if (!ok || id == 0) {
            continue;
        }
        const QString name = tbl->item(r, 1) != nullptr ? tbl->item(r, 1)->text().trimmed() : QString();
        const QString tipo = tbl->item(r, 2) != nullptr ? tbl->item(r, 2)->text().trimmed().toLower()
                                                        : QStringLiteral("recurso");
        const QString note = tbl->item(r, 3) != nullptr ? tbl->item(r, 3)->text().trimmed() : QString();

        if (tipo == QStringLiteral("monstruo") && !name.isEmpty()) {
            monOut.insert(id, name);
        } else if (tipo == QStringLiteral("personaje") && !name.isEmpty()) {
            plOut.insert(id, name);
        } else if (tipo == QStringLiteral("objeto") && !name.isEmpty()) {
            objOut.insert(id, name);
        } else if (!name.isEmpty()) {
            resOut.insert(id, name);
        }
        if (!note.isEmpty()) {
            notesOut.insert(id, note);
        }
    }

    IdDatabase next;
    next.setResourceOverrides(resOut);
    next.setMonsterNames(monOut);
    next.setPlayerNames(plOut);
    next.setObjectNames(objOut);
    next.setCustomNotes(notesOut);
    QString err;
    if (!next.saveToFile(IdDatabase::defaultStoragePath(), &err)) {
        QMessageBox::warning(this, QStringLiteral("ids_database.json"), err);
        return;
    }
    idDatabase_ = next;
    appendProxyLog(QStringLiteral("[IDS] Guardado ids_database.json"));
    if (protocolLogTree_ != nullptr) {
        protocolLogTree_->clear();
        for (int i = 0; i < protocolRecords_.size(); ++i) {
            appendProtocolTreeItem(protocolRecords_[i], i);
        }
        applyProtocolLogFilters();
    }
    refreshProtocolDetailFromSelection();
    QMessageBox::information(this, QStringLiteral("IDs"), QStringLiteral("Cambios guardados."));
}

QString MainWindow::peekLastDllLogHookLine() const
{
    const QString candidates[] = {
        QStringLiteral("C:/dofus_dll_log.txt"),
        QDir(QDir::tempPath()).absoluteFilePath(QStringLiteral("dofus_redirect_log.txt")),
    };
    QString path;
    for (const QString& p : candidates) {
        if (QFile::exists(p)) {
            path = p;
            break;
        }
    }
    if (path.isEmpty()) {
        return QString();
    }
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        return QString();
    }
    const qint64 sz = f.size();
    constexpr qint64 kTail = 16384;
    if (sz > kTail) {
        if (!f.seek(sz - kTail)) {
            return QString();
        }
        f.readLine();
    }
    const QByteArray blob = f.readAll();
    const QString text = QString::fromUtf8(blob);
    const QStringList lines = text.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (int i = lines.size() - 1; i >= 0; --i) {
        const QString ln = lines.at(i).trimmed();
        if (ln.contains(QStringLiteral("Redirect"), Qt::CaseInsensitive)
            || ln.contains(QStringLiteral("ConnectEx redirect"), Qt::CaseInsensitive)
            || ln.contains(QStringLiteral("Hooks activos"), Qt::CaseInsensitive)
            || ln.contains(QStringLiteral("Hooks connect"), Qt::CaseInsensitive)
            || ln.contains(QStringLiteral("Resumen hooks"), Qt::CaseInsensitive)
            || ln.contains(QStringLiteral("getaddrinfo DNS"), Qt::CaseInsensitive)
            || ln.contains(QStringLiteral("GetAddrInfoW DNS"), Qt::CaseInsensitive)
            || ln.contains(QStringLiteral("gethostbyname DNS"), Qt::CaseInsensitive)) {
            return ln;
        }
    }
    return QString();
}

bool MainWindow::tryGetSelectedPid(quint32* outPid) const
{
    if (procTable_ == nullptr || outPid == nullptr) {
        return false;
    }
    const QList<QTableWidgetItem*> items = procTable_->selectedItems();
    if (items.isEmpty()) {
        return false;
    }
    const int row = items.first()->row();
    auto* cell = procTable_->item(row, 0);
    if (cell == nullptr) {
        return false;
    }
    bool ok = false;
    const quint32 p = cell->text().toUInt(&ok);
    if (!ok || p == 0) {
        return false;
    }
    *outPid = p;
    return true;
}

void MainWindow::onProcessMonitorStart()
{
#ifndef Q_OS_WIN
    Q_UNUSED(this);
#else
    if (!winIsElevatedAdministrator()) {
        QMessageBox::critical(
            this,
            QStringLiteral("Administrador"),
            QStringLiteral("El monitor inyecta DLL: ejecuta la aplicación como administrador."));
        return;
    }
    if (processMonitor_ == nullptr) {
        return;
    }
    if (processMonitor_->isRunning()) {
        QMessageBox::information(this, QStringLiteral("Monitor"), QStringLiteral("El monitor ya está en ejecución."));
        return;
    }
    processMonitor_->start();
    if (monitorStartBtn_ != nullptr) {
        monitorStartBtn_->setEnabled(false);
    }
    if (monitorStopBtn_ != nullptr) {
        monitorStopBtn_->setEnabled(true);
    }
    appendProxyLog(QStringLiteral(
        "[MONITOR] Vigilancia de Dofus.exe activa (cada ~1 s). Abre el juego para inyección automática + cierre TCP."));
#endif
}

void MainWindow::onProcessMonitorStop()
{
#ifndef Q_OS_WIN
    Q_UNUSED(this);
#else
    if (processMonitor_ == nullptr) {
        return;
    }
    processMonitor_->stopSafely();
    if (monitorStartBtn_ != nullptr) {
        monitorStartBtn_->setEnabled(true);
    }
    if (monitorStopBtn_ != nullptr) {
        monitorStopBtn_->setEnabled(false);
    }
    pendingMonitorInjectPid_ = 0;
    if (pendingMonitorInjectTimer_ != nullptr) {
        pendingMonitorInjectTimer_->stop();
    }
    appendProxyLog(QStringLiteral("[MONITOR] Monitor detenido."));
#endif
}

void MainWindow::onDofusDetectedInject(quint32 pid)
{
#ifndef Q_OS_WIN
    Q_UNUSED(pid);
#else
    if (pid == 0 || !winIsElevatedAdministrator()) {
        return;
    }
    pendingMonitorInjectPid_ = pid;
    if (pendingMonitorInjectTimer_ == nullptr) {
        return;
    }
    pendingMonitorInjectTimer_->stop();
    pendingMonitorInjectTimer_->start(750);
#endif
}

void MainWindow::onPendingMonitorInjectTimeout()
{
#ifdef Q_OS_WIN
    const quint32 pid = pendingMonitorInjectPid_;
    pendingMonitorInjectPid_ = 0;
    if (pid == 0 || !winIsElevatedAdministrator()) {
        return;
    }
    const QString dllPath =
        dllPathEdit_ != nullptr && !dllPathEdit_->text().trimmed().isEmpty() ? dllPathEdit_->text().trimmed()
                                                                             : defaultRedirectDllPath();
    QString injErr;
    appendProxyLog(QStringLiteral("[AUTO][⏳] Inyección retardada iniciada para PID %1").arg(pid));
    if (!winInjectDllIntoProcess(pid, dllPath, &injErr)) {
        appendProxyLog(QStringLiteral("[AUTO][!] Dofus.exe PID %1 — inyección fallida: %2")
                             .arg(pid)
                             .arg(injErr));
        return;
    }
    injectedDllPid_ = pid;
    appendProxyLog(QStringLiteral("[AUTO][✅] DLL inyectada en PID %1").arg(pid));
    appendProxyLog(QStringLiteral("[AUTO][✅] Hooks DNS + connect (ver log y panel «Diagnóstico del hook»)."));
    kickGamePort5555AfterInject(pid, false);
    if (massCloseOutboundTcpAfterInjectChk_ != nullptr && massCloseOutboundTcpAfterInjectChk_->isChecked()) {
        kickAllOutboundAfterInject(pid);
    }
    const int r = rowForPid(pid);
    if (r >= 0 && procTable_ != nullptr) {
        procTable_->clearSelection();
        procTable_->selectRow(r);
    }
#else
    Q_UNUSED(this);
#endif
}

void MainWindow::onFullDiagnosticClicked()
{
#ifndef Q_OS_WIN
    QMessageBox::information(this, QStringLiteral("Diagnóstico"), QStringLiteral("Solo disponible en Windows."));
#else
    QStringList out;
    out << QStringLiteral("=== DIAGNÓSTICO COMPLETO ===");
    out << QStringLiteral("Fecha: ") + QDateTime::currentDateTime().toString(Qt::ISODate);
    out << QStringLiteral("");
    const auto matches = collectDofusMatches();
    out << QStringLiteral("Procesos «Dofus» detectados: %1").arg(matches.size());
    for (const ProcessEntry& e : matches) {
        out << QStringLiteral("  · PID %1 — %2").arg(e.pid).arg(e.name);
    }
    out << QStringLiteral("");
    out << QStringLiteral("Proxy escuchando: %1").arg(proxy_->isListening() ? QStringLiteral("sí")
                                                                             : QStringLiteral("no"));
    out << QStringLiteral("Proxy en marcha (UI): %1").arg(proxyRunning_ ? QStringLiteral("sí")
                                                                          : QStringLiteral("no"));
    out << QStringLiteral("Túnel listo: %1").arg(tunnelReady_ ? QStringLiteral("sí") : QStringLiteral("no"));
    out << QStringLiteral("");
    quint32 sel = 0;
    if (tryGetSelectedPid(&sel)) {
        out << QStringLiteral("PID seleccionado en tabla: %1").arg(sel);
        const QVector<TcpRowPidIpv4> rows = winEnumerateTcpIpv4RowsForOwningPid(sel);
        bool hasLoop5555 = false;
        for (const TcpRowPidIpv4& row : rows) {
            const QString rem = QHostAddress(qFromBigEndian(row.remoteAddrIpv4BE)).toString();
            if (row.tcpState == 5 && row.remotePort == kLocalProxyMustPort && QHostAddress(rem).isLoopback()) {
                hasLoop5555 = true;
                break;
            }
        }
        out << QStringLiteral("127.0.0.1:%1 ESTABLISHED (este PID): %2")
                   .arg(kLocalProxyMustPort)
                   .arg(hasLoop5555 ? QStringLiteral("sí") : QStringLiteral("no"));
    } else {
        out << QStringLiteral("PID seleccionado: ninguno");
    }
    out << QStringLiteral("");
    const QString logPath =
        QDir(QDir::tempPath()).absoluteFilePath(QStringLiteral("dofus_redirect_log.txt"));
    out << QStringLiteral("Log DLL: ") + QDir::toNativeSeparators(logPath);
    QFile lf(logPath);
    if (lf.open(QIODevice::ReadOnly)) {
        const qint64 sz = lf.size();
        if (sz > 24000) {
            lf.seek(sz - 24000);
            lf.readLine();
        }
        out << QStringLiteral("");
        out << QStringLiteral("--- Últimas líneas del log DLL ---");
        out << QString::fromUtf8(lf.readAll());
    } else {
        out << QStringLiteral("(no se pudo abrir el log)");
    }

    auto* dlg = new QDialog(this);
    dlg->setWindowTitle(QStringLiteral("Diagnóstico completo"));
    dlg->setMinimumSize(560, 420);
    auto* v = new QVBoxLayout(dlg);
    auto* te = new QPlainTextEdit;
    te->setReadOnly(true);
    te->setPlainText(out.join(QLatin1Char('\n')));
    {
        auto f = te->font();
        f.setFamily(QStringLiteral("Consolas"));
        f.setStyleHint(QFont::Monospace);
        te->setFont(f);
    }
    v->addWidget(te);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Close);
    QObject::connect(bb, &QDialogButtonBox::rejected, dlg, &QDialog::accept);
    v->addWidget(bb);
    dlg->exec();
    dlg->deleteLater();
#endif
}
#endif
