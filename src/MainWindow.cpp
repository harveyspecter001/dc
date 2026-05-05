#include "MainWindow.h"
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
#include <QCoreApplication>
#include <QDateTime>
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
#include <QMenu>
#include <QMimeData>
#include <QSplitter>
#include <QUrl>
#include <QSpinBox>
#include <QSettings>
#include <QTextStream>

#include <functional>

namespace {
constexpr quint16 kUpstreamDefaultPort = 5555;
constexpr int kProtoVecRole = Qt::UserRole + 48;

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

    auto* tabWidget = new QTabWidget;
    tabWidget->setDocumentMode(true);
    tabWidget->setUsesScrollButtons(true);
    tabWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setCentralWidget(tabWidget);

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

    tabWidget->addTab(wrapInScroll(pageProxyMain), QStringLiteral("Proxy"));

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
        resourcesTable_ = new QTableWidget(4, 3);
        resourcesTable_->setHorizontalHeaderLabels(
            {QStringLiteral("Recurso"), QStringLiteral("ID"), QStringLiteral("Cantidad (si aplica)")});
        const QStringList rnames = {QStringLiteral("Trigo"), QStringLiteral("Ortiga"), QStringLiteral("Castaño"),
                                    QStringLiteral("Fresno")};
        for (int i = 0; i < 4; ++i) {
            resourcesTable_->setItem(i, 0, new QTableWidgetItem(rnames.at(i)));
            resourcesTable_->setItem(i, 1, new QTableWidgetItem(QStringLiteral("—")));
            resourcesTable_->setItem(i, 2, new QTableWidgetItem(QStringLiteral("—")));
        }
        resourcesTable_->horizontalHeader()->setStretchLastSection(true);
        resourcesTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        resourcesTable_->setSelectionMode(QAbstractItemView::NoSelection);
        v->addWidget(resourcesTable_, 1);
        refreshResourcesBtn_ = new QPushButton(QStringLiteral("Actualizar desde logs"));
        refreshResourcesBtn_->setToolTip(
            QStringLiteral("Recalcula la tabla a partir de los paquetes ISO ya analizados en la pestaña «Logs»."));
        connect(refreshResourcesBtn_, &QPushButton::clicked, this, &MainWindow::onRefreshResourcesFromLogsClicked);
        v->addWidget(refreshResourcesBtn_);
        editIdsBtn_ = new QPushButton(QStringLiteral("Editar IDs (ids_database.json)"));
        editIdsBtn_->setToolTip(
            QStringLiteral("Tabla: ID, nombre, tipo (recurso/monstruo/objeto) y notas. Se guarda junto al .exe."));
        connect(editIdsBtn_, &QPushButton::clicked, this, &MainWindow::onEditIdsClicked);
        v->addWidget(editIdsBtn_);
    }
    auto* pageProto = new QWidget;
    {
        auto* v = new QVBoxLayout(pageProto);
        v->setSpacing(8);
        v->setContentsMargins(8, 8, 8, 8);
        v->addWidget(new QLabel(QStringLiteral(
            "<b>Logs de protocolo</b> — columna seleccionada abre detalle HEX; plantillas ☆iri solo desde paquetes IRI.")));
        auto* fl = new QHBoxLayout;
        protocolKindFilter_ = new QComboBox;
        protocolKindFilter_->addItem(QStringLiteral("Mostrar: todos"));
        protocolKindFilter_->addItem(QStringLiteral("Solo IRI"));
        protocolKindFilter_->addItem(QStringLiteral("Solo IRL"));
        protocolKindFilter_->addItem(QStringLiteral("Solo ISO"));
        protocolKindFilter_->addItem(QStringLiteral("Solo IRX"));
        protocolKindFilter_->addItem(QStringLiteral("Solo ISL"));
        protocolKindFilter_->addItem(QStringLiteral("Solo COMANDO/jrt"));
        protocolKindFilter_->addItem(QStringLiteral("Solo DATOS"));
        protocolKindFilter_->addItem(QStringLiteral("Solo OTRO"));
        protocolKindFilter_->addItem(QStringLiteral("Solo IEE (recolectar)"));
        protocolKindFilter_->addItem(QStringLiteral("Solo IDR (ítem recibido)"));
        protocolKindFilter_->setToolTip(QStringLiteral("Filtra por tipo detectado en el payload."));
        connect(protocolKindFilter_, &QComboBox::currentIndexChanged, this, &MainWindow::onProtocolFilterChanged);
        fl->addWidget(protocolKindFilter_);
        protocolSearchEdit_ = new QLineEdit;
        protocolSearchEdit_->setPlaceholderText(QStringLiteral("Buscar string, URL o número de ID…"));
        protocolSearchEdit_->setToolTip(QStringLiteral(
            "Coincide en todo el contenido de la fila (incl. vista previa de IDs y URL principal)."));
        connect(protocolSearchEdit_, &QLineEdit::textChanged, this, &MainWindow::onProtocolFilterChanged);
        fl->addWidget(protocolSearchEdit_, 1);
        importExportedLogBtn_ = new QPushButton(QStringLiteral("Importar .txt…"));
        importExportedLogBtn_->setToolTip(QStringLiteral("Vista previa del primer paquete y recuento antes de cargar."));
        connect(importExportedLogBtn_, &QPushButton::clicked, this, &MainWindow::onImportExportedLogClicked);
        fl->addWidget(importExportedLogBtn_);
        clearProtocolLogBtn_ = new QPushButton(QStringLiteral("Vaciar lista"));
        connect(clearProtocolLogBtn_, &QPushButton::clicked, this, &MainWindow::onClearProtocolLogClicked);
        fl->addWidget(clearProtocolLogBtn_);
        v->addLayout(fl);

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
        dv->addWidget(new QLabel(QStringLiteral("<b>Detalle del paquete (Wireshark-ish)</b>")));
        protocolDetailText_ = new QPlainTextEdit;
        protocolDetailText_->setReadOnly(true);
        protocolDetailText_->setMinimumHeight(220);
        {
            auto df = protocolDetailText_->font();
            df.setFamily(QStringLiteral("Consolas"));
            protocolDetailText_->setFont(df);
        }
        dv->addWidget(protocolDetailText_);
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
    tabWidget->insertTab(1, wrapInScroll(pageRes), QStringLiteral("Recursos"));
    tabWidget->insertTab(2, wrapInScroll(pageProto), QStringLiteral("Logs"));

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
    tabWidget->addTab(wrapInScroll(pageAdv), QStringLiteral("Avanzado"));

    statusBar()->show();
    characterStatusBarLbl_ = new QLabel(
        QStringLiteral("Personaje: — · Nivel: — · Clase: —"));
    characterStatusBarLbl_->setStyleSheet(QStringLiteral("color:#e5e5e5;padding:4px 8px;"));
    statusBar()->addPermanentWidget(characterStatusBarLbl_);

    connect(proxy_, &TcpMitmProxy::logLine, this, &MainWindow::appendProxyLog);
    connect(proxy_, &TcpMitmProxy::protocolPayloadCaptured, this, &MainWindow::onProtocolPayloadCaptured);
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
    switch (k) {
    case PacketKind::IriMovement:
        return QColor(0x4a, 0xde, 0x80);
    case PacketKind::IrlList:
        return QColor(0x60, 0xa5, 0xfa);
    case PacketKind::IsoResources:
        return QColor(0xfb, 0xbf, 0x24);
    case PacketKind::IrxMonsters:
        return QColor(0xf8, 0x71, 0x71);
    case PacketKind::IslEntities:
        return QColor(0xc4, 0xb5, 0xfd);
    case PacketKind::IeeHarvest:
        return QColor(0xfb, 0x92, 0x3c);
    case PacketKind::IdrItemReceived:
        return QColor(0x86, 0xef, 0xac);
    case PacketKind::CommandData:
        return QColor(0xf8, 0x71, 0x71);
    case PacketKind::DataGeneric:
        return QColor(0x9c, 0xa3, 0xaf);
    default:
        return QColor(0xd4, 0xd4, 0xd4);
    }
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

void MainWindow::appendProtocolTreeItem(const ProtocolPacketRecord& r, int vectorIndex)
{
    if (protocolLogTree_ == nullptr) {
        return;
    }
    auto* it = new QTreeWidgetItem(protocolLogTree_);
    it->setData(0, Qt::UserRole, static_cast<int>(r.kind));
    it->setData(0, kProtoVecRole, vectorIndex);
    it->setText(0, QString::number(r.index));
    it->setText(1, r.received.toString(QStringLiteral("HH:mm:ss.zzz")));
    it->setText(2, r.fromClient ? QStringLiteral("→") : QStringLiteral("←"));
    it->setText(3, r.kindLabel);
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
    it->setForeground(0, QBrush(QColor(0xe5, 0xe7, 0xeb)));
    it->setForeground(1, QBrush(QColor(0xe5, 0xe7, 0xeb)));
    it->setForeground(2, QBrush(dirFg));
    it->setForeground(3, QBrush(fgType));
    it->setForeground(4, QBrush(QColor(0xe5, 0xe7, 0xeb)));
    it->setForeground(5, QBrush(QColor(0xfe, 0xf3, 0xc7)));
    it->setForeground(6, QBrush(QColor(0xdb, 0xea, 0xfe)));

    protocolLogTree_->resizeColumnToContents(0);
    protocolLogTree_->resizeColumnToContents(4);
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
    const QString body = buildPacketAnalysisText(rec, mergedAliasRulesForAnalysis(), 256,
                                                 &idDatabase_.customNotesById());
    protocolDetailText_->setPlainText(body);
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
    protocolLogTree_->setCurrentItem(it);
    refreshProtocolDetailFromSelection();
    QMenu menu(this);
    menu.addAction(QStringLiteral("Exportar selección (%1) a TXT…")
                       .arg(protocolLogTree_->selectedItems().size()),
                   this, &MainWindow::exportSelectedPackages);
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
        ProtocolPacketRecord previewRec = buildRecordFromPayload(1, chunks[0].first, chunks[0].second);
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
        onProtocolPayloadCaptured(ch.first, ch.second);
    }
    appendProxyLog(QStringLiteral("[IMPORT] %1 trozos desde %2.")
                       .arg(chunks.size())
                       .arg(QDir::toNativeSeparators(path)));
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
        bool okKind = false;
        if (fil == 0) {
            okKind = true;
        } else if (fil == 1) {
            okKind = (k == PacketKind::IriMovement);
        } else if (fil == 2) {
            okKind = (k == PacketKind::IrlList);
        } else if (fil == 3) {
            okKind = (k == PacketKind::IsoResources);
        } else if (fil == 4) {
            okKind = (k == PacketKind::IrxMonsters);
        } else if (fil == 5) {
            okKind = (k == PacketKind::IslEntities);
        } else if (fil == 6) {
            okKind = (k == PacketKind::CommandData);
        } else if (fil == 7) {
            okKind = (k == PacketKind::DataGeneric);
        } else if (fil == 8) {
            okKind = (k == PacketKind::Unknown);
        } else if (fil == 9) {
            okKind = (k == PacketKind::IeeHarvest);
        } else if (fil == 10) {
            okKind = (k == PacketKind::IdrItemReceived);
        }
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
    if (resourcesTable_ == nullptr) {
        return;
    }
    for (int i = 0; i < resourcesTable_->rowCount(); ++i) {
        if (resourcesTable_->item(i, 1) != nullptr) {
            resourcesTable_->item(i, 1)->setText(QStringLiteral("—"));
        }
    }
    for (const ProtocolPacketRecord& r : protocolRecords_) {
        if (r.kind != PacketKind::IsoResources) {
            continue;
        }
        const QVector<IdRangeRule> merged = mergedAliasRulesForAnalysis();
        for (quint64 id :
             filterResourceCandidateIds(r.numericIds, parsedAndDatabaseRulesForResourceFilter())) {
            const QString rn = resolveIdWithRules(id, merged, nullptr);
            if (rn.isEmpty()) {
                continue;
            }
            for (int row = 0; row < resourcesTable_->rowCount(); ++row) {
                auto* nameCell = resourcesTable_->item(row, 0);
                if (nameCell != nullptr && nameCell->text() == rn && resourcesTable_->item(row, 1) != nullptr) {
                    resourcesTable_->item(row, 1)->setText(QString::number(id));
                    break;
                }
            }
        }
    }
    if (lastMapGuess_ != 0 && mapCurrentIdLbl_ != nullptr) {
        mapCurrentIdLbl_->setText(QStringLiteral("Mapa actual: %1").arg(lastMapGuess_));
    }
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

void MainWindow::updateResourcesFromIsoPayload(const QByteArray& payload)
{
    QList<quint64> vars;
    extractProtobufStyleVarints(payload, &vars);
    const QVector<IdRangeRule> merged = mergedAliasRulesForAnalysis();
    for (quint64 id : filterResourceCandidateIds(vars, parsedAndDatabaseRulesForResourceFilter())) {
        const QString rn = resolveIdWithRules(id, merged, nullptr);
        if (rn.isEmpty() || resourcesTable_ == nullptr) {
            continue;
        }
        for (int row = 0; row < resourcesTable_->rowCount(); ++row) {
            auto* nameCell = resourcesTable_->item(row, 0);
            if (nameCell != nullptr && nameCell->text() == rn && resourcesTable_->item(row, 1) != nullptr) {
                resourcesTable_->item(row, 1)->setText(QString::number(id));
                break;
            }
        }
    }
    const quint64 mid = guessMapIdHeuristic(payload);
    if (mid != 0) {
        lastMapGuess_ = mid;
        if (mapCurrentIdLbl_ != nullptr) {
            mapCurrentIdLbl_->setText(QStringLiteral("Mapa actual: %1").arg(mid));
        }
    }
}

void MainWindow::onProtocolPayloadCaptured(bool fromClient, const QByteArray& payload)
{
    ++protocolPacketSeq_;
    ProtocolPacketRecord r = buildRecordFromPayload(protocolPacketSeq_, fromClient, payload);
    protocolRecords_.push_back(r);
    appendProtocolTreeItem(r, protocolRecords_.size() - 1);
    applyProtocolLogFilters();

    if (r.kind == PacketKind::IsoResources) {
        updateResourcesFromIsoPayload(payload);
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
    if (mapCurrentIdLbl_ != nullptr) {
        mapCurrentIdLbl_->setText(QStringLiteral("Mapa actual: —"));
    }
    if (resourcesTable_ != nullptr) {
        for (int i = 0; i < resourcesTable_->rowCount(); ++i) {
            if (resourcesTable_->item(i, 1) != nullptr) {
                resourcesTable_->item(i, 1)->setText(QStringLiteral("—"));
            }
            if (resourcesTable_->item(i, 2) != nullptr) {
                resourcesTable_->item(i, 2)->setText(QStringLiteral("—"));
            }
        }
    }
    refreshCharacterLabels();
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
    for (quint64 k : idDatabase_.objectNames().keys()) {
        idUnion.insert(k);
    }
    for (quint64 k : idDatabase_.customNotesById().keys()) {
        idUnion.insert(k);
    }
    QList<quint64> sorted = idUnion.values();
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
