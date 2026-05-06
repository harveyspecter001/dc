#pragma once

#include <QByteArray>
#include <QColor>
#include <QFrame>
#include <QMainWindow>
#include <QString>
#include <QVector>

#include "IdDatabase.h"
#include "IriCardinalEmulator.h"
#include "ProcessEnumerator.h"
#include "ProtocolLogAnalyzer.h"

#include <QtGlobal>
#ifdef Q_OS_WIN
#include "WindowsTcpPidSnapshot.h"
#endif

class QCheckBox;
class QCloseEvent;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTableWidget;
class QTimer;
class QGroupBox;
class QTreeWidget;
class QTreeWidgetItem;
class QComboBox;
class QListWidget;
class QPlainTextEdit;
class QTabWidget;
class QTextEdit;
class QTextBrowser;
class QSplitter;

class DiagnosticsLogWindow;
class TcpMitmProxy;
#ifdef Q_OS_WIN
class ProcessMonitor;
#endif

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void refreshProcesses();
    void onStartProxySoloClicked();
    void onStopProxyClicked();
    void onStartAllClicked();
    void onStopAllClicked();
    void onApplyUpstreamClicked();
    void onForceUpstreamRedetectClicked();
#ifdef Q_OS_WIN
    void onStartProxyWithDllClicked();
#endif
    void appendProxyLog(const QString& line);

    void reloadDirectionMapClicked();
    void updateTunnelStatus(bool tunnelReadyWithClient);
    void refreshConnectionMonitor();
    void openDiagnosticsLogWindow();
    void onTestProxyClicked();
    void onTestUpstreamClicked();
    void syncProxyOptionsFromUi();
    void onProcessMonitorStart();
    void onProcessMonitorStop();
    void onDofusDetectedInject(quint32 pid);
    void onFullDiagnosticClicked();
#ifdef Q_OS_WIN
    void onPendingMonitorInjectTimeout();
#endif
#ifdef Q_OS_WIN
    void onApplyHostsClicked();
    void onRestoreHostsClicked();
    void onInjectDllClicked();
    void onInjectTestDllClicked();
    void onManualWinsockConnectClicked();
    void onNetstat5555Clicked();
#endif
    void onProtocolPayloadCaptured(bool fromClient, const QByteArray& payload);
    void onRefreshResourcesFromLogsClicked();
    void onImportExportedLogClicked();
    void onClearProtocolLogClicked();
    void onProtocolFilterChanged();
    void onProtocolLogCurrentItemChanged(QTreeWidgetItem* current, QTreeWidgetItem* previous);
    void onProtocolLogContextMenu(const QPoint& pos);
    void onExportSelectedWithNote();
    void refreshExportedLogsList();
    void openResourceEditor();
    void onIdAliasRulesChanged();
    void onEditIdsClicked();
    void onHarvestWaitTimeout();
    void onSaveIeeTemplateClicked();
    void onRecolectHarvestClicked();
    void exportSelectedPackages();

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    QVector<ProcessEntry> allRows_;
    void applyTableFilter();
    int rowForPid(quint32 pid) const;

    QLabel* dofStatus_ = nullptr;
    QLabel* selectedPidLbl_ = nullptr;
    QLineEdit* nameFilterEdit_ = nullptr;
    QCheckBox* dofusOnlyCheckbox_ = nullptr;
    QCheckBox* autoSelectSingleCheckbox_ = nullptr;
    QTableWidget* procTable_ = nullptr;
    QPushButton* refreshBtn_ = nullptr;

    QLineEdit* bindHost_ = nullptr;
    QLineEdit* bindPort_ = nullptr;
    QLineEdit* upstreamHost_ = nullptr;
    QLineEdit* upstreamPort_ = nullptr;
    QCheckBox* logTcpCheckbox_ = nullptr;
    QCheckBox* drainQueueLogChk_ = nullptr;
    QCheckBox* verboseProxyChk_ = nullptr;
    QCheckBox* fullTunnelDiagChk_ = nullptr;
    QCheckBox* rawForwarderChk_ = nullptr;
    QCheckBox* transparentProxyChk_ = nullptr;
    QCheckBox* echoProxyChk_ = nullptr;
    QCheckBox* minimalProxyChk_ = nullptr;
    QCheckBox* listenIpv6Chk_ = nullptr;
    QCheckBox* captureHandshakeChk_ = nullptr;
    QPushButton* testProxyBtn_ = nullptr;
    QPushButton* testUpstreamBtn_ = nullptr;
    QPushButton* manualWinsockConnectBtn_ = nullptr;
    QPushButton* injectTestDllBtn_ = nullptr;
    QPushButton* netstat5555Btn_ = nullptr;
    QLabel* upstreamDetectedLbl_ = nullptr;
    QLabel* upstreamQuickLbl_ = nullptr;
    QLabel* proxyProbeHintsLbl_ = nullptr;
    QLabel* proxyStartupOrderLbl_ = nullptr;
    QLabel* proxyTestHintsLbl_ = nullptr;

    QPushButton* startProxySoloBtn_ = nullptr;
    QPushButton* stopProxyBtn_ = nullptr;
    QPushButton* startAllBtn_ = nullptr;
    QPushButton* stopAllBtn_ = nullptr;
    QPushButton* applyUpstreamBtn_ = nullptr;
    QPushButton* forceRedetectUpstreamBtn_ = nullptr;
#ifdef Q_OS_WIN
    QPushButton* startProxyWithDllBtn_ = nullptr;
#endif
    QPlainTextEdit* proxyLog_ = nullptr;
    DiagnosticsLogWindow* diagLogWin_ = nullptr;

    QLabel* userStepsLbl_ = nullptr;
    QLabel* tunnelStatusLbl_ = nullptr;

    QLabel* reconnectHintLbl_ = nullptr;
    QLabel* memIpReadLbl_ = nullptr;
    QLabel* tcpConnDumpLbl_ = nullptr;
#ifdef Q_OS_WIN
    QPushButton* applyHostsBtn_ = nullptr;
    QPushButton* restoreHostsBtn_ = nullptr;
    ProcessMonitor* processMonitor_ = nullptr;
    QPushButton* monitorStartBtn_ = nullptr;
    QPushButton* monitorStopBtn_ = nullptr;
    QPushButton* fullDiagnosticBtn_ = nullptr;
    QLabel* hookDiagPanel_ = nullptr;
    QLabel* monitorUsageLbl_ = nullptr;
    QLineEdit* dllPathEdit_ = nullptr;
    QPushButton* injectDllBtn_ = nullptr;
    QCheckBox* autoInjectDllChk_ = nullptr;
    QCheckBox* massCloseOutboundTcpAfterInjectChk_ = nullptr;
    QLabel* diagProxyIndLbl_ = nullptr;
    QLabel* diagLastFlowLbl_ = nullptr;
    QString lastMonitorFlowLine_;
    quint32 injectedDllPid_ = 0;
    bool prevProxyLoopbackEstablished_ = false;
    QString lastDllLogMonitorLine_;
    quint32 pendingMonitorInjectPid_ = 0;
    QTimer* pendingMonitorInjectTimer_ = nullptr;
#endif

    QLineEdit* dirMapJsonPath_ = nullptr;
    QPushButton* reloadDirMapBtn_ = nullptr;
    QLabel* mapModelSummaryLbl_ = nullptr;
    QPushButton* importMovementLogBtn_ = nullptr;
    QLabel* iriTokenStatusLbl_ = nullptr;
    QLabel* iriTemplateCheckLbl_ = nullptr;
    QLabel* iriOfflineHintLbl_ = nullptr;
    QPushButton* arrowN_btn_ = nullptr;
    QPushButton* arrowS_btn_ = nullptr;
    QPushButton* arrowE_btn_ = nullptr;
    QPushButton* arrowO_btn_ = nullptr;

    QTimer* connMonitorTimer_ = nullptr;

    TcpMitmProxy* proxy_ = nullptr;
    bool proxyRunning_ = false;
    bool tunnelReady_ = false;
    int outboundTcpClosedLastStart_ = 0;

    IriCardinalEmulator iriEmu_;

    QLabel* characterStatusBarLbl_ = nullptr;
    QLabel* mapCurrentIdLbl_ = nullptr;
    QTableWidget* resourcesTable_ = nullptr;
    QPushButton* refreshResourcesBtn_ = nullptr;
    QPushButton* editIdsBtn_ = nullptr;
    QPushButton* editResourcesGuiBtn_ = nullptr;
    QLabel* monstersMapLbl_ = nullptr;
    QTabWidget* mainTabWidget_ = nullptr;
    QWidget* advancedTabWrap_ = nullptr;
    QListWidget* libraryLogList_ = nullptr;
    QTextEdit* libraryPreviewEdit_ = nullptr;
    QTreeWidget* protocolLogTree_ = nullptr;
    QComboBox* protocolKindFilter_ = nullptr;
    QCheckBox* protocolLogAutoScrollChk_ = nullptr;
    QLineEdit* protocolSearchEdit_ = nullptr;
    QPushButton* clearProtocolLogBtn_ = nullptr;
    QPushButton* importExportedLogBtn_ = nullptr;
    QSplitter* protocolLogSplitter_ = nullptr;
    QTextBrowser* protocolDetailText_ = nullptr;
    QPlainTextEdit* idAliasRulesEdit_ = nullptr;
    QPushButton* saveTmplN_btn_ = nullptr;
    QPushButton* saveTmplS_btn_ = nullptr;
    QPushButton* saveTmplE_btn_ = nullptr;
    QPushButton* saveTmplO_btn_ = nullptr;
    QPushButton* saveIeeTemplateBtn_ = nullptr;
    QPushButton* recolectHarvestBtn_ = nullptr;
    QLabel* harvestStatusLbl_ = nullptr;
    QFrame* protocolDropZone_ = nullptr;

    IdDatabase idDatabase_;
    QByteArray harvestTemplatePayload_;
    bool harvestAwaitingIdr_ = false;
    QTimer* harvestWatchTimer_ = nullptr;
    int harvestWaitMs_ = 2000;

    QVector<ProtocolPacketRecord> protocolRecords_;
    int protocolPacketSeq_ = 0;
    int serverPayloadOrdinal_ = 0;
    CharacterSnapshot characterSnap_;
    quint64 lastMapGuess_ = 0;

    QVector<ProcessEntry> collectDofusMatches() const;

    QString appStyleSheet() const;
    void tryLoadDirectionMapFromField(bool logOk);
    void applyCardinal(const QString& cardinalEs);
    void refreshIriDiagnostics();
    void onImportMovementLogClicked();

    [[nodiscard]] QString movementInjectionPrecheck(const QByteArray& patched,
                                                    const QByteArray& liveOptional) const;

    void shutdownProxyAndCleanup();
    void syncUpstreamFromUiToProxy();
    void ensureUpstreamRealIpFromUi();
    void saveUpstreamIpToSharedFile();
    void updateProxyToolbarState();
    void refreshMovementButtonsEnabled();
    void updateUpstreamQuickLabel();
    void runUpstreamTcpProbe(const QString& host, quint16 port);

    [[nodiscard]] QColor protocolKindColor(PacketKind k) const;
    [[nodiscard]] QString packetTypeEmoji(PacketKind k) const;
    [[nodiscard]] QString buildProtocolPacketDetailHtml(const ProtocolPacketRecord& rec) const;
    [[nodiscard]] QVector<IdRangeRule> parsedUserIdRulesFromUi() const;
    [[nodiscard]] QVector<IdRangeRule> mergedAliasRulesForAnalysis() const;
    [[nodiscard]] QVector<IdRangeRule> parsedAndDatabaseRulesForResourceFilter() const;
    void reloadIdDatabaseFromDisk();
    void reloadHarvestTemplateFromDisk();
    [[nodiscard]] QString harvestTemplateBinPath() const;
    void setupLibraryTab(QWidget* tab);
    void appendProtocolTreeItem(const ProtocolPacketRecord& r, int vectorIndex);
    void refreshProtocolDetailFromSelection();
    void saveSelectedPacketAsTemplate(const QString& cardinalEs);
    void exportSelectedPacketAsJsonOrTxt();
    void showImportLogPreviewDialog(const QString& path);
    void applyProtocolLogFilters();
    void rebuildResourcesTableFromRecords();
    void refreshCharacterLabels();
    void updateResourcesFromIsoPayload(const QByteArray& payload);

#ifdef Q_OS_WIN
    [[nodiscard]] bool tryGetSelectedPid(quint32* outPid) const;
    [[nodiscard]] QString defaultRedirectDllPath() const;
#ifdef Q_OS_WIN
    [[nodiscard]] QString defaultTestDllPath() const;
#endif
    void appendMonitorLine(const QString& body);
    void kickGamePort5555AfterInject(quint32 pid, bool logIfZero);
    void kickAllOutboundAfterInject(quint32 pid);
    [[nodiscard]] QString peekLastDllLogHookLine() const;
    [[nodiscard]] QString buildHookDiagHtmlFromDllLog() const;
#endif
};
