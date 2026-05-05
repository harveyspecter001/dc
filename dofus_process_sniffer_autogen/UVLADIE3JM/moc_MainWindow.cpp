/****************************************************************************
** Meta object code from reading C++ file 'MainWindow.h'
**
** Created by: The Qt Meta Object Compiler version 69 (Qt 6.11.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../src/MainWindow.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'MainWindow.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 69
#error "This file was generated using the moc from 6.11.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {
struct qt_meta_tag_ZN10MainWindowE_t {};
} // unnamed namespace

template <> constexpr inline auto MainWindow::qt_create_metaobjectdata<qt_meta_tag_ZN10MainWindowE_t>()
{
    namespace QMC = QtMocConstants;
    QtMocHelpers::StringRefStorage qt_stringData {
        "MainWindow",
        "refreshProcesses",
        "",
        "onStartProxySoloClicked",
        "onStopProxyClicked",
        "onApplyUpstreamClicked",
        "onStartProxyWithDllClicked",
        "appendProxyLog",
        "line",
        "reloadDirectionMapClicked",
        "updateTunnelStatus",
        "tunnelReadyWithClient",
        "refreshConnectionMonitor",
        "openDiagnosticsLogWindow",
        "onTestProxyClicked",
        "onTestUpstreamClicked",
        "syncProxyOptionsFromUi",
        "onProcessMonitorStart",
        "onProcessMonitorStop",
        "onDofusDetectedInject",
        "pid",
        "onFullDiagnosticClicked",
        "onApplyHostsClicked",
        "onRestoreHostsClicked",
        "onInjectDllClicked",
        "onInjectTestDllClicked",
        "onManualWinsockConnectClicked",
        "onNetstat5555Clicked",
        "onProtocolPayloadCaptured",
        "fromClient",
        "payload",
        "onRefreshResourcesFromLogsClicked",
        "onImportExportedLogClicked",
        "onClearProtocolLogClicked",
        "onProtocolFilterChanged",
        "onProtocolLogCurrentItemChanged",
        "QTreeWidgetItem*",
        "current",
        "previous",
        "onProtocolLogContextMenu",
        "QPoint",
        "pos",
        "onIdAliasRulesChanged",
        "onEditIdsClicked",
        "onHarvestWaitTimeout",
        "onSaveIeeTemplateClicked",
        "onRecolectHarvestClicked"
    };

    QtMocHelpers::UintData qt_methods {
        // Slot 'refreshProcesses'
        QtMocHelpers::SlotData<void()>(1, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onStartProxySoloClicked'
        QtMocHelpers::SlotData<void()>(3, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onStopProxyClicked'
        QtMocHelpers::SlotData<void()>(4, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onApplyUpstreamClicked'
        QtMocHelpers::SlotData<void()>(5, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onStartProxyWithDllClicked'
        QtMocHelpers::SlotData<void()>(6, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'appendProxyLog'
        QtMocHelpers::SlotData<void(const QString &)>(7, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { QMetaType::QString, 8 },
        }}),
        // Slot 'reloadDirectionMapClicked'
        QtMocHelpers::SlotData<void()>(9, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'updateTunnelStatus'
        QtMocHelpers::SlotData<void(bool)>(10, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { QMetaType::Bool, 11 },
        }}),
        // Slot 'refreshConnectionMonitor'
        QtMocHelpers::SlotData<void()>(12, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'openDiagnosticsLogWindow'
        QtMocHelpers::SlotData<void()>(13, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onTestProxyClicked'
        QtMocHelpers::SlotData<void()>(14, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onTestUpstreamClicked'
        QtMocHelpers::SlotData<void()>(15, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'syncProxyOptionsFromUi'
        QtMocHelpers::SlotData<void()>(16, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onProcessMonitorStart'
        QtMocHelpers::SlotData<void()>(17, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onProcessMonitorStop'
        QtMocHelpers::SlotData<void()>(18, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onDofusDetectedInject'
        QtMocHelpers::SlotData<void(quint32)>(19, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { QMetaType::UInt, 20 },
        }}),
        // Slot 'onFullDiagnosticClicked'
        QtMocHelpers::SlotData<void()>(21, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onApplyHostsClicked'
        QtMocHelpers::SlotData<void()>(22, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onRestoreHostsClicked'
        QtMocHelpers::SlotData<void()>(23, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onInjectDllClicked'
        QtMocHelpers::SlotData<void()>(24, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onInjectTestDllClicked'
        QtMocHelpers::SlotData<void()>(25, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onManualWinsockConnectClicked'
        QtMocHelpers::SlotData<void()>(26, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onNetstat5555Clicked'
        QtMocHelpers::SlotData<void()>(27, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onProtocolPayloadCaptured'
        QtMocHelpers::SlotData<void(bool, const QByteArray &)>(28, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { QMetaType::Bool, 29 }, { QMetaType::QByteArray, 30 },
        }}),
        // Slot 'onRefreshResourcesFromLogsClicked'
        QtMocHelpers::SlotData<void()>(31, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onImportExportedLogClicked'
        QtMocHelpers::SlotData<void()>(32, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onClearProtocolLogClicked'
        QtMocHelpers::SlotData<void()>(33, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onProtocolFilterChanged'
        QtMocHelpers::SlotData<void()>(34, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onProtocolLogCurrentItemChanged'
        QtMocHelpers::SlotData<void(QTreeWidgetItem *, QTreeWidgetItem *)>(35, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { 0x80000000 | 36, 37 }, { 0x80000000 | 36, 38 },
        }}),
        // Slot 'onProtocolLogContextMenu'
        QtMocHelpers::SlotData<void(const QPoint &)>(39, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { 0x80000000 | 40, 41 },
        }}),
        // Slot 'onIdAliasRulesChanged'
        QtMocHelpers::SlotData<void()>(42, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onEditIdsClicked'
        QtMocHelpers::SlotData<void()>(43, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onHarvestWaitTimeout'
        QtMocHelpers::SlotData<void()>(44, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onSaveIeeTemplateClicked'
        QtMocHelpers::SlotData<void()>(45, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onRecolectHarvestClicked'
        QtMocHelpers::SlotData<void()>(46, 2, QMC::AccessPrivate, QMetaType::Void),
    };
    QtMocHelpers::UintData qt_properties {
    };
    QtMocHelpers::UintData qt_enums {
    };
    return QtMocHelpers::metaObjectData<MainWindow, qt_meta_tag_ZN10MainWindowE_t>(QMC::MetaObjectFlag{}, qt_stringData,
            qt_methods, qt_properties, qt_enums);
}
Q_CONSTINIT const QMetaObject MainWindow::staticMetaObject = { {
    QMetaObject::SuperData::link<QMainWindow::staticMetaObject>(),
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10MainWindowE_t>.stringdata,
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10MainWindowE_t>.data,
    qt_static_metacall,
    nullptr,
    qt_staticMetaObjectRelocatingContent<qt_meta_tag_ZN10MainWindowE_t>.metaTypes,
    nullptr
} };

void MainWindow::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<MainWindow *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->refreshProcesses(); break;
        case 1: _t->onStartProxySoloClicked(); break;
        case 2: _t->onStopProxyClicked(); break;
        case 3: _t->onApplyUpstreamClicked(); break;
        case 4: _t->onStartProxyWithDllClicked(); break;
        case 5: _t->appendProxyLog((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1]))); break;
        case 6: _t->reloadDirectionMapClicked(); break;
        case 7: _t->updateTunnelStatus((*reinterpret_cast<std::add_pointer_t<bool>>(_a[1]))); break;
        case 8: _t->refreshConnectionMonitor(); break;
        case 9: _t->openDiagnosticsLogWindow(); break;
        case 10: _t->onTestProxyClicked(); break;
        case 11: _t->onTestUpstreamClicked(); break;
        case 12: _t->syncProxyOptionsFromUi(); break;
        case 13: _t->onProcessMonitorStart(); break;
        case 14: _t->onProcessMonitorStop(); break;
        case 15: _t->onDofusDetectedInject((*reinterpret_cast<std::add_pointer_t<quint32>>(_a[1]))); break;
        case 16: _t->onFullDiagnosticClicked(); break;
        case 17: _t->onApplyHostsClicked(); break;
        case 18: _t->onRestoreHostsClicked(); break;
        case 19: _t->onInjectDllClicked(); break;
        case 20: _t->onInjectTestDllClicked(); break;
        case 21: _t->onManualWinsockConnectClicked(); break;
        case 22: _t->onNetstat5555Clicked(); break;
        case 23: _t->onProtocolPayloadCaptured((*reinterpret_cast<std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QByteArray>>(_a[2]))); break;
        case 24: _t->onRefreshResourcesFromLogsClicked(); break;
        case 25: _t->onImportExportedLogClicked(); break;
        case 26: _t->onClearProtocolLogClicked(); break;
        case 27: _t->onProtocolFilterChanged(); break;
        case 28: _t->onProtocolLogCurrentItemChanged((*reinterpret_cast<std::add_pointer_t<QTreeWidgetItem*>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QTreeWidgetItem*>>(_a[2]))); break;
        case 29: _t->onProtocolLogContextMenu((*reinterpret_cast<std::add_pointer_t<QPoint>>(_a[1]))); break;
        case 30: _t->onIdAliasRulesChanged(); break;
        case 31: _t->onEditIdsClicked(); break;
        case 32: _t->onHarvestWaitTimeout(); break;
        case 33: _t->onSaveIeeTemplateClicked(); break;
        case 34: _t->onRecolectHarvestClicked(); break;
        default: ;
        }
    }
}

const QMetaObject *MainWindow::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *MainWindow::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10MainWindowE_t>.strings))
        return static_cast<void*>(this);
    return QMainWindow::qt_metacast(_clname);
}

int MainWindow::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 35)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 35;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 35)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 35;
    }
    return _id;
}
QT_WARNING_POP
