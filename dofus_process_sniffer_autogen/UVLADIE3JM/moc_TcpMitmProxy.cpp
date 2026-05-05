/****************************************************************************
** Meta object code from reading C++ file 'TcpMitmProxy.h'
**
** Created by: The Qt Meta Object Compiler version 69 (Qt 6.11.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../src/TcpMitmProxy.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'TcpMitmProxy.h' doesn't include <QObject>."
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
struct qt_meta_tag_ZN12TcpMitmProxyE_t {};
} // unnamed namespace

template <> constexpr inline auto TcpMitmProxy::qt_create_metaobjectdata<qt_meta_tag_ZN12TcpMitmProxyE_t>()
{
    namespace QMC = QtMocConstants;
    QtMocHelpers::StringRefStorage qt_stringData {
        "TcpMitmProxy",
        "listeningChanged",
        "",
        "on",
        "logLine",
        "line",
        "protocolPayloadCaptured",
        "fromClient",
        "payload",
        "tunnelReadyChanged",
        "ready",
        "start",
        "bindAddress",
        "bindPort",
        "remoteHost",
        "remotePort",
        "startListenOnly",
        "stop",
        "setRemoteEndpoint",
        "setUpstream",
        "host",
        "port",
        "connectUpstreamForCurrentSession",
        "injectTowardServer",
        "data",
        "onNewConnection",
        "pumpClientUpstream",
        "pumpUpstreamClient",
        "pumpClientEchoOnly",
        "pumpClientMinimalOnly",
        "onUpstreamConnected",
        "onUpstreamDisconnected",
        "onUpstreamSocketError",
        "QAbstractSocket::SocketError",
        "socketError",
        "teardown",
        "reason",
        "onUpstreamBytesWritten",
        "bytes",
        "onClientBytesWritten",
        "onUpstreamConnectWatchTimeout",
        "onUpstreamNoResponseTimeout",
        "onAutoUpstreamWatchTick"
    };

    QtMocHelpers::UintData qt_methods {
        // Signal 'listeningChanged'
        QtMocHelpers::SignalData<void(bool)>(1, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Bool, 3 },
        }}),
        // Signal 'logLine'
        QtMocHelpers::SignalData<void(const QString &)>(4, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 5 },
        }}),
        // Signal 'protocolPayloadCaptured'
        QtMocHelpers::SignalData<void(bool, const QByteArray &)>(6, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Bool, 7 }, { QMetaType::QByteArray, 8 },
        }}),
        // Signal 'tunnelReadyChanged'
        QtMocHelpers::SignalData<void(bool)>(9, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Bool, 10 },
        }}),
        // Slot 'start'
        QtMocHelpers::SlotData<bool(const QString &, quint16, const QString &, quint16)>(11, 2, QMC::AccessPublic, QMetaType::Bool, {{
            { QMetaType::QString, 12 }, { QMetaType::UShort, 13 }, { QMetaType::QString, 14 }, { QMetaType::UShort, 15 },
        }}),
        // Slot 'startListenOnly'
        QtMocHelpers::SlotData<bool(const QString &, quint16)>(16, 2, QMC::AccessPublic, QMetaType::Bool, {{
            { QMetaType::QString, 12 }, { QMetaType::UShort, 13 },
        }}),
        // Slot 'stop'
        QtMocHelpers::SlotData<void()>(17, 2, QMC::AccessPublic, QMetaType::Void),
        // Slot 'setRemoteEndpoint'
        QtMocHelpers::SlotData<void(const QString &, quint16)>(18, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 14 }, { QMetaType::UShort, 15 },
        }}),
        // Slot 'setUpstream'
        QtMocHelpers::SlotData<void(const QString &, int)>(19, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 20 }, { QMetaType::Int, 21 },
        }}),
        // Slot 'connectUpstreamForCurrentSession'
        QtMocHelpers::SlotData<void()>(22, 2, QMC::AccessPublic, QMetaType::Void),
        // Slot 'injectTowardServer'
        QtMocHelpers::SlotData<QString(const QByteArray &)>(23, 2, QMC::AccessPublic, QMetaType::QString, {{
            { QMetaType::QByteArray, 24 },
        }}),
        // Slot 'onNewConnection'
        QtMocHelpers::SlotData<void()>(25, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'pumpClientUpstream'
        QtMocHelpers::SlotData<void()>(26, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'pumpUpstreamClient'
        QtMocHelpers::SlotData<void()>(27, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'pumpClientEchoOnly'
        QtMocHelpers::SlotData<void()>(28, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'pumpClientMinimalOnly'
        QtMocHelpers::SlotData<void()>(29, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onUpstreamConnected'
        QtMocHelpers::SlotData<void()>(30, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onUpstreamDisconnected'
        QtMocHelpers::SlotData<void()>(31, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onUpstreamSocketError'
        QtMocHelpers::SlotData<void(QAbstractSocket::SocketError)>(32, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { 0x80000000 | 33, 34 },
        }}),
        // Slot 'teardown'
        QtMocHelpers::SlotData<void(const QString &)>(35, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { QMetaType::QString, 36 },
        }}),
        // Slot 'onUpstreamBytesWritten'
        QtMocHelpers::SlotData<void(qint64)>(37, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { QMetaType::LongLong, 38 },
        }}),
        // Slot 'onClientBytesWritten'
        QtMocHelpers::SlotData<void(qint64)>(39, 2, QMC::AccessPrivate, QMetaType::Void, {{
            { QMetaType::LongLong, 38 },
        }}),
        // Slot 'onUpstreamConnectWatchTimeout'
        QtMocHelpers::SlotData<void()>(40, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onUpstreamNoResponseTimeout'
        QtMocHelpers::SlotData<void()>(41, 2, QMC::AccessPrivate, QMetaType::Void),
        // Slot 'onAutoUpstreamWatchTick'
        QtMocHelpers::SlotData<void()>(42, 2, QMC::AccessPrivate, QMetaType::Void),
    };
    QtMocHelpers::UintData qt_properties {
    };
    QtMocHelpers::UintData qt_enums {
    };
    return QtMocHelpers::metaObjectData<TcpMitmProxy, qt_meta_tag_ZN12TcpMitmProxyE_t>(QMC::MetaObjectFlag{}, qt_stringData,
            qt_methods, qt_properties, qt_enums);
}
Q_CONSTINIT const QMetaObject TcpMitmProxy::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN12TcpMitmProxyE_t>.stringdata,
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN12TcpMitmProxyE_t>.data,
    qt_static_metacall,
    nullptr,
    qt_staticMetaObjectRelocatingContent<qt_meta_tag_ZN12TcpMitmProxyE_t>.metaTypes,
    nullptr
} };

void TcpMitmProxy::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<TcpMitmProxy *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->listeningChanged((*reinterpret_cast<std::add_pointer_t<bool>>(_a[1]))); break;
        case 1: _t->logLine((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1]))); break;
        case 2: _t->protocolPayloadCaptured((*reinterpret_cast<std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<QByteArray>>(_a[2]))); break;
        case 3: _t->tunnelReadyChanged((*reinterpret_cast<std::add_pointer_t<bool>>(_a[1]))); break;
        case 4: { bool _r = _t->start((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<quint16>>(_a[2])),(*reinterpret_cast<std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast<std::add_pointer_t<quint16>>(_a[4])));
            if (_a[0]) *reinterpret_cast<bool*>(_a[0]) = std::move(_r); }  break;
        case 5: { bool _r = _t->startListenOnly((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<quint16>>(_a[2])));
            if (_a[0]) *reinterpret_cast<bool*>(_a[0]) = std::move(_r); }  break;
        case 6: _t->stop(); break;
        case 7: _t->setRemoteEndpoint((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<quint16>>(_a[2]))); break;
        case 8: _t->setUpstream((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast<std::add_pointer_t<int>>(_a[2]))); break;
        case 9: _t->connectUpstreamForCurrentSession(); break;
        case 10: { QString _r = _t->injectTowardServer((*reinterpret_cast<std::add_pointer_t<QByteArray>>(_a[1])));
            if (_a[0]) *reinterpret_cast<QString*>(_a[0]) = std::move(_r); }  break;
        case 11: _t->onNewConnection(); break;
        case 12: _t->pumpClientUpstream(); break;
        case 13: _t->pumpUpstreamClient(); break;
        case 14: _t->pumpClientEchoOnly(); break;
        case 15: _t->pumpClientMinimalOnly(); break;
        case 16: _t->onUpstreamConnected(); break;
        case 17: _t->onUpstreamDisconnected(); break;
        case 18: _t->onUpstreamSocketError((*reinterpret_cast<std::add_pointer_t<QAbstractSocket::SocketError>>(_a[1]))); break;
        case 19: _t->teardown((*reinterpret_cast<std::add_pointer_t<QString>>(_a[1]))); break;
        case 20: _t->onUpstreamBytesWritten((*reinterpret_cast<std::add_pointer_t<qint64>>(_a[1]))); break;
        case 21: _t->onClientBytesWritten((*reinterpret_cast<std::add_pointer_t<qint64>>(_a[1]))); break;
        case 22: _t->onUpstreamConnectWatchTimeout(); break;
        case 23: _t->onUpstreamNoResponseTimeout(); break;
        case 24: _t->onAutoUpstreamWatchTick(); break;
        default: ;
        }
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType(); break;
        case 18:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType(); break;
            case 0:
                *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType::fromType< QAbstractSocket::SocketError >(); break;
            }
            break;
        }
    }
    if (_c == QMetaObject::IndexOfMethod) {
        if (QtMocHelpers::indexOfMethod<void (TcpMitmProxy::*)(bool )>(_a, &TcpMitmProxy::listeningChanged, 0))
            return;
        if (QtMocHelpers::indexOfMethod<void (TcpMitmProxy::*)(const QString & )>(_a, &TcpMitmProxy::logLine, 1))
            return;
        if (QtMocHelpers::indexOfMethod<void (TcpMitmProxy::*)(bool , const QByteArray & )>(_a, &TcpMitmProxy::protocolPayloadCaptured, 2))
            return;
        if (QtMocHelpers::indexOfMethod<void (TcpMitmProxy::*)(bool )>(_a, &TcpMitmProxy::tunnelReadyChanged, 3))
            return;
    }
}

const QMetaObject *TcpMitmProxy::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *TcpMitmProxy::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_staticMetaObjectStaticContent<qt_meta_tag_ZN12TcpMitmProxyE_t>.strings))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int TcpMitmProxy::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 25)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 25;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 25)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 25;
    }
    return _id;
}

// SIGNAL 0
void TcpMitmProxy::listeningChanged(bool _t1)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 0, nullptr, _t1);
}

// SIGNAL 1
void TcpMitmProxy::logLine(const QString & _t1)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 1, nullptr, _t1);
}

// SIGNAL 2
void TcpMitmProxy::protocolPayloadCaptured(bool _t1, const QByteArray & _t2)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 2, nullptr, _t1, _t2);
}

// SIGNAL 3
void TcpMitmProxy::tunnelReadyChanged(bool _t1)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 3, nullptr, _t1);
}
QT_WARNING_POP
