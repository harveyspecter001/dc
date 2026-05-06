#include "PacketTypeOverrides.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QIODevice>
#include <QJsonDocument>
#include <QJsonObject>

QString PacketTypeOverrides::defaultStoragePath()
{
    if (QCoreApplication::instance() != nullptr) {
        return QCoreApplication::applicationDirPath() + QStringLiteral("/packet_type_overrides.json");
    }
    return QStringLiteral("packet_type_overrides.json");
}

QString PacketTypeOverrides::fingerprintHex(const QByteArray& payload) const
{
    return QString::fromLatin1(QCryptographicHash::hash(payload, QCryptographicHash::Sha256).toHex());
}

bool PacketTypeOverrides::load(QString* errorOut)
{
    if (errorOut != nullptr) {
        errorOut->clear();
    }
    fpToLabel_.clear();
    const QString path = defaultStoragePath();
    QFile f(path);
    if (!f.exists()) {
        return true;
    }
    if (!f.open(QIODevice::ReadOnly)) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("No se puede leer %1").arg(path);
        }
        return false;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject()) {
        return true;
    }
    const QJsonObject root = doc.object();
    const QJsonObject fps = root.value(QStringLiteral("fingerprints")).toObject();
    for (auto it = fps.constBegin(); it != fps.constEnd(); ++it) {
        if (it.value().isString()) {
            fpToLabel_[it.key()] = it.value().toString();
        }
    }
    return true;
}

bool PacketTypeOverrides::save(QString* errorOut) const
{
    if (errorOut != nullptr) {
        errorOut->clear();
    }
    QJsonObject fps;
    for (auto it = fpToLabel_.constBegin(); it != fpToLabel_.constEnd(); ++it) {
        fps.insert(it.key(), it.value());
    }
    QJsonObject root;
    root.insert(QStringLiteral("fingerprints"), fps);

    QFile f(defaultStoragePath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("No se puede escribir packet_type_overrides.json");
        }
        return false;
    }
    f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    f.close();
    return true;
}

QString PacketTypeOverrides::labelForPayload(const QByteArray& payload) const
{
    const QString fp = fingerprintHex(payload);
    return fpToLabel_.value(fp);
}

void PacketTypeOverrides::setLabelForPayload(const QByteArray& payload, const QString& label)
{
    const QString fp = fingerprintHex(payload);
    if (label.trimmed().isEmpty()) {
        fpToLabel_.remove(fp);
        return;
    }
    fpToLabel_[fp] = label.trimmed();
}

void PacketTypeOverrides::removeFingerprint(const QByteArray& payload)
{
    fpToLabel_.remove(fingerprintHex(payload));
}
