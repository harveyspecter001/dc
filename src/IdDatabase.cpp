#include "IdDatabase.h"

#include "ProtocolLogAnalyzer.h"

#include <QCoreApplication>
#include <QFile>
#include <QIODevice>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>

namespace {

void insertJsonObjectIntoMap(const QJsonObject& o, QHash<quint64, QString>* out)
{
    if (out == nullptr) {
        return;
    }
    for (auto it = o.constBegin(); it != o.constEnd(); ++it) {
        bool ok = false;
        const quint64 id = it.key().toULongLong(&ok);
        if (!ok || !it.value().isString()) {
            continue;
        }
        (*out)[id] = it.value().toString();
    }
}

} // namespace

void IdDatabase::clear()
{
    resources_.clear();
    monsters_.clear();
    players_.clear();
    objects_.clear();
    customNotes_.clear();
    resourceCaptureHex_.clear();
    monsterCaptureHex_.clear();
}

QString IdDatabase::defaultStoragePath()
{
    if (QCoreApplication::instance() != nullptr) {
        return QCoreApplication::applicationDirPath() + QStringLiteral("/ids_database.json");
    }
    return QStringLiteral("ids_database.json");
}

bool IdDatabase::loadFromFile(const QString& path, QString* errorOut)
{
    if (errorOut != nullptr) {
        errorOut->clear();
    }
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("No se puede leer ids_database.");
        }
        return false;
    }
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
    f.close();
    if (doc.isNull() || !doc.isObject()) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("JSON inválido: %1").arg(pe.errorString());
        }
        return false;
    }
    clear();
    const QJsonObject root = doc.object();
    insertJsonObjectIntoMap(root.value(QStringLiteral("resource_overrides")).toObject(), &resources_);
    insertJsonObjectIntoMap(root.value(QStringLiteral("monster_names")).toObject(), &monsters_);
    insertJsonObjectIntoMap(root.value(QStringLiteral("player_names")).toObject(), &players_);
    insertJsonObjectIntoMap(root.value(QStringLiteral("object_names")).toObject(), &objects_);
    insertJsonObjectIntoMap(root.value(QStringLiteral("custom_notes")).toObject(), &customNotes_);
    insertJsonObjectIntoMap(root.value(QStringLiteral("resource_capture_hex")).toObject(), &resourceCaptureHex_);
    insertJsonObjectIntoMap(root.value(QStringLiteral("monster_capture_hex")).toObject(), &monsterCaptureHex_);
    return true;
}

bool IdDatabase::saveToFile(const QString& path, QString* errorOut) const
{
    if (errorOut != nullptr) {
        errorOut->clear();
    }
    QJsonObject root;
    {
        QJsonObject o;
        for (auto it = resources_.constBegin(); it != resources_.constEnd(); ++it) {
            o.insert(QString::number(it.key()), it.value());
        }
        root.insert(QStringLiteral("resource_overrides"), o);
    }
    {
        QJsonObject o;
        for (auto it = monsters_.constBegin(); it != monsters_.constEnd(); ++it) {
            o.insert(QString::number(it.key()), it.value());
        }
        root.insert(QStringLiteral("monster_names"), o);
    }
    {
        QJsonObject o;
        for (auto it = players_.constBegin(); it != players_.constEnd(); ++it) {
            o.insert(QString::number(it.key()), it.value());
        }
        root.insert(QStringLiteral("player_names"), o);
    }
    {
        QJsonObject o;
        for (auto it = objects_.constBegin(); it != objects_.constEnd(); ++it) {
            o.insert(QString::number(it.key()), it.value());
        }
        root.insert(QStringLiteral("object_names"), o);
    }
    {
        QJsonObject o;
        for (auto it = customNotes_.constBegin(); it != customNotes_.constEnd(); ++it) {
            o.insert(QString::number(it.key()), it.value());
        }
        root.insert(QStringLiteral("custom_notes"), o);
    }
    {
        QJsonObject o;
        for (auto it = resourceCaptureHex_.constBegin(); it != resourceCaptureHex_.constEnd(); ++it) {
            o.insert(QString::number(it.key()), it.value());
        }
        root.insert(QStringLiteral("resource_capture_hex"), o);
    }
    {
        QJsonObject o;
        for (auto it = monsterCaptureHex_.constBegin(); it != monsterCaptureHex_.constEnd(); ++it) {
            o.insert(QString::number(it.key()), it.value());
        }
        root.insert(QStringLiteral("monster_capture_hex"), o);
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("No se puede escribir ids_database.");
        }
        return false;
    }
    f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    f.close();
    return true;
}

QVector<IdRangeRule> IdDatabase::toRangeRules() const
{
    QVector<IdRangeRule> out;
    auto add = [&out](const QHash<quint64, QString>& m, const QString& category) {
        for (auto it = m.constBegin(); it != m.constEnd(); ++it) {
            IdRangeRule r;
            r.lo = r.hi = it.key();
            r.label = it.value();
            r.category = category;
            out.push_back(r);
        }
    };
    add(resources_, QStringLiteral("recurso"));
    add(monsters_, QStringLiteral("monstruo"));
    add(players_, QStringLiteral("personaje"));
    add(objects_, QStringLiteral("objeto"));
    return out;
}
