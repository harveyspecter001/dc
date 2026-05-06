#pragma once

#include <QHash>
#include <QString>
#include <QVector>

struct IdRangeRule;

/// `ids_database.json` — sobrescrituras por ID y notas editables desde la pestaña Recursos.
class IdDatabase {
public:
    void clear();

    [[nodiscard]] static QString defaultStoragePath();

    /// Carga desde JSON en disco; errores opcionales.
    [[nodiscard]] bool loadFromFile(const QString& path, QString* errorOut = nullptr);

    [[nodiscard]] bool saveToFile(const QString& path, QString* errorOut = nullptr) const;

    /// Reglas `lo == hi == id` concatenadas después de texto «Alias por rangos» y antes del builtin merge.
    [[nodiscard]] QVector<IdRangeRule> toRangeRules() const;

    [[nodiscard]] const QHash<quint64, QString>& customNotesById() const { return customNotes_; }

    void setMonsterNames(const QHash<quint64, QString>& m) { monsters_ = m; }
    void setPlayerNames(const QHash<quint64, QString>& m) { players_ = m; }
    void setResourceOverrides(const QHash<quint64, QString>& m) { resources_ = m; }
    void setObjectNames(const QHash<quint64, QString>& m) { objects_ = m; }
    void setCustomNotes(const QHash<quint64, QString>& m) { customNotes_ = m; }

    [[nodiscard]] const QHash<quint64, QString>& resourceOverrides() const { return resources_; }
    [[nodiscard]] const QHash<quint64, QString>& monsterNames() const { return monsters_; }
    [[nodiscard]] const QHash<quint64, QString>& playerNames() const { return players_; }
    [[nodiscard]] const QHash<quint64, QString>& objectNames() const { return objects_; }

    /// Hex ASCII del último paquete de mapa desde el que se guardó el candidato (estudio offline).
    [[nodiscard]] const QHash<quint64, QString>& resourceCaptureHex() const { return resourceCaptureHex_; }
    [[nodiscard]] const QHash<quint64, QString>& monsterCaptureHex() const { return monsterCaptureHex_; }
    void setResourceCaptureHex(const QHash<quint64, QString>& m) { resourceCaptureHex_ = m; }
    void setMonsterCaptureHex(const QHash<quint64, QString>& m) { monsterCaptureHex_ = m; }

private:
    QHash<quint64, QString> resources_;
    QHash<quint64, QString> monsters_;
    QHash<quint64, QString> players_;
    QHash<quint64, QString> objects_;
    QHash<quint64, QString> customNotes_;
    QHash<quint64, QString> resourceCaptureHex_;
    QHash<quint64, QString> monsterCaptureHex_;
};
