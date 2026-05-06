#pragma once

#include <QByteArray>
#include <QString>
#include <QHash>

/// Persiste correcciones de tipo por huella SHA-256 del payload en `packet_type_overrides.json`.
class PacketTypeOverrides {
public:
    [[nodiscard]] static QString defaultStoragePath();

    bool load(QString* errorOut = nullptr);
    bool save(QString* errorOut = nullptr) const;

    [[nodiscard]] QString fingerprintHex(const QByteArray& payload) const;

    /// Etiqueta guardada para este payload, o vacío.
    [[nodiscard]] QString labelForPayload(const QByteArray& payload) const;

    void setLabelForPayload(const QByteArray& payload, const QString& label);

    void removeFingerprint(const QByteArray& payload);

private:
    QHash<QString, QString> fpToLabel_;
};
