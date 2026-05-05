#pragma once

#include <QByteArray>
#include <QHash>
#include <QString>
#include <QStringList>

struct DirectionMapModel {
    int offset = 0;
    QString tipo;
    QHash<QString, qint32> mapeo;
    QHash<QString, QByteArray> plantillasPorCardinal;
};

/// Resultado de validar un payload de aplicación que debería ser movimiento ☆iri.
struct IriPacketAnalysis {
    bool validStrictUrl = false;
    bool payloadSizeOk = false;
    int payloadSize = 0;
    QByteArray sessionToken5;
    int routeByteCount = 0;
    bool routeLengthOk = false;
    QString inferredCardinal;
    QStringList warnings;
    QStringList errors;

    [[nodiscard]] bool overallAcceptableForInjection() const
    {
        return errors.isEmpty() && validStrictUrl && payloadSizeOk && routeLengthOk;
    }
};

/// Misma idea que `_apply_emulated_cardinal` + `ejemplos_hex` del Python (`direcciones_map.json`).
class IriCardinalEmulator {
public:
    static QString normalizeCardinal(const QString& label);

    bool loadFromFile(const QString& path, QString* errOut);

    const DirectionMapModel* model() const { return modeloCargado_ ? &modelo_ : nullptr; }

    bool pickCrossBase(const QString& destCardinal, QByteArray* baseOut, QString* sourceCardOut) const;

    bool patchTowardCardinal(const QByteArray& baseBlob, const QString& destCardinal, QByteArray* patchedOut,
                             QString* debugOut) const;

    QString loadedPath_;

private:
    bool modeloCargado_ = false;
    DirectionMapModel modelo_;
};

bool payloadHasAnkamaIri(const QByteArray& data);

[[nodiscard]] IriPacketAnalysis analyzeIriPayload(const QByteArray& payload,
                                                  const DirectionMapModel* modelOrNull);

[[nodiscard]] QString formatSessionTokenHex(const QByteArray& fiveBytes);

/// Primer bloque hex ≥50 B en el archivo exportado que supere la validación estricta ☆iri.
[[nodiscard]] bool findFirstValidIriInExportLog(const QString& logFilePath, QByteArray* outPayload,
                                              int* packetIndexOut, IriPacketAnalysis* analysisOut,
                                              QString* errOut);

[[nodiscard]] bool mergeEjemploHexIntoDirectionMapJson(const QString& directionMapJsonPath,
                                                       const QString& cardinalNormalized,
                                                       const QByteArray& rawPayload, QString* errOut);

[[nodiscard]] bool saveTemplatesJsonSidecar(const QString& directionMapJsonPath, const QString& cardinalNormalized,
                                            const QByteArray& rawPayload, const IriPacketAnalysis& analysis,
                                            const QString& sourceLogPath, QString* errOut);
