#pragma once

#include <QMap>
#include <QString>
#include <QVector>

#include <QtGlobal>

/// Heurística por rangos y nombres concretos (Trigo, Ortiga, Castaño, Fresno, …).
class ResourcePredictor {
public:
    struct ResourceFamily {
        qint32 minId = 0;
        qint32 maxId = 0;
        QString familyName;
        QMap<qint32, QString> specificNames;
    };

    static const QVector<ResourceFamily>& families();

    /// Nombre conocido por ID exacto, o etiqueta de familia por rango; vacío si no coincide.
    [[nodiscard]] static QString predict(quint64 id);

    [[nodiscard]] static bool isLikelyGatherableResource(quint64 id) { return !predict(id).isEmpty(); }
};
