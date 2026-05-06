#include "ResourcePredictor.h"

#include <algorithm>
#include <limits>

static QVector<ResourcePredictor::ResourceFamily> buildFamilies()
{
    using RF = ResourcePredictor::ResourceFamily;
    QVector<RF> v;
    v.reserve(6);

    {
        RF f;
        f.minId = 513600;
        f.maxId = 513699;
        f.familyName = QStringLiteral("Trigo");
        f.specificNames = {{513616, QStringLiteral("Trigo")},
                             {513618, QStringLiteral("Trigo")},
                             {513621, QStringLiteral("Trigo")}};
        v.push_back(f);
    }
    {
        RF f;
        f.minId = 513800;
        f.maxId = 513899;
        f.familyName = QStringLiteral("Ortiga");
        f.specificNames = {{513836, QStringLiteral("Ortiga")},
                             {513837, QStringLiteral("Ortiga")},
                             {513867, QStringLiteral("Salvia")}};
        v.push_back(f);
    }
    {
        RF f;
        f.minId = 514000;
        f.maxId = 514099;
        f.familyName = QStringLiteral("Castaño");
        f.specificNames = {{514038, QStringLiteral("Castaño")},
                             {514213, QStringLiteral("Castaño")}};
        v.push_back(f);
    }
    {
        RF f;
        f.minId = 514200;
        f.maxId = 514699;
        f.familyName = QStringLiteral("Fresno");
        f.specificNames = {{514211, QStringLiteral("Fresno")},
                             {514593, QStringLiteral("Fresno")},
                             {514654, QStringLiteral("Fresno")},
                             {514655, QStringLiteral("Fresno")},
                             {514656, QStringLiteral("Fresno")},
                             {514657, QStringLiteral("Fresno")}};
        v.push_back(f);
    }
    return v;
}

const QVector<ResourcePredictor::ResourceFamily>& ResourcePredictor::families()
{
    static const QVector<ResourceFamily> kFam = buildFamilies();
    return kFam;
}

QString ResourcePredictor::predict(quint64 id64)
{
    if (id64 > quint64(std::numeric_limits<qint32>::max())) {
        return {};
    }
    const qint32 id = static_cast<qint32>(id64);
    for (const ResourceFamily& fam : families()) {
        if (fam.specificNames.contains(id)) {
            return fam.specificNames.value(id);
        }
    }
    for (const ResourceFamily& fam : families()) {
        if (id >= fam.minId && id <= fam.maxId) {
            return fam.familyName;
        }
    }
    return {};
}
