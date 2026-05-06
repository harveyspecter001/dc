#include "ProtocolLogAnalyzer.h"
#include "PacketTypeOverrides.h"
#include "ProtobufParser.h"

#include <QHash>
#include <QStringList>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>
#include <QtGlobal>

#include <algorithm>

namespace {

bool looksLikeHexContinuationLine(const QString& line)
{
    if (line.size() < 2) {
        return false;
    }
    for (QChar c : line) {
        if (c.isSpace()) {
            continue;
        }
        const ushort u = c.unicode();
        if ((u >= '0' && u <= '9') || (u >= 'a' && u <= 'f') || (u >= 'A' && u <= 'F')) {
            continue;
        }
        return false;
    }
    return true;
}

bool readOneVarint(const QByteArray& d, int* offsetInOut, quint64* valueOut)
{
    if (offsetInOut == nullptr || valueOut == nullptr) {
        return false;
    }
    int i = *offsetInOut;
    quint64 result = 0;
    int shift = 0;
    while (i < d.size()) {
        const unsigned char b = static_cast<unsigned char>(d.at(i));
        ++i;
        result |= quint64(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            *offsetInOut = i;
            *valueOut = result;
            return true;
        }
        shift += 7;
        if (shift > 63) {
            return false;
        }
    }
    return false;
}

void scanAllVarints(const QByteArray& d, QList<quint64>* out)
{
    if (out == nullptr) {
        return;
    }
    for (int pos = 0; pos < d.size(); ++pos) {
        int off = pos;
        quint64 v = 0;
        if (readOneVarint(d, &off, &v)) {
            out->push_back(v);
        }
    }
}

} // namespace

static bool ankamaUrlSuffixInList(const QStringList& urls, QLatin1String sufWithSlash)
{
    for (const QString& u : urls) {
        if (u.endsWith(sufWithSlash, Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

static bool utf16LeContainsLatin1(const QByteArray& p, QLatin1String ascii)
{
    QByteArray needle;
    needle.reserve(ascii.size() * 2);
    const QByteArray a = QByteArray(ascii);
    for (int i = 0; i < a.size(); ++i) {
        needle.append(static_cast<char>(static_cast<unsigned char>(a.at(i))));
        needle.append(char(0));
    }
    return p.contains(needle);
}

static void mergeAnkamaTypeUrlStrings(const QByteArray& payload, QStringList* out)
{
    if (out == nullptr) {
        return;
    }
    extractAnkamaTypeUrls(payload, out);
    static const QRegularExpression re(QStringLiteral(R"(type\.ankama\.com/[a-z]+)"));
    const QString latin = QString::fromLatin1(payload);
    for (auto it = re.globalMatch(latin); it.hasNext();) {
        const QString cap = it.next().captured(0);
        if (!out->contains(cap)) {
            out->append(cap);
        }
    }
}

static PacketKind kindFromUrlListPriority(const QStringList& urls)
{
    static const QVector<QPair<QString, PacketKind>> order = {
        qMakePair(QStringLiteral("iri"), PacketKind::IriMovement),
        qMakePair(QStringLiteral("iee"), PacketKind::IeeHarvest),
        qMakePair(QStringLiteral("irl"), PacketKind::IrlList),
        qMakePair(QStringLiteral("iso"), PacketKind::IsoResources),
        qMakePair(QStringLiteral("irx"), PacketKind::IrxMonsters),
        qMakePair(QStringLiteral("idr"), PacketKind::IdrItemReceived),
        qMakePair(QStringLiteral("idy"), PacketKind::IdyItemDisplayed),
        qMakePair(QStringLiteral("idw"), PacketKind::IdwItemVanished),
        qMakePair(QStringLiteral("isl"), PacketKind::IslEntities),
        qMakePair(QStringLiteral("isu"), PacketKind::IsuClientSync),
        qMakePair(QStringLiteral("irk"), PacketKind::IrkSyncResponse),
        qMakePair(QStringLiteral("isa"), PacketKind::IsaPingClient),
        qMakePair(QStringLiteral("itr"), PacketKind::ItrMapTransitClient),
        qMakePair(QStringLiteral("ish"), PacketKind::IshMapTinyServer),
        qMakePair(QStringLiteral("ito"), PacketKind::ItoMapTransitClient),
        qMakePair(QStringLiteral("iue"), PacketKind::MapHydrateTripleServer),
        qMakePair(QStringLiteral("iuc"), PacketKind::MapHydrateTripleServer),
        qMakePair(QStringLiteral("knw"), PacketKind::MapHydrateTripleServer),
        qMakePair(QStringLiteral("jsa"), PacketKind::JsaPulseClient),
        qMakePair(QStringLiteral("jsb"), PacketKind::JsbPulseServer),
        qMakePair(QStringLiteral("itx"), PacketKind::ItxMapHeavyServer),
        qMakePair(QStringLiteral("kta"), PacketKind::KtaKeyedServer),
        qMakePair(QStringLiteral("ier"), PacketKind::MapGatherIerSnapshotServer),
        qMakePair(QStringLiteral("iev"), PacketKind::MapGatherIevTapClient),
        qMakePair(QStringLiteral("ieu"), PacketKind::MapGatherIeuBundleServer),
        qMakePair(QStringLiteral("iet"), PacketKind::MapGatherIeuBundleServer),
        qMakePair(QStringLiteral("ies"), PacketKind::MapGatherIeuBundleServer),
        qMakePair(QStringLiteral("isp"), PacketKind::IspSync),
        qMakePair(QStringLiteral("itv"), PacketKind::ItvInteraction),
        qMakePair(QStringLiteral("kj"), PacketKind::KjCompression),
        qMakePair(QStringLiteral("jmw"), PacketKind::JmwMonsterCmd),
        qMakePair(QStringLiteral("jrt"), PacketKind::CommandData),
        qMakePair(QStringLiteral("jrr"), PacketKind::JrrCommandResponse),
    };
    for (const auto& pr : order) {
        const QString suf = QLatin1Char('/') + pr.first;
        for (const QString& u : urls) {
            if (u.endsWith(suf)) {
                return pr.second;
            }
        }
    }
    return PacketKind::Unknown;
}

static PacketKind classifyPacketKindByRawMarkers(const QByteArray& payload)
{
    if (payload.contains(QByteArrayLiteral("type.ankama.com/iri"))) {
        return PacketKind::IriMovement;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/iee"))) {
        return PacketKind::IeeHarvest;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/iso"))) {
        return PacketKind::IsoResources;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/irx"))) {
        return PacketKind::IrxMonsters;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/irl"))) {
        return PacketKind::IrlList;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/idr"))) {
        return PacketKind::IdrItemReceived;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/idy"))) {
        return PacketKind::IdyItemDisplayed;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/idw"))) {
        return PacketKind::IdwItemVanished;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/isl"))) {
        return PacketKind::IslEntities;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/isu"))) {
        return PacketKind::IsuClientSync;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/irk"))) {
        return PacketKind::IrkSyncResponse;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/jnr"))
        && payload.contains(QByteArrayLiteral("type.ankama.com/isp"))) {
        return PacketKind::MapHopJnrIspClient;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/isa"))) {
        return PacketKind::IsaPingClient;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/itr"))) {
        return PacketKind::ItrMapTransitClient;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/ish"))) {
        return PacketKind::IshMapTinyServer;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/ito"))) {
        return PacketKind::ItoMapTransitClient;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/iue"))
        || payload.contains(QByteArrayLiteral("type.ankama.com/iuc"))
        || payload.contains(QByteArrayLiteral("type.ankama.com/knw"))) {
        return PacketKind::MapHydrateTripleServer;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/jsa"))) {
        return PacketKind::JsaPulseClient;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/jsb"))) {
        return PacketKind::JsbPulseServer;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/itx"))) {
        return PacketKind::ItxMapHeavyServer;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/kta"))) {
        return PacketKind::KtaKeyedServer;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/ier"))) {
        return PacketKind::MapGatherIerSnapshotServer;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/iev"))) {
        return PacketKind::MapGatherIevTapClient;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/ieu"))
        || payload.contains(QByteArrayLiteral("type.ankama.com/iet"))
        || payload.contains(QByteArrayLiteral("type.ankama.com/ies"))) {
        return PacketKind::MapGatherIeuBundleServer;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/isp"))) {
        return PacketKind::IspSync;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/itv"))) {
        return PacketKind::ItvInteraction;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/kj"))) {
        return PacketKind::KjCompression;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/jmw"))) {
        return PacketKind::JmwMonsterCmd;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/jrt"))) {
        return PacketKind::CommandData;
    }
    if (payload.contains(QByteArrayLiteral("type.ankama.com/jrr"))) {
        return PacketKind::JrrCommandResponse;
    }
    return PacketKind::DataGeneric;
}

PacketKind classifyPacketKind(const QByteArray& payload)
{
    if (payload.isEmpty()) {
        return PacketKind::Unknown;
    }

    QStringList urls;
    mergeAnkamaTypeUrlStrings(payload, &urls);
    if (ankamaUrlSuffixInList(urls, QLatin1String("/jnr"))
        && ankamaUrlSuffixInList(urls, QLatin1String("/isp"))) {
        return PacketKind::MapHopJnrIspClient;
    }
    const PacketKind fromUrls = kindFromUrlListPriority(urls);
    if (fromUrls != PacketKind::Unknown) {
        return fromUrls;
    }

    // IRI en borde de mapa: a veces la URL va en UTF-16 LE o fragmentada sin match UTF-8 contiguo.
    if (utf16LeContainsLatin1(payload, QLatin1String("type.ankama.com/iri"))
        || utf16LeContainsLatin1(payload, QLatin1String("ankama.com/iri"))) {
        return PacketKind::IriMovement;
    }
    if (payload.contains(QByteArrayLiteral("ankama.com/iri"))) {
        return PacketKind::IriMovement;
    }

    const PacketKind raw = classifyPacketKindByRawMarkers(payload);
    if (raw != PacketKind::DataGeneric) {
        return raw;
    }
    return PacketKind::DataGeneric;
}

QString packetKindDisplayString(PacketKind k)
{
    switch (k) {
    case PacketKind::IriMovement:
        return QStringLiteral("IRI (MOVIMIENTO)");
    case PacketKind::IrlList:
        return QStringLiteral("IRL (LISTA)");
    case PacketKind::IsoResources:
        return QStringLiteral("ISO (RECURSOS)");
    case PacketKind::MapGatherIerSnapshotServer:
        return QStringLiteral("RECO · IER SNAPSHOT");
    case PacketKind::MapGatherIevTapClient:
        return QStringLiteral("RECO · IEV TOQUE");
    case PacketKind::MapGatherIeuBundleServer:
        return QStringLiteral("RECO · IEU/IET/IES");
    case PacketKind::IrxMonsters:
        return QStringLiteral("IRX (MONSTRUOS)");
    case PacketKind::IslEntities:
        return QStringLiteral("ISL (ENTIDADES)");
    case PacketKind::IeeHarvest:
        return QStringLiteral("IEE (RECOLECCIÓN)");
    case PacketKind::IdrItemReceived:
        return QStringLiteral("IDR (ITEM RECIBIDO)");
    case PacketKind::IdyItemDisplayed:
        return QStringLiteral("IDY (ITEM DESPLEGADO)");
    case PacketKind::IdwItemVanished:
        return QStringLiteral("IDW (ITEM DESAPARECE)");
    case PacketKind::IsuClientSync:
        return QStringLiteral("ISU (SYNC CLIENTE)");
    case PacketKind::IrkSyncResponse:
        return QStringLiteral("IRK (SYNC RESPUESTA)");
    case PacketKind::KjCompression:
        return QStringLiteral("KJ (COMPRESIÓN?)");
    case PacketKind::JmwMonsterCmd:
        return QStringLiteral("JMW (COMANDO MONSTRUOS)");
    case PacketKind::CommandData:
        return QStringLiteral("JRT (COMANDO)");
    case PacketKind::JrrCommandResponse:
        return QStringLiteral("JRR (RESPUESTA COMANDO)");
    case PacketKind::IspSync:
        return QStringLiteral("ISP (SINCRONIZACIÓN?)");
    case PacketKind::ItvInteraction:
        return QStringLiteral("ITV (INFO TRANSFER)");
    case PacketKind::IsaPingClient:
        return QStringLiteral("ISA (SESION/MAPA)");
    case PacketKind::ItrMapTransitClient:
        return QStringLiteral("ITR (TRAMO MAPA · C→S)");
    case PacketKind::IshMapTinyServer:
        return QStringLiteral("ISH (TRAMO MAPA · S→C)");
    case PacketKind::ItoMapTransitClient:
        return QStringLiteral("ITO (TRAMO MAPA · C→S)");
    case PacketKind::MapHydrateTripleServer:
        return QStringLiteral("MAPA · HIDRATA (IUE/IUC/KNW)");
    case PacketKind::MapHopJnrIspClient:
        return QStringLiteral("PASO MAPA (JNR+ISP)");
    case PacketKind::ItxMapHeavyServer:
        return QStringLiteral("ITX (MAPA · CARGA)");
    case PacketKind::KtaKeyedServer:
        return QStringLiteral("KTA (MAPA · CLAVE)");
    case PacketKind::JsaPulseClient:
        return QStringLiteral("JSA (PULSO · C→S)");
    case PacketKind::JsbPulseServer:
        return QStringLiteral("JSB (PULSO · S→C)");
    case PacketKind::DataGeneric:
        return QStringLiteral("DATOS");
    default:
        return QStringLiteral("OTRO");
    }
}

PacketKind packetKindFromDisplayLabel(const QString& label)
{
    const QString t = label.trimmed();
    static const QVector<QPair<QString, PacketKind>> map = {
        {QStringLiteral("IRI (MOVIMIENTO)"), PacketKind::IriMovement},
        {QStringLiteral("IRL (LISTA)"), PacketKind::IrlList},
        {QStringLiteral("ISO (RECURSOS)"), PacketKind::IsoResources},
        {QStringLiteral("RECO · IER SNAPSHOT"), PacketKind::MapGatherIerSnapshotServer},
        {QStringLiteral("RECO · IEV TOQUE"), PacketKind::MapGatherIevTapClient},
        {QStringLiteral("RECO · IEU/IET/IES"), PacketKind::MapGatherIeuBundleServer},
        {QStringLiteral("IRX (MONSTRUOS)"), PacketKind::IrxMonsters},
        {QStringLiteral("ISL (ENTIDADES)"), PacketKind::IslEntities},
        {QStringLiteral("ISL (LISTA)"), PacketKind::IslEntities},
        {QStringLiteral("IEE (RECOLECCIÓN)"), PacketKind::IeeHarvest},
        {QStringLiteral("IEE (RECOLECTAR)"), PacketKind::IeeHarvest},
        {QStringLiteral("IDR (ITEM RECIBIDO)"), PacketKind::IdrItemReceived},
        {QStringLiteral("IDY (ITEM DESPLEGADO)"), PacketKind::IdyItemDisplayed},
        {QStringLiteral("IDW (ITEM DESAPARECE)"), PacketKind::IdwItemVanished},
        {QStringLiteral("ISU (SYNC CLIENTE)"), PacketKind::IsuClientSync},
        {QStringLiteral("IRK (SYNC RESPUESTA)"), PacketKind::IrkSyncResponse},
        {QStringLiteral("KJ (COMPRESIÓN?)"), PacketKind::KjCompression},
        {QStringLiteral("JMW (COMANDO MONSTRUOS)"), PacketKind::JmwMonsterCmd},
        {QStringLiteral("JRT (COMANDO)"), PacketKind::CommandData},
        {QStringLiteral("COMANDO / jrt"), PacketKind::CommandData},
        {QStringLiteral("JRR (RESPUESTA COMANDO)"), PacketKind::JrrCommandResponse},
        {QStringLiteral("ISP (SINCRONIZACIÓN?)"), PacketKind::IspSync},
        {QStringLiteral("ITV (INFO TRANSFER)"), PacketKind::ItvInteraction},
        {QStringLiteral("ITV (INTERACCIÓN?)"), PacketKind::ItvInteraction},
        {QStringLiteral("PASO MAPA (JNR+ISP)"), PacketKind::MapHopJnrIspClient},
        {QStringLiteral("ISA (SESION/MAPA)"), PacketKind::IsaPingClient},
        {QStringLiteral("ITR (TRAMO MAPA · C→S)"), PacketKind::ItrMapTransitClient},
        {QStringLiteral("ISH (TRAMO MAPA · S→C)"), PacketKind::IshMapTinyServer},
        {QStringLiteral("ITO (TRAMO MAPA · C→S)"), PacketKind::ItoMapTransitClient},
        {QStringLiteral("MAPA · HIDRATA (IUE/IUC/KNW)"), PacketKind::MapHydrateTripleServer},
        {QStringLiteral("ITX (MAPA · CARGA)"), PacketKind::ItxMapHeavyServer},
        {QStringLiteral("KTA (MAPA · CLAVE)"), PacketKind::KtaKeyedServer},
        {QStringLiteral("JSA (PULSO · C→S)"), PacketKind::JsaPulseClient},
        {QStringLiteral("JSB (PULSO · S→C)"), PacketKind::JsbPulseServer},
        {QStringLiteral("DATOS"), PacketKind::DataGeneric},
        {QStringLiteral("OTRO"), PacketKind::Unknown},
    };
    for (const auto& p : map) {
        if (t.compare(p.first, Qt::CaseInsensitive) == 0) {
            return p.second;
        }
    }
    return PacketKind::Unknown;
}

QStringList standardPacketKindLabels()
{
    QStringList out;
    out.reserve(48);
    const QList<PacketKind> kinds = {
        PacketKind::IriMovement,
        PacketKind::MapHopJnrIspClient,
        PacketKind::IeeHarvest,
        PacketKind::IsoResources,
        PacketKind::MapGatherIerSnapshotServer,
        PacketKind::MapGatherIevTapClient,
        PacketKind::MapGatherIeuBundleServer,
        PacketKind::IrxMonsters,
        PacketKind::IrlList,
        PacketKind::IdrItemReceived,
        PacketKind::IdyItemDisplayed,
        PacketKind::IdwItemVanished,
        PacketKind::IslEntities,
        PacketKind::IsuClientSync,
        PacketKind::IrkSyncResponse,
        PacketKind::IsaPingClient,
        PacketKind::ItrMapTransitClient,
        PacketKind::IshMapTinyServer,
        PacketKind::ItoMapTransitClient,
        PacketKind::MapHydrateTripleServer,
        PacketKind::ItxMapHeavyServer,
        PacketKind::KtaKeyedServer,
        PacketKind::JsaPulseClient,
        PacketKind::JsbPulseServer,
        PacketKind::KjCompression,
        PacketKind::JmwMonsterCmd,
        PacketKind::CommandData,
        PacketKind::JrrCommandResponse,
        PacketKind::IspSync,
        PacketKind::ItvInteraction,
        PacketKind::DataGeneric,
        PacketKind::Unknown,
    };
    for (PacketKind k : kinds) {
        out.push_back(packetKindDisplayString(k));
    }
    return out;
}

QVector<IdRangeRule> defaultBuiltinIdRules()
{
    QVector<IdRangeRule> rules;
    auto add = [&rules](quint64 lo, quint64 hi, const QString& name) {
        rules.push_back(IdRangeRule{lo, hi, name, QStringLiteral("recurso")});
    };
    add(513600, 513699, QStringLiteral("Trigo"));
    add(513800, 513899, QStringLiteral("Ortiga"));
    add(514000, 514099, QStringLiteral("Castaño"));
    add(514200, 514699, QStringLiteral("Fresno"));
    return rules;
}

QVector<IdRangeRule> parseIdAliasRulesText(const QString& text)
{
    QVector<IdRangeRule> out;
    static const QRegularExpression re(QStringLiteral(
        R"(^\s*(#|$))"));
    static const QRegularExpression ruleRe(QStringLiteral(
        R"(^\s*(\d+)\s*-\s*(\d+)\s*:\s*([^:#]+?)(?:\s*:\s*(\w+))?\s*$)"));

    const QStringList lines = text.split(QLatin1Char('\n'));
    for (QString line : lines) {
        if (ruleRe.match(line).hasMatch() == false && re.match(line).hasMatch()) {
            continue;
        }
        const auto m = ruleRe.match(line);
        if (!m.hasMatch()) {
            continue;
        }
        const quint64 lo = m.captured(1).toULongLong();
        const quint64 hi = m.captured(2).toULongLong();
        if (hi < lo) {
            continue;
        }
        IdRangeRule r;
        r.lo = lo;
        r.hi = hi;
        r.label = m.captured(3).trimmed();
        QString cat = m.captured(4).trimmed().toLower();
        if (cat == QStringLiteral("monstruo") || cat == QStringLiteral("monster")) {
            r.category = QStringLiteral("monstruo");
        } else if (cat == QStringLiteral("objeto") || cat == QStringLiteral("item")) {
            r.category = QStringLiteral("objeto");
        } else if (cat == QStringLiteral("recurso") || cat.isEmpty()) {
            r.category = QStringLiteral("recurso");
        } else {
            r.category = cat;
        }
        out.push_back(r);
    }
    return out;
}

QString resolveIdWithRules(quint64 id, const QVector<IdRangeRule>& rules, QString* categoryOut)
{
    if (categoryOut != nullptr) {
        categoryOut->clear();
    }
    for (const IdRangeRule& rule : rules) {
        if (id >= rule.lo && id <= rule.hi) {
            if (categoryOut != nullptr) {
                *categoryOut = rule.category.isEmpty() ? QStringLiteral("recurso") : rule.category;
            }
            return rule.label;
        }
    }
    return {};
}

QString resourceDisplayNameForId(quint64 id)
{
    const QVector<IdRangeRule> builtins = defaultBuiltinIdRules();
    return resolveIdWithRules(id, builtins, nullptr);
}

void extractAnkamaTypeUrls(const QByteArray& payload, QStringList* outUrls)
{
    if (outUrls == nullptr) {
        return;
    }
    const QString p = QString::fromUtf8(payload);
    static const QRegularExpression re(QStringLiteral(R"(type\.ankama\.com/[a-z]+)"));
    for (auto it = re.globalMatch(p); it.hasNext();) {
        const QString cap = it.next().captured(0);
        if (!outUrls->contains(cap)) {
            outUrls->append(cap);
        }
    }
}

void extractProtobufStyleVarints(const QByteArray& payload, QList<quint64>* outValues)
{
    if (outValues == nullptr) {
        return;
    }
    scanAllVarints(payload, outValues);
}

static void collectWireNumsRec(const QList<ProtoField>& fields, QList<quint64>* out, int depth)
{
    if (out == nullptr) return;
    if (depth > 12) return;
    for (const ProtoField& f : fields) {
        if (f.wireType == 0 || f.wireType == 1 || f.wireType == 5) {
            const quint64 v = static_cast<quint64>(f.value.toULongLong());
            out->push_back(v);
        }
        if (f.isNested && !f.nested.isEmpty()) {
            collectWireNumsRec(f.nested, out, depth + 1);
        }
    }
}

void extractProtobufWireNumericScalars(const QByteArray& payload, QList<quint64>* outValues)
{
    if (outValues == nullptr) {
        return;
    }
    ProtobufParser parser;
    const QList<ProtoField> fields = parser.parse(payload);
    if (fields.isEmpty()) {
        return;
    }
    collectWireNumsRec(fields, outValues, 0);
}

QList<quint64> filterResourceCandidateIds(const QList<quint64>& varints, const QVector<IdRangeRule>& extraRules)
{
    QVector<IdRangeRule> merged = extraRules + defaultBuiltinIdRules();
    QList<quint64> r;
    for (quint64 v : varints) {
        QString cat;
        if (!resolveIdWithRules(v, merged, &cat).isEmpty()
            && (cat == QStringLiteral("recurso") || cat.isEmpty())) {
            r.push_back(v);
        }
    }
    return r;
}

quint64 guessMapIdHeuristic(const QByteArray& payload)
{
    QList<quint64> all;
    scanAllVarints(payload, &all);
    for (quint64 v : all) {
        // No tomar IDs de recurso conocidos (~513xxx) como mapa — si no, cada RECO cambia «mapa» y la UI
        // nunca limpia candidatos al zarpar de verdad (parece histórico acumulado).
        if (v >= 512000ULL && v <= 519999ULL) {
            continue;
        }
        if (v >= 100000ULL && v <= 2000000000ULL) {
            return v;
        }
    }
    return 0;
}

void guessCharacterFromServerPayload(const QByteArray& payload, int packetIndex, CharacterSnapshot* inOut)
{
    if (inOut == nullptr || payload.size() < 8) {
        return;
    }
    const QString u = QString::fromUtf8(payload);
    if (u.contains(QStringLiteral("type.ankama.com"))) {
        return;
    }

    static const QRegularExpression reClass(QStringLiteral(
        R"(([A-Za-zÀ-ÿ]+(?:\s*[-–]\s*[A-Za-zÀ-ÿ]+)+))"));
    {
        auto m = reClass.match(u);
        if (m.hasMatch() && m.captured(1).size() >= 4 && m.captured(1).size() <= 32) {
            if (inOut->classLine.isEmpty()) {
                inOut->classLine = m.captured(1).trimmed();
                inOut->sourcePacketIndex = packetIndex;
            }
        }
    }

    static const QRegularExpression reName(QStringLiteral(R"(([A-Za-z][A-Za-z0-9_-]{3,22}))"));
    QString bestName;
    for (auto it = reName.globalMatch(u); it.hasNext();) {
        const QString w = it.next().captured(1);
        if (w.size() < 4) {
            continue;
        }
        if (w.compare(QStringLiteral("true"), Qt::CaseInsensitive) == 0
            || w.compare(QStringLiteral("false"), Qt::CaseInsensitive) == 0) {
            continue;
        }
        if (w.size() > bestName.size()) {
            bestName = w;
        }
    }
    if (!bestName.isEmpty() && inOut->name.isEmpty()) {
        inOut->name = bestName;
        inOut->sourcePacketIndex = packetIndex;
    }

    QList<quint64> nums;
    scanAllVarints(payload, &nums);
    for (quint64 v : nums) {
        if (v >= 1 && v <= 99999999ULL && static_cast<int>(v) > inOut->level) {
            inOut->level = static_cast<int>(v);
            inOut->sourcePacketIndex = packetIndex;
        }
    }
}

QString formatVarintsPreview(const QList<quint64>& v, int maxCount)
{
    QString s;
    for (int i = 0; i < qMin(maxCount, v.size()); ++i) {
        if (i > 0) {
            s += QStringLiteral(", ");
        }
        s += QString::number(v.at(i));
    }
    if (v.size() > maxCount) {
        s += QStringLiteral("…");
    }
    return s;
}

QString formatHexDumpWireshark(const QByteArray& data, int maxBytes)
{
    const int n = qMin(data.size(), maxBytes);
    QString out;
    for (int off = 0; off < n; off += 16) {
        out += QStringLiteral("%1  ")
                   .arg(off, 4, 16, QLatin1Char('0'))
                   .toUpper();
        QString asc;
        for (int i = 0; i < 16; ++i) {
            const int p = off + i;
            if (p < n) {
                const unsigned char c = static_cast<unsigned char>(data.at(p));
                out += QStringLiteral("%1 ").arg(quint32(c), 2, 16, QLatin1Char('0')).toUpper();
                asc += QLatin1Char((c >= 32 && c < 127) ? static_cast<char>(c) : '.');
            } else {
                out += QLatin1String("   ");
                asc += QLatin1Char(' ');
            }
            if (i == 7) {
                out += QLatin1Char(' ');
            }
        }
        out += QLatin1String(" │ ") + asc + QLatin1Char('\n');
    }
    if (data.size() > maxBytes) {
        out += QStringLiteral("… (%1 bytes totales)\n").arg(data.size());
    }
    return out;
}

IrxVarintBuckets classifyIrxStyleVarints(const QList<quint64>& rawIds)
{
    QList<quint64> uniq = rawIds;
    std::sort(uniq.begin(), uniq.end());
    uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());

    IrxVarintBuckets b;
    for (quint64 id : uniq) {
        if (id >= 1000000ULL) {
            b.monsters.append(id);
        } else if (id >= 1000ULL && id <= 9999ULL) {
            b.players.append(id);
        } else if (id > 0 && id < 1000ULL) {
            b.structure.append(id);
        } else {
            b.other.append(id);
        }
    }
    return b;
}

QString analyzeIrxStyleVarintBuckets(const QList<quint64>& rawIds)
{
    const IrxVarintBuckets buck = classifyIrxStyleVarints(rawIds);
    QString result;
    auto appendBlock = [&](const QString& title, const QList<quint64>& lst) {
        if (lst.isEmpty()) {
            return;
        }
        result += title;
        for (quint64 id : lst) {
            result += QStringLiteral("   • %1\n").arg(id);
        }
        result += QLatin1Char('\n');
    };

    appendBlock(QStringLiteral("MONSTRUOS / criaturas (IDs ≥ 1.000.000):\n"), buck.monsters);
    appendBlock(QStringLiteral("PERSONAJES / jugadores típicos (IDs 1.000–9.999):\n"), buck.players);
    if (!buck.players.isEmpty()) {
        result += QStringLiteral(
            "   (No son monstruos del mapa; suelen ser IDs de jugador u otras entidades.)\n\n");
    }
    appendBlock(QStringLiteral("IDs pequeños — posible estructura interna (< 1.000):\n"), buck.structure);
    if (!buck.other.isEmpty()) {
        result += QStringLiteral("Otros IDs:\n");
        for (quint64 id : buck.other) {
            result += QStringLiteral("   • %1\n").arg(id);
        }
        result += QLatin1Char('\n');
    }
    return result;
}

QString buildPacketAnalysisText(const ProtocolPacketRecord& rec, const QVector<IdRangeRule>& rulesChain,
                                int hexMaxBytes, const QHash<quint64, QString>* exactIdNotes)
{
    const QString dirStr = rec.fromClient ? QStringLiteral("→") : QStringLiteral("←");
    QString t;
    t += QStringLiteral("PAQUETE #%1 | %2 | %3 | %4 B | %5\n")
             .arg(rec.index)
             .arg(rec.received.toString(QStringLiteral("HH:mm:ss.zzz")))
             .arg(dirStr)
             .arg(rec.byteSize)
             .arg(rec.kindLabel);
    t += QLatin1String("────────────────────────────────────────\n");

    QStringList recursoLines;
    QStringList monstroLines;
    QStringList personajeLines;
    QStringList objetoLines;
    QStringList otrosLines;

    const QVector<IdRangeRule>& merged = rulesChain;

    QList<quint64> uniq = rec.numericIds;
    std::sort(uniq.begin(), uniq.end());
    uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());

    for (quint64 id : uniq) {
        QString cat;
        const QString label = resolveIdWithRules(id, merged, &cat);
        const QString line = QStringLiteral("   • %1 (ID: %2)").arg(label).arg(id);
        if (label.isEmpty()) {
            otrosLines << QStringLiteral("   • ID %1 (sin alias)").arg(id);
        } else if (cat == QStringLiteral("monstruo")) {
            monstroLines << line;
        } else if (cat == QStringLiteral("personaje")) {
            personajeLines << line;
        } else if (cat == QStringLiteral("objeto")) {
            objetoLines << line;
        } else {
            recursoLines << line;
        }
    }

    if (rec.kind == PacketKind::IrxMonsters || rec.kind == PacketKind::IslEntities) {
        t += QStringLiteral("⚠ Tipo IRX / ISL — revisar IDs sin alias como posibles criaturas u objetos de lista.\n\n");
        const QString buckets = analyzeIrxStyleVarintBuckets(rec.numericIds);
        if (!buckets.isEmpty()) {
            t += QStringLiteral("Clasificación heurística de varints (mapa vs jugador vs otros):\n");
            t += buckets;
            t += QLatin1String("────────────────────────────────────────\n");
        }
    }

    if (!recursoLines.isEmpty()) {
        t += QStringLiteral("RECURSOS / alias tipo recurso (%1):\n").arg(recursoLines.size());
        for (const QString& l : recursoLines) {
            t += l + QLatin1Char('\n');
        }
        t += QLatin1Char('\n');
    }
    if (!monstroLines.isEmpty()) {
        t += QStringLiteral("MONSTRUOS (aliases, %1):\n").arg(monstroLines.size());
        for (const QString& l : monstroLines) {
            t += l + QLatin1Char('\n');
        }
        t += QLatin1Char('\n');
    }
    if (!personajeLines.isEmpty()) {
        t += QStringLiteral("PERSONAJES / jugadores (aliases, %1):\n").arg(personajeLines.size());
        for (const QString& l : personajeLines) {
            t += l + QLatin1Char('\n');
        }
        t += QLatin1Char('\n');
    }
    if (!objetoLines.isEmpty()) {
        t += QStringLiteral("OBJETOS (aliases, %1):\n").arg(objetoLines.size());
        for (const QString& l : objetoLines) {
            t += l + QLatin1Char('\n');
        }
        t += QLatin1Char('\n');
    }
    if (!otrosLines.isEmpty()) {
        const int cap = 50;
        t += QStringLiteral("IDS SIN ALIAS (máx. %1 de %2 únicos; varints totales en scan: %3):\n")
                 .arg(qMin(cap, otrosLines.size()))
                 .arg(otrosLines.size())
                 .arg(rec.numericIds.size());
        for (int i = 0; i < qMin(cap, otrosLines.size()); ++i) {
            t += otrosLines.at(i) + QLatin1Char('\n');
        }
        if (otrosLines.size() > cap) {
            t += QStringLiteral("   …\n");
        }
        t += QLatin1Char('\n');
    }

    if (!rec.stringsFound.isEmpty()) {
        t += QStringLiteral("STRINGS (%1):\n").arg(rec.stringsFound.size());
        for (const QString& s : rec.stringsFound) {
            t += QLatin1String("   «") + s + QLatin1String("»\n");
        }
        t += QLatin1Char('\n');
    }

    t += QStringLiteral("VARINTS / IDs (%1):\n").arg(rec.numericIds.size());
    int lim = qMin(rec.numericIds.size(), 96);
    for (int i = 0; i < lim; ++i) {
        const quint64 vid = rec.numericIds.at(i);
        t += QStringLiteral("   [%1] %2").arg(i).arg(vid);
        if (exactIdNotes != nullptr) {
            const auto nit = exactIdNotes->constFind(vid);
            if (nit != exactIdNotes->constEnd()) {
                t += QStringLiteral(" — nota: «%1»").arg(nit.value());
            }
        }
        t += QLatin1Char('\n');
    }
    if (rec.numericIds.size() > lim) {
        t += QStringLiteral("   …\n");
    }
    t += QLatin1Char('\n');

    t += QStringLiteral("HEX (primeros %1 bytes):\n").arg(hexMaxBytes);
    t += formatHexDumpWireshark(rec.rawPayload, hexMaxBytes);
    return t;
}

ProtocolPacketRecord buildRecordFromPayload(int packetIndex, bool fromClient, const QByteArray& payload,
                                            const PacketTypeOverrides* overrides)
{
    ProtocolPacketRecord r;
    r.index = packetIndex;
    r.received = QDateTime::currentDateTime();
    r.fromClient = fromClient;
    r.byteSize = payload.size();
    r.rawPayload = payload;

    QString ovLabel;
    if (overrides != nullptr) {
        ovLabel = overrides->labelForPayload(payload);
    }
    if (!ovLabel.isEmpty()) {
        const PacketKind mapped = packetKindFromDisplayLabel(ovLabel);
        r.kind = (mapped != PacketKind::Unknown) ? mapped : PacketKind::DataGeneric;
        r.kindLabel = ovLabel;
    } else {
        r.kind = classifyPacketKind(payload);
        r.kindLabel = packetKindDisplayString(r.kind);
    }
    extractAnkamaTypeUrls(payload, &r.stringsFound);
    if (!r.stringsFound.isEmpty()) {
        r.primaryUrl = r.stringsFound.first();
    }
    // Mejor que scanAllVarints: incluye fixed32/fixed64 y anidados (para RECO IEU/IER/ITV etc.).
    extractProtobufWireNumericScalars(payload, &r.numericIds);
    if (r.numericIds.isEmpty()) {
        extractProtobufStyleVarints(payload, &r.numericIds);
    }
    return r;
}

bool parseExportedProxyLogText(const QString& text, QVector<QPair<bool, QByteArray>>* outChunks, QString* errorOut)
{
    if (outChunks == nullptr) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral("Salida nula.");
        }
        return false;
    }
    outChunks->clear();

    bool pendingDirIsClient = true;
    bool haveDir = false;
    QStringList hexLines;

    const QStringList lines = text.split(QLatin1Char('\n'));
    auto flushHex = [&]() {
        if (hexLines.isEmpty()) {
            return;
        }
        QString concat = hexLines.join(QString());
        const QRegularExpression reNonHex(QStringLiteral("[^0-9A-Fa-f]"));
        concat.remove(reNonHex);
        if (concat.size() % 2 != 0) {
            concat.chop(1);
        }
        if (concat.size() < 4) {
            hexLines.clear();
            return;
        }
        const QByteArray raw = QByteArray::fromHex(concat.toLatin1());
        if (!raw.isEmpty()) {
            outChunks->push_back(qMakePair(pendingDirIsClient, raw));
        }
        hexLines.clear();
    };

    for (QString line : lines) {
        line = line.trimmed();
        if (line.contains(QStringLiteral("[CLIENTE → PROXY]"))
            || line.contains(QStringLiteral("[CLIENTE->PROXY]"))) {
            flushHex();
            pendingDirIsClient = true;
            haveDir = true;
            continue;
        }
        if (line.contains(QStringLiteral("[PROXY → SERVIDOR]")) || line.contains(QStringLiteral("[PROXY->SERVIDOR]"))) {
            flushHex();
            pendingDirIsClient = true;
            haveDir = true;
            continue;
        }
        if (line.contains(QStringLiteral("[SERVIDOR → PROXY]")) || line.contains(QStringLiteral("[SERVIDOR->PROXY]"))
            || line.contains(QStringLiteral("[PROXY → CLIENTE]"))) {
            flushHex();
            pendingDirIsClient = false;
            haveDir = true;
            continue;
        }
        if (line.startsWith(QStringLiteral("HEX:"), Qt::CaseInsensitive)) {
            hexLines.append(line.mid(4).trimmed());
            continue;
        }
        if (haveDir && looksLikeHexContinuationLine(line)) {
            hexLines.append(line);
        }
    }
    flushHex();

    if (outChunks->isEmpty()) {
        if (errorOut != nullptr) {
            *errorOut = QStringLiteral(
                "No se encontraron bloques HEX reconocibles (usa export del registro con «Log detallado»).");
        }
        return false;
    }
    return true;
}
