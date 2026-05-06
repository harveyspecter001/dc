#include "ProtocolLogAnalyzer.h"
#include "PacketTypeOverrides.h"
#include "ProtobufParser.h"

#include <QHash>
#include <QStringList>
#include <QRegularExpression>
#include <QPoint>
#include <QSet>
#include <QStringList>
#include <QtGlobal>

#include <algorithm>
#include <queue>

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

bool looksLikeWiresharkHexLine(const QString& line)
{
    // Formato típico exportado: "0000  DE AD BE EF ...  │ ascii..."
    // Aceptamos si empieza con 4 hex (offset) y contiene al menos un byte hex de 2 dígitos.
    if (line.size() < 6) {
        return false;
    }
    static const QRegularExpression reOffset(QStringLiteral(R"(^[0-9A-Fa-f]{4}\s)"));
    if (!reOffset.match(line).hasMatch()) {
        return false;
    }
    static const QRegularExpression reByte(QStringLiteral(R"(\b[0-9A-Fa-f]{2}\b)"));
    return reByte.match(line).hasMatch();
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

static const ProtoField* findFirstField(const QList<ProtoField>& fields, int fieldNumber)
{
    for (const ProtoField& f : fields) {
        if (f.fieldNumber == fieldNumber) {
            return &f;
        }
    }
    return nullptr;
}

static void collectVarintsRec(const QList<ProtoField>& fields, QList<quint64>* out, int depth)
{
    if (out == nullptr) return;
    if (depth > 12) return;
    for (const ProtoField& f : fields) {
        if (f.wireType == 0) {
            out->push_back(static_cast<quint64>(f.value.toULongLong()));
        }
        if (f.isNested && !f.nested.isEmpty()) {
            collectVarintsRec(f.nested, out, depth + 1);
        }
    }
}

bool tryGetIriMapId(const QByteArray& payload, quint64& mapIdOut)
{
    mapIdOut = 0;
    ProtobufParser parser;
    const QList<ProtoField> fields = parser.parse(payload);
    const ProtoField* f2 = findFirstField(fields, 2);
    if (f2 == nullptr) {
        return false;
    }
    if (f2->wireType != 0 && f2->wireType != 1 && f2->wireType != 5) {
        return false;
    }
    const quint64 v = static_cast<quint64>(f2->value.toULongLong());
    if (v == 0) {
        return false;
    }
    mapIdOut = v;
    return true;
}

bool tryGetIriPathVarints(const QByteArray& payload, QList<quint64>& pathOut)
{
    pathOut.clear();
    ProtobufParser parser;
    const QList<ProtoField> fields = parser.parse(payload);
    const ProtoField* f3 = findFirstField(fields, 3);
    if (f3 == nullptr) {
        return false;
    }

    // Field 3 en `iri.cs` es `ket` (mensaje). No sabemos aún el layout exacto del “path”.
    // Best-effort: recolectar varints dentro del submensaje.
    QList<quint64> v;
    if (f3->isNested && !f3->nested.isEmpty()) {
        collectVarintsRec(f3->nested, &v, 0);
    }
    if (v.isEmpty()) {
        return false;
    }
    pathOut = v;
    return true;
}

bool tryGetIevTapInfo(const QByteArray& payload, ResourceInfo& out)
{
    out = ResourceInfo{};
    ProtobufParser parser;
    const QList<ProtoField> fields = parser.parse(payload);
    const ProtoField* f1 = findFirstField(fields, 1);
    const ProtoField* f2 = findFirstField(fields, 2);
    if (f1 == nullptr || f2 == nullptr) {
        return false;
    }
    if (f1->wireType != 0 || f2->wireType != 0) {
        return false;
    }
    out.typeId = static_cast<quint64>(f1->value.toULongLong());
    out.instanceId = static_cast<quint64>(f2->value.toULongLong());
    return out.typeId != 0;
}

static void collectNestedMessagesRec(const QList<ProtoField>& fields, QList<QList<ProtoField>>* out, int depth)
{
    if (out == nullptr) return;
    if (depth > 10) return;
    for (const ProtoField& f : fields) {
        if (f.isNested && !f.nested.isEmpty()) {
            out->push_back(f.nested);
            collectNestedMessagesRec(f.nested, out, depth + 1);
        }
    }
}

QList<ResourceInfo> extractIsoResourcesHeuristic(const QByteArray& payload)
{
    QList<ResourceInfo> out;
    ProtobufParser parser;
    const QList<ProtoField> root = parser.parse(payload);
    if (root.isEmpty()) {
        return out;
    }

    QList<QList<ProtoField>> msgs;
    collectNestedMessagesRec(root, &msgs, 0);

    // Dedup por (typeId, instanceId) para evitar múltiples “vistas” del mismo submensaje.
    QSet<quint64> seenKey;

    for (const QList<ProtoField>& m : msgs) {
        QList<quint64> vars;
        collectVarintsRec(m, &vars, 0);
        if (vars.isEmpty()) continue;

        quint64 typeId = 0;
        quint64 instanceId = 0;
        QList<quint64> small;
        small.reserve(vars.size());

        for (quint64 v : vars) {
            if (v >= 512000ULL && v <= 519999ULL && typeId == 0) {
                typeId = v;
                continue;
            }
            if (v > 0 && v <= 10000ULL) {
                small.push_back(v);
            }
        }
        if (typeId == 0) {
            continue;
        }

        // instance_id: suele ser varint “mediano” que no es recurso; preferimos > 1000.
        for (quint64 v : vars) {
            if (v == typeId) continue;
            if (v > 1000ULL && v < 100000000ULL) {
                instanceId = v;
                break;
            }
        }

        ResourceInfo ri;
        ri.typeId = typeId;
        ri.instanceId = instanceId;

        // cell: típico < 560
        for (quint64 v : small) {
            if (v < 560ULL) {
                ri.cell = static_cast<int>(v);
                ri.hasCell = true;
                break;
            }
        }

        // x,y: heurística con dos valores pequeños (<=200) que no sean cell.
        QList<int> xy;
        for (quint64 v : small) {
            if (v <= 200ULL) {
                const int iv = static_cast<int>(v);
                if (ri.hasCell && iv == ri.cell) {
                    continue;
                }
                xy.push_back(iv);
                if (xy.size() >= 2) break;
            }
        }
        if (xy.size() >= 2) {
            ri.x = xy.at(0);
            ri.y = xy.at(1);
            ri.hasXy = true;
        }

        const quint64 key = (ri.typeId << 32) ^ (ri.instanceId & 0xffffffffULL);
        if (seenKey.contains(key)) {
            continue;
        }
        seenKey.insert(key);
        out.push_back(ri);
    }

    return out;
}

static inline bool looksLikeResourceTypeId(quint64 v)
{
    return v >= 512000ULL && v <= 519999ULL;
}

static void walkItxResourceRec(const QList<ProtoField>& fields, QList<ResourceInfo>* out, int depth)
{
    if (out == nullptr) return;
    if (depth > 12) return;

    // 1) Evaluar el mensaje ACTUAL como posible “entrada de recurso”.
    {
        ResourceInfo ri;
        for (const ProtoField& nf : fields) {
            if (nf.wireType != 0) continue;
            const quint64 v = static_cast<quint64>(nf.value.toULongLong());
            if (looksLikeResourceTypeId(v)) {
                ri.typeId = v;
                break;
            }
        }
        for (const ProtoField& nf : fields) {
            if (!(nf.wireType == 2 && nf.isNested && !nf.nested.isEmpty())) {
                continue;
            }
            int cell = -1;
            quint64 inst = 0;
            for (const ProtoField& nn : nf.nested) {
                if (nn.wireType != 0) continue;
                const quint64 v = static_cast<quint64>(nn.value.toULongLong());
                if (cell == -1 && v > 0 && v < 560ULL) {
                    cell = static_cast<int>(v);
                    continue;
                }
                if (inst == 0 && v > 1000ULL && v < 100000000ULL && !looksLikeResourceTypeId(v)) {
                    inst = v;
                    continue;
                }
            }
            if (cell != -1 && !ri.hasCell) {
                ri.cell = cell;
                ri.hasCell = true;
            }
            if (inst != 0 && ri.instanceId == 0) {
                ri.instanceId = inst;
            }
        }
        if (ri.typeId != 0) {
            out->push_back(ri);
        }
    }

    // 2) Recurse: seguir descendiendo a mensajes anidados.
    for (const ProtoField& f : fields) {
        if (f.isNested && !f.nested.isEmpty()) {
            walkItxResourceRec(f.nested, out, depth + 1);
        }
    }
}

QList<ResourceInfo> extractResourcesFromItx(const QByteArray& payload)
{
    QList<ResourceInfo> out;
    ProtobufParser parser;
    const QList<ProtoField> root = parser.parse(payload);
    if (root.isEmpty()) {
        // Seguimos con fallback abajo (scan raw) antes de rendirnos.
    } else {
        walkItxResourceRec(root, &out, 0);
    }

    // Fallback: si el parser se corta temprano (ITX puede contener tramos no-Protobuf),
    // escanear el raw buscando submensajes tipo field 11 length-delimited (tag 0x5A),
    // que en logs reales contiene entradas con type_id 514xxx.
    if (out.isEmpty()) {
        auto readVarintAt = [](const QByteArray& d, int* offsetInOut, quint64* valueOut) -> bool {
            if (!offsetInOut || !valueOut) return false;
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
                if (shift > 63) return false;
            }
            return false;
        };

        auto extractFromSub = [&](const QByteArray& sub) {
            const QList<ProtoField> fs = parser.parse(sub);
            if (fs.isEmpty()) return;
            // Reusar la lógica existente sobre un contenedor "fake" nested
            walkItxResourceRec(fs, &out, 0);
        };

        const QByteArray& d = payload;
        for (int pos = 0; pos + 2 < d.size(); ++pos) {
            if (static_cast<unsigned char>(d.at(pos)) != 0x5A) {
                continue;
            }
            int off = pos + 1;
            quint64 len = 0;
            if (!readVarintAt(d, &off, &len)) {
                continue;
            }
            if (len == 0 || len > 4096) {
                continue;
            }
            if (off + static_cast<int>(len) > d.size()) {
                continue;
            }
            const QByteArray sub = d.mid(off, static_cast<int>(len));
            extractFromSub(sub);
        }
    }

    // Dedup por (typeId, instanceId, cell) para evitar repeticiones por múltiples rutas de anidamiento.
    QSet<quint64> seen;
    QList<ResourceInfo> uniq;
    uniq.reserve(out.size());
    for (const ResourceInfo& r : out) {
        const quint64 key = (r.typeId << 32)
                            ^ (r.instanceId & 0xffffffffULL)
                            ^ (static_cast<quint64>(r.hasCell ? (r.cell & 0x3ff) : 0) << 10);
        if (seen.contains(key)) continue;
        seen.insert(key);
        uniq.push_back(r);
    }
    return uniq;
}

QList<QString> calculatePath(int x1, int y1, int x2, int y2)
{
    QList<QString> steps;
    int x = x1;
    int y = y1;

    while (y > y2) {
        steps.push_back(QStringLiteral("N"));
        --y;
    }
    while (y < y2) {
        steps.push_back(QStringLiteral("S"));
        ++y;
    }
    while (x < x2) {
        steps.push_back(QStringLiteral("E"));
        ++x;
    }
    while (x > x2) {
        steps.push_back(QStringLiteral("O"));
        --x;
    }
    return steps;
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

namespace {
[[nodiscard]] bool readVarintAt(const QByteArray& b, int off, quint64& out, int* bytesRead)
{
    if (off < 0 || off >= b.size()) {
        return false;
    }
    quint64 v = 0;
    int shift = 0;
    int i = off;
    for (; i < b.size() && shift < 64; ++i) {
        const quint8 by = static_cast<quint8>(b.at(i));
        v |= (quint64(by & 0x7F) << shift);
        if ((by & 0x80) == 0) {
            out = v;
            if (bytesRead != nullptr) {
                *bytesRead = (i - off + 1);
            }
            return true;
        }
        shift += 7;
    }
    return false;
}

[[nodiscard]] bool looksLikeMapIdLong(quint64 v)
{
    return v >= 100000000ULL && v <= 400000000ULL;
}
} // namespace

bool tryExtractMapIdLongFromIsaOrItx(const QByteArray& payload, quint64& mapIdOut)
{
    // ISA: ... "type.ankama.com/isa" ... 0x20 <varint(mapId)>
    {
        const QByteArray u = QByteArrayLiteral("type.ankama.com/isa");
        const int uix = payload.indexOf(u);
        if (uix >= 0) {
            const int searchFrom = uix + u.size();
            const int tagIx = payload.indexOf(char(0x20), searchFrom);
            if (tagIx >= 0 && tagIx + 1 < payload.size()) {
                quint64 v = 0;
                if (readVarintAt(payload, tagIx + 1, v, nullptr) && looksLikeMapIdLong(v)) {
                    mapIdOut = v;
                    return true;
                }
            }
        }
    }

    // ITX: ... "type.ankama.com/itx" ... 0x18 <varint(mapId)> (visto en dumps)
    {
        const QByteArray u = QByteArrayLiteral("type.ankama.com/itx");
        const int uix = payload.indexOf(u);
        if (uix >= 0) {
            const int searchFrom = uix + u.size();
            // en ITX el mensaje es grande; hay muchos 0x18. elegimos el primero que parezca mapId.
            int tagIx = payload.indexOf(char(0x18), searchFrom);
            while (tagIx >= 0 && tagIx + 1 < payload.size()) {
                quint64 v = 0;
                if (readVarintAt(payload, tagIx + 1, v, nullptr) && looksLikeMapIdLong(v)) {
                    mapIdOut = v;
                    return true;
                }
                tagIx = payload.indexOf(char(0x18), tagIx + 1);
            }
        }
    }

    return false;
}

namespace {
constexpr int kDofusMapWidth = 14;
constexpr int kDofusMapHeight = 20;
constexpr int kDofusCellCount = kDofusMapWidth * kDofusMapHeight * 2; // 560

static QVector<QPoint> buildCellPosTable()
{
    // Port directo de MapPoint.as::init()
    QVector<QPoint> pos;
    pos.resize(kDofusCellCount);

    int startX = 0;
    int startY = 0;
    int cell = 0;
    for (int a = 0; a < kDofusMapHeight; ++a) {
        for (int b = 0; b < kDofusMapWidth; ++b) {
            pos[cell++] = QPoint(startX + b, startY + b);
        }
        ++startX;
        for (int b = 0; b < kDofusMapWidth; ++b) {
            pos[cell++] = QPoint(startX + b, startY + b);
        }
        --startY;
    }
    return pos;
}

static const QVector<QPoint>& cellPos()
{
    static const QVector<QPoint> t = buildCellPosTable();
    return t;
}

static inline bool isInMapCoord(int x, int y)
{
    // MapPoint.as::isInMap
    return (x + y) >= 0 && (x - y) >= 0 && (x - y) < (kDofusMapHeight * 2) && (x + y) < (kDofusMapWidth * 2);
}
} // namespace

DofusCellCoord dofusCellToCoord(int cellId)
{
    DofusCellCoord out;
    if (cellId < 0 || cellId >= kDofusCellCount) {
        out.ok = false;
        return out;
    }
    const QPoint p = cellPos().at(cellId);
    out.x = p.x();
    out.y = p.y();
    out.ok = true;
    return out;
}

int dofusCoordToCell(int x, int y)
{
    if (!isInMapCoord(x, y)) {
        return -1;
    }
    // MapPoint.as::setFromCoords:
    // cellId = ((x - y) * MAP_WIDTH + y) + ((x - y) / 2)
    const int d = x - y;
    if ((d & 1) != 0) {
        return -1;
    }
    const int cell = (d * kDofusMapWidth + y) + (d / 2);
    if (cell < 0 || cell >= kDofusCellCount) {
        return -1;
    }
    return cell;
}

QList<int> calculateCellPath(int cellFrom, int cellTo)
{
    const DofusCellCoord a = dofusCellToCoord(cellFrom);
    const DofusCellCoord b = dofusCellToCoord(cellTo);
    if (!a.ok || !b.ok) {
        return {};
    }
    if (cellFrom == cellTo) {
        return {cellFrom};
    }

    // Vecinos 8-dir de MapPoint.getNearestCellInDirection.
    static const int dx[8] = {+1, +1, +1, 0, -1, -1, -1, 0};
    static const int dy[8] = {+1, 0, -1, -1, -1, 0, +1, +1};

    // A* sin obstáculos (coste 1 por paso).
    struct Node {
        int cell;
        int g;
        int f;
    };
    auto h = [&](int c) -> int {
        const DofusCellCoord p = dofusCellToCoord(c);
        return p.ok ? (qAbs(p.x - b.x) + qAbs(p.y - b.y)) : 999999;
    };

    QVector<int> cameFrom(kDofusCellCount, -1);
    QVector<int> gScore(kDofusCellCount, 1 << 30);
    QVector<bool> closed(kDofusCellCount, false);

    auto cmp = [](const Node& n1, const Node& n2) { return n1.f > n2.f; };
    std::priority_queue<Node, std::vector<Node>, decltype(cmp)> open(cmp);

    gScore[cellFrom] = 0;
    open.push(Node{cellFrom, 0, h(cellFrom)});

    while (!open.empty()) {
        const Node cur = open.top();
        open.pop();
        if (cur.cell == cellTo) {
            QList<int> path;
            int c = cellTo;
            while (c != -1) {
                path.prepend(c);
                if (c == cellFrom) break;
                c = cameFrom.at(c);
            }
            if (!path.isEmpty() && path.first() == cellFrom) {
                return path;
            }
            return {};
        }
        if (closed[cur.cell]) continue;
        closed[cur.cell] = true;

        const DofusCellCoord pc = dofusCellToCoord(cur.cell);
        for (int dir = 0; dir < 8; ++dir) {
            const int nx = pc.x + dx[dir];
            const int ny = pc.y + dy[dir];
            const int nbCell = dofusCoordToCell(nx, ny);
            if (nbCell < 0) continue;
            if (closed[nbCell]) continue;

            const int tentative = gScore[cur.cell] + 1;
            if (tentative < gScore[nbCell]) {
                cameFrom[nbCell] = cur.cell;
                gScore[nbCell] = tentative;
                open.push(Node{nbCell, tentative, tentative + h(nbCell)});
            }
        }
    }
    return {};
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

    // Extracciones “estructuradas” (cuando tenemos field numbers confirmados en DiffableCs).
    if (rec.kind == PacketKind::IriMovement) {
        quint64 mapId = 0;
        if (tryGetIriMapId(rec.rawPayload, mapId)) {
            t += QStringLiteral("IRI: map_id (field 2) = %1\n").arg(mapId);
        }
        QList<quint64> path;
        if (tryGetIriPathVarints(rec.rawPayload, path)) {
            t += QStringLiteral("IRI: path varints (desde field 3) = [%1]\n")
                     .arg(formatVarintsPreview(path, 12));
        }
        t += QLatin1Char('\n');
    } else if (rec.kind == PacketKind::MapGatherIevTapClient) {
        ResourceInfo ri;
        if (tryGetIevTapInfo(rec.rawPayload, ri)) {
            t += QStringLiteral("IEV: type_id(field 1)=%1, instance_id(field 2)=%2\n\n")
                     .arg(ri.typeId)
                     .arg(ri.instanceId);
        }
    } else if (rec.kind == PacketKind::IsoResources) {
        const QList<ResourceInfo> lst = extractIsoResourcesHeuristic(rec.rawPayload);
        if (!lst.isEmpty()) {
            t += QStringLiteral("ISO (heurístico): %1 recursos candidatos\n").arg(lst.size());
            const int lim = qMin(8, lst.size());
            for (int i = 0; i < lim; ++i) {
                const ResourceInfo& ri = lst.at(i);
                t += QStringLiteral("  - type_id=%1, instance_id=%2")
                         .arg(ri.typeId)
                         .arg(ri.instanceId);
                if (ri.hasCell) {
                    t += QStringLiteral(", cell=%1").arg(ri.cell);
                }
                if (ri.hasXy) {
                    t += QStringLiteral(", x=%1, y=%2").arg(ri.x).arg(ri.y);
                }
                t += QLatin1Char('\n');
            }
            if (lst.size() > lim) {
                t += QStringLiteral("  …\n");
            }
            t += QLatin1Char('\n');
        }
    }

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
        // Soportamos 2 formatos:
        // - export "Log detallado": líneas HEX continuas
        // - logs tipo ll_p1_to_190: líneas con offset "0000  3b 12 ..." (extraemos tokens de 2 hex)
        QByteArray hexBytes;
        hexBytes.reserve(hexLines.size() * 32);
        static const QRegularExpression reByte(QStringLiteral(R"(\b[0-9A-Fa-f]{2}\b)"));
        static const QRegularExpression reLeadingOffset(QStringLiteral(R"(^[0-9A-Fa-f]{4}\s+)"));
        for (const QString& l : hexLines) {
            // Si viene en formato wireshark "0000  DE AD ... │ ascii", ignorar el offset "0000"
            QString s = l;
            if (reLeadingOffset.match(s).hasMatch()) {
                s = s.mid(4).trimmed();
            }
            // Si hay columna ASCII, descartarla (todo lo que venga después del separador)
            const int bar = s.indexOf(QChar(0x2502)); // │
            if (bar >= 0) {
                s = s.left(bar);
            }
            for (auto it = reByte.globalMatch(s); it.hasNext();) {
                hexBytes.append(it.next().captured(0).toLatin1());
            }
        }
        if (hexBytes.size() < 4) {
            hexLines.clear();
            return;
        }
        const QByteArray raw = QByteArray::fromHex(hexBytes);
        if (!raw.isEmpty()) {
            outChunks->push_back(qMakePair(pendingDirIsClient, raw));
        }
        hexLines.clear();
    };

    for (QString line : lines) {
        line = line.trimmed();
        // Formato exportado del sniffer: "PAQUETE #66 | ... | ← | ..."
        if (line.startsWith(QStringLiteral("PAQUETE #"), Qt::CaseInsensitive)) {
            if (line.contains(QChar(0x2192))) { // →
                pendingDirIsClient = true;
                haveDir = true;
            } else if (line.contains(QChar(0x2190))) { // ←
                pendingDirIsClient = false;
                haveDir = true;
            }
        }
        // Formato ll_p1_to_190: encabezado "#148 ... →/← ..."
        if (line.startsWith(QLatin1Char('#'))) {
            // Si venía un HEX colgando sin marcador explícito de fin, no lo tocamos aquí.
            if (line.contains(QChar(0x2192))) { // →
                pendingDirIsClient = true;
                haveDir = true;
            } else if (line.contains(QChar(0x2190))) { // ←
                pendingDirIsClient = false;
                haveDir = true;
            }
        }
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
        // Nuevo formato export: "HEX (primeros N bytes):"
        if (line.startsWith(QStringLiteral("HEX ("), Qt::CaseInsensitive)) {
            flushHex();
            // el bloque real viene en las siguientes líneas "0000  .."
            continue;
        }
        if ((haveDir || !hexLines.isEmpty())
            && (looksLikeHexContinuationLine(line) || looksLikeWiresharkHexLine(line))) {
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
