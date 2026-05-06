#include "ProtocolLogAnalyzer.h"
#include "PacketTypeOverrides.h"

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

PacketKind classifyPacketKind(const QByteArray& payload)
{
    if (payload.isEmpty()) {
        return PacketKind::Unknown;
    }
    // Orden: rutas type.ankama.com/* (cada token de ruta es distinto: /iri, /irl, /iso, …)
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

QString packetKindDisplayString(PacketKind k)
{
    switch (k) {
    case PacketKind::IriMovement:
        return QStringLiteral("IRI (MOVIMIENTO)");
    case PacketKind::IrlList:
        return QStringLiteral("IRL (LISTA)");
    case PacketKind::IsoResources:
        return QStringLiteral("ISO (RECURSOS)");
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
        return QStringLiteral("ITV (INTERACCIÓN?)");
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
        {QStringLiteral("ITV (INTERACCIÓN?)"), PacketKind::ItvInteraction},
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
    out.reserve(32);
    const QList<PacketKind> kinds = {
        PacketKind::IriMovement,
        PacketKind::IeeHarvest,
        PacketKind::IsoResources,
        PacketKind::IrxMonsters,
        PacketKind::IrlList,
        PacketKind::IdrItemReceived,
        PacketKind::IdyItemDisplayed,
        PacketKind::IdwItemVanished,
        PacketKind::IslEntities,
        PacketKind::IsuClientSync,
        PacketKind::IrkSyncResponse,
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
        if (v >= 100000ULL && v <= 99999999ULL) {
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

QString analyzeIrxStyleVarintBuckets(const QList<quint64>& rawIds)
{
    QList<quint64> uniq = rawIds;
    std::sort(uniq.begin(), uniq.end());
    uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());

    QList<quint64> monsterIds;
    QList<quint64> playerIds;
    QList<quint64> structureIds;
    QList<quint64> otherIds;

    for (quint64 id : uniq) {
        if (id >= 1000000ULL) {
            monsterIds.append(id);
        } else if (id >= 1000ULL && id <= 9999ULL) {
            playerIds.append(id);
        } else if (id > 0 && id < 1000ULL) {
            structureIds.append(id);
        } else {
            otherIds.append(id);
        }
    }

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

    appendBlock(QStringLiteral("MONSTRUOS / criaturas (IDs ≥ 1.000.000):\n"), monsterIds);
    appendBlock(QStringLiteral("PERSONAJES / jugadores típicos (IDs 1.000–9.999):\n"), playerIds);
    if (!playerIds.isEmpty()) {
        result += QStringLiteral(
            "   (No son monstruos del mapa; suelen ser IDs de jugador u otras entidades.)\n\n");
    }
    appendBlock(QStringLiteral("IDs pequeños — posible estructura interna (< 1.000):\n"), structureIds);
    if (!otherIds.isEmpty()) {
        result += QStringLiteral("Otros IDs:\n");
        for (quint64 id : otherIds) {
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
    extractProtobufStyleVarints(payload, &r.numericIds);
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
