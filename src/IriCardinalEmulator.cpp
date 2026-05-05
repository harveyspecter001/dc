#include "IriCardinalEmulator.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QVector>

#include <QtGlobal>

#include <algorithm>

#include <cstring>

namespace {

bool decodeVarintRaw(const QByteArray& buf, int i, quint64* outVal, int* outEndIdx)
{
    quint64 v = 0;
    int shift = 0;
    int pos = i;
    const int lim = buf.size();
    while (pos < lim) {
        const uchar b = static_cast<uchar>(buf.at(pos++));
        v |= quint64(b & 0x7F) << shift;
        if (!(b & 0x80)) {
            if (outVal != nullptr) {
                *outVal = v;
            }
            if (outEndIdx != nullptr) {
                *outEndIdx = pos;
            }
            return true;
        }
        shift += 7;
        if (shift > 63) {
            return false;
        }
    }
    return false;
}

QByteArray encodeUvar(quint64 vv)
{
    QByteArray enc;
    quint64 v = vv;
    while (true) {
        const uchar bt = uchar(v & 0x7F);
        v >>= 7;
        if (v != 0) {
            enc.append(char(bt | uchar(0x80)));
        } else {
            enc.append(char(bt));
            break;
        }
    }
    return enc;
}

QString patchVarintSameLenRawEnum(QByteArray& blob, int off, qint32 newVal)
{
    if (off < 0 || off >= blob.size()) {
        return QStringLiteral("offset fuera del payload");
    }
    quint64 oldU = 0;
    int end = off;
    if (!decodeVarintRaw(blob, off, &oldU, &end)) {
        return QStringLiteral("no se puede leer varint en offset");
    }
    const QByteArray oldEnc = blob.mid(off, end - off);
    const QByteArray newEnc = encodeUvar(static_cast<quint64>(qMax(qint64(0), qint64(newVal))));
    if (newEnc.size() != oldEnc.size()) {
        return QStringLiteral("tam. varint %1→%2 incompatible").arg(oldEnc.size()).arg(newEnc.size());
    }
    std::memcpy(blob.data() + off, newEnc.constData(), static_cast<size_t>(newEnc.size()));
    return {};
}

QString inferCardinalAtModelOffset(const QByteArray& payload, const DirectionMapModel& m)
{
    if (m.offset < 0 || m.offset >= payload.size() || m.mapeo.isEmpty()) {
        return {};
    }
    if (m.tipo == QStringLiteral("byte")) {
        const quint8 b = static_cast<uchar>(payload.at(m.offset));
        for (auto it = m.mapeo.constBegin(); it != m.mapeo.constEnd(); ++it) {
            if (static_cast<quint8>(it.value() & 0xFF) == b) {
                return it.key();
            }
        }
        return {};
    }
    if (m.tipo == QStringLiteral("varint")) {
        quint64 u = 0;
        int end = m.offset;
        if (!decodeVarintRaw(payload, m.offset, &u, &end)) {
            return {};
        }
        for (auto it = m.mapeo.constBegin(); it != m.mapeo.constEnd(); ++it) {
            if (static_cast<quint64>(static_cast<qint32>(it.value())) == u) {
                return it.key();
            }
        }
    }
    return {};
}

} // namespace

QString IriCardinalEmulator::normalizeCardinal(const QString& label)
{
    const QString t = label.trimmed().toLower();
    if (t == QLatin1Char('n')) {
        return QStringLiteral("Norte");
    }
    if (t == QLatin1Char('s')) {
        return QStringLiteral("Sur");
    }
    if (t == QLatin1Char('e')) {
        return QStringLiteral("Este");
    }
    if (t == QLatin1Char('o')) {
        return QStringLiteral("Oeste");
    }
    if (t == QLatin1String("norte")) {
        return QStringLiteral("Norte");
    }
    if (t == QLatin1String("sur")) {
        return QStringLiteral("Sur");
    }
    if (t == QLatin1String("este")) {
        return QStringLiteral("Este");
    }
    if (t == QLatin1String("oeste")) {
        return QStringLiteral("Oeste");
    }
    const QString tl = label.trimmed();
    static const QString kNames[]{QStringLiteral("Norte"), QStringLiteral("Sur"), QStringLiteral("Este"),
                                 QStringLiteral("Oeste")};
    for (const QString& kn : kNames) {
        if (tl == kn) {
            return kn;
        }
    }
    return {};
}

bool payloadHasAnkamaIri(const QByteArray& data)
{
    /// QByteArray.contains con ASCII view
    return data.toLower().contains("type.ankama.com/iri");
}

bool IriCardinalEmulator::loadFromFile(const QString& path, QString* errOut)
{
    modeloCargado_ = false;
    modelo_ = DirectionMapModel();
    loadedPath_.clear();

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        if (errOut != nullptr) {
            *errOut = QStringLiteral("No se abre: %1").arg(path);
        }
        return false;
    }

    QJsonParseError jpe{};
    const QJsonDocument jd = QJsonDocument::fromJson(f.readAll(), &jpe);
    if (jpe.error != QJsonParseError::NoError || !jd.isObject()) {
        if (errOut != nullptr) {
            *errOut = jpe.errorString();
        }
        return false;
    }

    const QJsonObject root = jd.object();

    modelo_.offset = root.value(QStringLiteral("offset")).toInt();
    modelo_.tipo = root.value(QStringLiteral("tipo")).toString();
    if (modelo_.tipo != QStringLiteral("byte") && modelo_.tipo != QStringLiteral("varint")) {
        if (errOut != nullptr) {
            *errOut = QStringLiteral("tipo debe ser byte o varint");
        }
        return false;
    }

    const QJsonObject mpObj = root.value(QStringLiteral("mapeo")).toObject();
    for (auto it = mpObj.begin(); it != mpObj.end(); ++it) {
        const QString nk = normalizeCardinal(it.key());
        if (nk.isEmpty()) {
            continue;
        }
        modelo_.mapeo[nk] = static_cast<qint32>(it.value().toInt());
    }

    if (modelo_.mapeo.isEmpty()) {
        if (errOut != nullptr) {
            *errOut = QStringLiteral("mapeo vacío");
        }
        return false;
    }

    const QJsonObject ej = root.value(QStringLiteral("ejemplos_hex")).toObject();
    for (auto it = ej.begin(); it != ej.end(); ++it) {
        const QString nk = normalizeCardinal(it.key());
        if (nk.isEmpty()) {
            continue;
        }
        QString hx = it.value().toString().remove(QLatin1Char(' '));
        const QByteArray raw = QByteArray::fromHex(hx.toLatin1());
        if (raw.isEmpty() || !payloadHasAnkamaIri(raw)) {
            continue;
        }
        modelo_.plantillasPorCardinal[nk] = raw;
    }

    modeloCargado_ = true;
    loadedPath_ = path;
    return true;
}

bool IriCardinalEmulator::pickCrossBase(const QString& destCardinal, QByteArray* baseOut,
                                        QString* sourceCardOut) const
{
    if (!modeloCargado_) {
        return false;
    }

    QVector<QPair<int, QString>> scored;

    static const QString kOrd[]{QStringLiteral("Norte"), QStringLiteral("Sur"), QStringLiteral("Este"),
                              QStringLiteral("Oeste")};
    for (const QString& cs : kOrd) {
        if (cs == destCardinal) {
            continue;
        }
        auto it = modelo_.plantillasPorCardinal.constFind(cs);
        if (it == modelo_.plantillasPorCardinal.cend()) {
            continue;
        }
        scored.append({0, cs});
    }
    if (scored.isEmpty()) {
        return false;
    }
    std::sort(scored.begin(), scored.end(), [](const QPair<int, QString>& a, const QPair<int, QString>& b) {
        if (a.first != b.first) {
            return a.first > b.first;
        }
        return a.second < b.second;
    });

    const QString src = scored.first().second;
    if (baseOut != nullptr) {
        *baseOut = modelo_.plantillasPorCardinal.value(src);
    }
    if (sourceCardOut != nullptr) {
        *sourceCardOut = src;
    }
    return true;
}

bool IriCardinalEmulator::patchTowardCardinal(const QByteArray& baseBlob, const QString& destCardinal,
                                              QByteArray* patchedOut, QString* debugOut) const
{
    if (!modeloCargado_) {
        if (debugOut != nullptr) {
            *debugOut = QStringLiteral("Modelo no cargado");
        }
        return false;
    }
    if (!payloadHasAnkamaIri(baseBlob)) {
        if (debugOut != nullptr) {
            *debugOut = QStringLiteral("Sin marca type.ankama.com/iri");
        }
        return false;
    }

    if (!modelo_.mapeo.contains(destCardinal)) {
        if (debugOut != nullptr) {
            *debugOut = QStringLiteral("sin mapeo para %1").arg(destCardinal);
        }
        return false;
    }
    const qint32 tgtVal = modelo_.mapeo.value(destCardinal);

    const int off = modelo_.offset;

    if (modelo_.tipo == QStringLiteral("byte")) {
        if (off < 0 || off >= baseBlob.size()) {
            if (debugOut != nullptr) {
                *debugOut = QStringLiteral("offset fuera del payload");
            }
            return false;
        }

        QByteArray blob = baseBlob;
        const uchar cur = static_cast<uchar>(blob.at(off));

        /// Python muestra mensaje cuando byte actual == valor destino pero plantilla≠dest puede ser confuso —
        /// enviamos igual el parche sólo si difiere para evitar tráficos «vacíos».

        blob[off] = char(quint8(tgtVal & 0xFF));

        QString dbg =
            QStringLiteral("byte @0x%1 (0x%2→0x%3)")
                .arg(off, 0, 16)
                .arg(quint32(cur), 2, 16, QLatin1Char('0'))
                .arg(quint32(tgtVal & 0xFF), 2, 16, QLatin1Char('0'));

        if (qint32(cur) == tgtVal) {
            /// No-op igual que servidor no cambiaría destino útilmente
            if (debugOut != nullptr) {
                *debugOut = dbg + QStringLiteral(" · la plantilla ya codifica ese cardinal (prueba otro ejemplo).");
            }
            return false;
        }

        if (patchedOut != nullptr) {
            *patchedOut = blob;
        }
        if (debugOut != nullptr) {
            *debugOut = dbg;
        }
        return true;
    }

    if (modelo_.tipo == QStringLiteral("varint")) {
        if (off < 0 || off >= baseBlob.size()) {
            if (debugOut != nullptr) {
                *debugOut = QStringLiteral("offset fuera del payload");
            }
            return false;
        }

        QByteArray blob = baseBlob;
        quint64 oldU = 0;
        int end = off;
        if (!decodeVarintRaw(blob, off, &oldU, &end)) {
            if (debugOut != nullptr) {
                *debugOut = QStringLiteral("varint ilegible en offset");
            }
            return false;
        }
        const QString e = patchVarintSameLenRawEnum(blob, off, tgtVal);
        if (!e.isEmpty()) {
            if (debugOut != nullptr) {
                *debugOut = e;
            }
            return false;
        }
        QString dbg =
            QStringLiteral("varint @0x%1 (%2→%3)").arg(off, 0, 16).arg(oldU).arg(tgtVal);
        if (oldU == static_cast<quint64>(quint32(qMax(0, tgtVal)))) {
            if (debugOut != nullptr) {
                *debugOut =
                    dbg + QStringLiteral(" · valor ya coincide (no-op práctico).");
            }
            return false;
        }
        if (patchedOut != nullptr) {
            *patchedOut = blob;
        }
        if (debugOut != nullptr) {
            *debugOut = dbg;
        }
        return true;
    }

    if (debugOut != nullptr) {
        *debugOut = QStringLiteral("tipo desconocido");
    }
    return false;
}

static constexpr int kIriPayloadMinBytes = 50;
static constexpr int kIriPayloadMaxBytes = 70;
static constexpr int kIriRouteStartIndex = 22;
static constexpr int kIriTokenOffset = 17;
static constexpr int kIriTokenLength = 5;
static constexpr int kIriRouteMinBytes = 10;

static bool rawHasBadAnkamaPath(const QByteArray& p)
{
    static const QByteArray bad[] = {
        QByteArrayLiteral("type.ankama.com/irw"),
        QByteArrayLiteral("type.ankama.com/isu"),
        QByteArrayLiteral("type.ankama.com/isp"),
        QByteArrayLiteral("type.ankama.com/jrt"),
    };
    for (const QByteArray& b : bad) {
        if (p.contains(b)) {
            return true;
        }
    }
    return false;
}

QString formatSessionTokenHex(const QByteArray& fiveBytes)
{
    QString s;
    for (int i = 0; i < fiveBytes.size(); ++i) {
        if (i > 0) {
            s += QLatin1Char(' ');
        }
        s += QStringLiteral("%1").arg(static_cast<quint8>(static_cast<uchar>(fiveBytes.at(i))), 2, 16, QLatin1Char('0'));
    }
    return s;
}

IriPacketAnalysis analyzeIriPayload(const QByteArray& payload, const DirectionMapModel* modelOrNull)
{
    IriPacketAnalysis r;
    r.payloadSize = payload.size();

    if (rawHasBadAnkamaPath(payload)) {
        r.errors << QStringLiteral("Contiene URL de mensaje distinta de /iri (p. ej. /irw, /isu, /isp, /jrt).");
    }
    if (!payload.contains(QByteArrayLiteral("type.ankama.com/iri"))) {
        r.errors << QStringLiteral("Falta el literal type.ankama.com/iri en el payload.");
    }
    r.validStrictUrl = r.errors.isEmpty() && payload.contains(QByteArrayLiteral("type.ankama.com/iri"));

    r.payloadSizeOk = (r.payloadSize >= kIriPayloadMinBytes && r.payloadSize <= kIriPayloadMaxBytes);
    if (!r.payloadSizeOk) {
        r.warnings << QStringLiteral("Tamaño %1 B · rango heurístico %2–%3 B.")
                          .arg(r.payloadSize)
                          .arg(kIriPayloadMinBytes)
                          .arg(kIriPayloadMaxBytes);
    }

    if (r.payloadSize >= kIriRouteStartIndex) {
        r.sessionToken5 = payload.mid(kIriTokenOffset, kIriTokenLength);
        r.routeByteCount = r.payloadSize - kIriRouteStartIndex;
    } else {
        r.warnings << QStringLiteral("Menos de %1 B: no aplica heurística token@17 + ruta@22.")
                          .arg(kIriRouteStartIndex);
    }

    r.routeLengthOk = (r.routeByteCount >= kIriRouteMinBytes);
    if (r.payloadSize >= kIriRouteStartIndex && !r.routeLengthOk) {
        r.warnings << QStringLiteral("Ruta ≈ %1 B desde el índice %2 (recomendado ≥ %3 B).")
                          .arg(r.routeByteCount)
                          .arg(kIriRouteStartIndex)
                          .arg(kIriRouteMinBytes);
    }

    if (modelOrNull != nullptr) {
        r.inferredCardinal = inferCardinalAtModelOffset(payload, *modelOrNull);
    }
    return r;
}

bool findFirstValidIriInExportLog(const QString& logFilePath, QByteArray* outPayload, int* packetIndexOut,
                                 IriPacketAnalysis* analysisOut, QString* errOut)
{
    if (outPayload == nullptr) {
        if (errOut != nullptr) {
            *errOut = QStringLiteral("outPayload nulo");
        }
        return false;
    }
    outPayload->clear();
    if (packetIndexOut != nullptr) {
        *packetIndexOut = -1;
    }
    if (analysisOut != nullptr) {
        *analysisOut = IriPacketAnalysis();
    }

    QFile f(logFilePath);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (errOut != nullptr) {
            *errOut = QStringLiteral("No se abre: %1").arg(logFilePath);
        }
        return false;
    }
    const QString text = QString::fromUtf8(f.readAll());
    f.close();

    int currentPacket = -1;
    const QRegularExpression reLinePacket(QStringLiteral("^\\s*#(\\d+)\\b"));
    const QRegularExpression reHexOnly(QStringLiteral("([^0-9A-Fa-f])"));

    const QStringList lines = text.split(QLatin1Char('\n'));
    for (const QString& lineIn : lines) {
        QString line = lineIn;
        const QRegularExpressionMatch mNum = reLinePacket.match(line);
        if (mNum.hasMatch()) {
            currentPacket = mNum.captured(1).toInt();
        }
        line.remove(reHexOnly);
        if (line.size() < 100) {
            continue;
        }
        if (line.size() % 2 != 0) {
            line.chop(1);
        }
        const QByteArray raw = QByteArray::fromHex(line.toLatin1());
        if (raw.size() < kIriPayloadMinBytes) {
            continue;
        }
        IriPacketAnalysis a = analyzeIriPayload(raw, nullptr);
        if (!a.overallAcceptableForInjection()) {
            continue;
        }
        *outPayload = raw;
        if (packetIndexOut != nullptr) {
            *packetIndexOut = currentPacket;
        }
        if (analysisOut != nullptr) {
            *analysisOut = a;
        }
        return true;
    }

    if (errOut != nullptr) {
        *errOut = QStringLiteral("No se encontró ningún bloque hex que cumpla ☆iri + talla + ruta (revisa el export).");
    }
    return false;
}

bool mergeEjemploHexIntoDirectionMapJson(const QString& directionMapJsonPath, const QString& cardinalNormalized,
                                         const QByteArray& rawPayload, QString* errOut)
{
    if (directionMapJsonPath.trimmed().isEmpty()) {
        if (errOut != nullptr) {
            *errOut = QStringLiteral("Ruta JSON vacía.");
        }
        return false;
    }
    QFile f(directionMapJsonPath);
    if (!f.open(QIODevice::ReadOnly)) {
        if (errOut != nullptr) {
            *errOut = QStringLiteral("No se lee: %1").arg(directionMapJsonPath);
        }
        return false;
    }
    QJsonParseError jpe{};
    const QJsonDocument jd = QJsonDocument::fromJson(f.readAll(), &jpe);
    f.close();
    if (jpe.error != QJsonParseError::NoError || !jd.isObject()) {
        if (errOut != nullptr) {
            *errOut = jpe.errorString();
        }
        return false;
    }
    QJsonObject root = jd.object();
    QJsonObject ej = root.value(QStringLiteral("ejemplos_hex")).toObject();
    ej.insert(cardinalNormalized, QString::fromLatin1(rawPayload.toHex()));
    root.insert(QStringLiteral("ejemplos_hex"), ej);

    const QByteArray out = QJsonDocument(root).toJson(QJsonDocument::Indented);
    QFile fo(directionMapJsonPath);
    if (!fo.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (errOut != nullptr) {
            *errOut = QStringLiteral("No se puede escribir: %1").arg(directionMapJsonPath);
        }
        return false;
    }
    fo.write(out);
    fo.close();
    return true;
}

bool saveTemplatesJsonSidecar(const QString& directionMapJsonPath, const QString& cardinalNormalized,
                             const QByteArray& rawPayload, const IriPacketAnalysis& analysis,
                             const QString& sourceLogPath, QString* errOut)
{
    const QFileInfo fi(directionMapJsonPath);
    const QString sidecar = fi.absoluteDir().filePath(QStringLiteral("templates.json"));

    QJsonObject root;
    QFile fr(sidecar);
    if (fr.open(QIODevice::ReadOnly)) {
        QJsonParseError jpe{};
        const QJsonDocument ex = QJsonDocument::fromJson(fr.readAll(), &jpe);
        fr.close();
        if (jpe.error == QJsonParseError::NoError && ex.isObject()) {
            root = ex.object();
        }
    }

    QJsonObject ej = root.value(QStringLiteral("ejemplos_hex_importados")).toObject();
    ej.insert(cardinalNormalized, QString::fromLatin1(rawPayload.toHex()));
    root.insert(QStringLiteral("ejemplos_hex_importados"), ej);

    QJsonObject meta;
    meta.insert(QStringLiteral("archivo_origen"), sourceLogPath);
    meta.insert(QStringLiteral("fecha_utc"), QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
    meta.insert(QStringLiteral("tam_payload"), analysis.payloadSize);
    meta.insert(QStringLiteral("token_hex"), formatSessionTokenHex(analysis.sessionToken5));
    meta.insert(QStringLiteral("ruta_bytes"), analysis.routeByteCount);
    root.insert(QStringLiteral("ultima_importacion"), meta);

    const QByteArray out = QJsonDocument(root).toJson(QJsonDocument::Indented);
    QFile fw(sidecar);
    if (!fw.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (errOut != nullptr) {
            *errOut = QStringLiteral("No se escribe %1").arg(sidecar);
        }
        return false;
    }
    fw.write(out);
    fw.close();
    return true;
}
