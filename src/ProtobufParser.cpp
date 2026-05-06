#include "ProtobufParser.h"

#include <QDateTime>

namespace {

constexpr int kWireVarint = 0;
constexpr int kWireFixed64 = 1;
constexpr int kWireLen = 2;
constexpr int kWireFixed32 = 5;

static bool looksLikePrintableAscii(const QByteArray& b)
{
    if (b.isEmpty()) return false;
    for (unsigned char c : b) {
        if (c == '\n' || c == '\r' || c == '\t') continue;
        if (c < 0x20 || c > 0x7e) return false;
    }
    return true;
}

static QString bytesPreview(const QByteArray& b)
{
    if (b.startsWith(QByteArrayLiteral("type.ankama.com/"))) {
        return QStringLiteral("\"%1\"").arg(QString::fromLatin1(b));
    }
    if (looksLikePrintableAscii(b) && b.size() <= 120) {
        return QStringLiteral("\"%1\"").arg(QString::fromLatin1(b));
    }
    if (b.size() <= 64) {
        return QStringLiteral("[%1 bytes] %2").arg(b.size()).arg(QString::fromLatin1(b.toHex()));
    }
    return QStringLiteral("[%1 bytes] (binario)").arg(b.size());
}

} // namespace

ProtobufParser::ProtobufParser(ParseLimits limits)
    : limits_(limits)
{
}

ProtobufParser::ProtobufParser()
    : limits_(ParseLimits())
{
}

bool ProtobufParser::readVarint(const QByteArray& data, int& offset, quint64* out)
{
    if (out == nullptr) return false;
    if (offset < 0 || offset >= data.size()) return false;
    quint64 result = 0;
    int shift = 0;
    int i = offset;
    while (i < data.size()) {
        const quint8 b = static_cast<quint8>(data.at(i));
        result |= (quint64(b & 0x7F) << shift);
        ++i;
        if ((b & 0x80) == 0) {
            offset = i;
            *out = result;
            return true;
        }
        shift += 7;
        if (shift > 63) {
            return false;
        }
    }
    return false;
}

bool ProtobufParser::parseMessage(const QByteArray& data, int& offset, int depth, QList<ProtoField>* out,
                                 int& fieldsBudget) const
{
    if (out == nullptr) return false;
    if (depth > limits_.maxDepth) return false;
    if (offset < 0 || offset > data.size()) return false;

    const int start = offset;
    while (offset < data.size() && fieldsBudget > 0) {
        ParseOneResult one = parseNext(data, offset, depth, fieldsBudget);
        if (!one.ok) {
            break;
        }
        out->push_back(one.field);
    }
    return offset > start;
}

ProtobufParser::ParseOneResult ProtobufParser::parseNext(const QByteArray& data, int& offset, int depth,
                                                         int& fieldsBudget) const
{
    ParseOneResult res;
    if (fieldsBudget <= 0) return res;
    if (offset < 0 || offset >= data.size()) return res;
    if (depth > limits_.maxDepth) return res;

    quint64 tag = 0;
    const int tagStart = offset;
    if (!readVarint(data, offset, &tag)) {
        offset = tagStart;
        return res;
    }
    const int fieldNum = int(tag >> 3);
    const int wireType = int(tag & 0x07);
    if (fieldNum <= 0) {
        return res;
    }

    ProtoField f;
    f.fieldNumber = fieldNum;
    f.wireType = wireType;

    if (wireType == kWireVarint) {
        quint64 v = 0;
        if (!readVarint(data, offset, &v)) return res;
        f.value = QVariant::fromValue<qulonglong>(static_cast<qulonglong>(v));
    } else if (wireType == kWireLen) {
        quint64 len = 0;
        if (!readVarint(data, offset, &len)) return res;
        if (len > quint64(data.size() - offset)) return res;
        const int ilen = int(len);
        QByteArray bytes = data.mid(offset, ilen);
        offset += ilen;
        f.value = bytes;

        // Intento anidado (best-effort): solo si el blob no es enorme y no parece string obvio.
        if (depth < limits_.maxDepth && ilen > 0 && ilen <= limits_.maxBytesNestedTry) {
            if (!bytes.startsWith(QByteArrayLiteral("type.ankama.com/")) && !looksLikePrintableAscii(bytes)) {
                int off2 = 0;
                QList<ProtoField> nested;
                const int budgetBefore = fieldsBudget;
                if (parseMessage(bytes, off2, depth + 1, &nested, fieldsBudget) && off2 == bytes.size()
                    && !nested.isEmpty() && fieldsBudget < budgetBefore) {
                    f.isNested = true;
                    f.nested = nested;
                }
            }
        }
    } else if (wireType == kWireFixed64) {
        if (offset + 8 > data.size()) return res;
        quint64 v = 0;
        memcpy(&v, data.constData() + offset, 8);
        offset += 8;
        f.value = QVariant::fromValue<qulonglong>(static_cast<qulonglong>(v));
    } else if (wireType == kWireFixed32) {
        if (offset + 4 > data.size()) return res;
        quint32 v = 0;
        memcpy(&v, data.constData() + offset, 4);
        offset += 4;
        f.value = QVariant::fromValue<qulonglong>(static_cast<qulonglong>(v));
    } else {
        return res;
    }

    --fieldsBudget;
    res.ok = true;
    res.field = f;
    return res;
}

QList<ProtoField> ProtobufParser::parse(const QByteArray& data) const
{
    QList<ProtoField> out;
    if (data.isEmpty()) return out;
    int offset = 0;
    int budget = limits_.maxFieldsTotal;
    (void)parseMessage(data, offset, /*depth*/ 0, &out, budget);
    return out;
}

QString detectPacketContext(const QByteArray& payload)
{
    if (payload.contains(QByteArrayLiteral("type.ankama.com/iri"))) return QStringLiteral("iri");
    if (payload.contains(QByteArrayLiteral("type.ankama.com/iso"))) return QStringLiteral("iso");
    if (payload.contains(QByteArrayLiteral("type.ankama.com/irx"))) return QStringLiteral("irx");
    if (payload.contains(QByteArrayLiteral("type.ankama.com/any"))) return QStringLiteral("any");
    if (payload.contains(QByteArrayLiteral("type.ankama.com/iee")) || payload.contains(QByteArrayLiteral("iev"))
        || payload.contains(QByteArrayLiteral("ieu"))) {
        return QStringLiteral("iee");
    }
    return QStringLiteral("unknown");
}

QString getFieldName(int fieldNum, const QString& context)
{
    const QString c = context.toLower();
    if (c == QStringLiteral("iri")) {
        if (fieldNum == 1) return QStringLiteral("session_token");
        if (fieldNum == 2) return QStringLiteral("any_wrapper");
        if (fieldNum == 3) return QStringLiteral("map_id");
        if (fieldNum == 4) return QStringLiteral("path");
    }
    if (c == QStringLiteral("iso")) {
        if (fieldNum == 1) return QStringLiteral("resource_list");
        if (fieldNum == 2) return QStringLiteral("resource_instance");
    }
    if (c == QStringLiteral("any") || c.contains(QStringLiteral("any"))) {
        if (fieldNum == 1) return QStringLiteral("type_url");
        if (fieldNum == 2) return QStringLiteral("payload");
    }
    return QStringLiteral("field%1").arg(fieldNum);
}

QString formatProtoFields(const QList<ProtoField>& fields, int indent, const QString& context)
{
    QString result;
    const QString indentStr(indent * 2, QLatin1Char(' '));
    for (const ProtoField& f : fields) {
        const QString name = getFieldName(f.fieldNumber, context);
        if (f.wireType == kWireVarint) {
            const quint64 v = static_cast<quint64>(f.value.toULongLong());
            result += QStringLiteral("%1%2: %3\n").arg(indentStr, name, QString::number(v));
        } else if (f.wireType == kWireLen && f.isNested) {
            QString newContext = name;
            // Heurística: si es wrapper Any, el contexto de adentro es "any".
            if (name.contains(QStringLiteral("any"), Qt::CaseInsensitive)) {
                newContext = QStringLiteral("any");
            }
            result += QStringLiteral("%1%2: {\n").arg(indentStr, name);
            result += formatProtoFields(f.nested, indent + 1, newContext);
            result += QStringLiteral("%1}\n").arg(indentStr);
        } else if (f.wireType == kWireLen) {
            const QByteArray b = f.value.toByteArray();
            result += QStringLiteral("%1%2: %3\n").arg(indentStr, name, bytesPreview(b));
        } else if (f.wireType == kWireFixed64) {
            const quint64 v = static_cast<quint64>(f.value.toULongLong());
            result += QStringLiteral("%1%2: %3 (64-bit)\n").arg(indentStr, name, QString::number(v));
        } else if (f.wireType == kWireFixed32) {
            const quint32 v = static_cast<quint32>(f.value.toULongLong());
            result += QStringLiteral("%1%2: %3 (32-bit)\n").arg(indentStr, name, QString::number(v));
        } else {
            result += QStringLiteral("%1%2: (wire=%3)\n").arg(indentStr, name, QString::number(f.wireType));
        }
    }
    return result;
}

