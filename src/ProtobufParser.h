#pragma once

#include <QByteArray>
#include <QList>
#include <QString>
#include <QVariant>

struct ProtoField {
    int fieldNumber = 0;
    int wireType = 0; // 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit
    QVariant value;   // quint64, quint32, QByteArray
    QList<ProtoField> nested;
    bool isNested = false;
};

class ProtobufParser {
public:
    struct ParseLimits {
        int maxDepth = 8;
        int maxFieldsTotal = 120;    // por mensaje (incluye anidados)
        int maxBytesNestedTry = 4096; // no intentar parsear anidado en blobs gigantes
    };

    ProtobufParser();
    explicit ProtobufParser(ParseLimits limits);

    /// Parsea un payload protobuf "wire format" y devuelve fields top-level.
    /// Best-effort: si encuentra errores, devuelve lo que pudo (puede estar vacío).
    [[nodiscard]] QList<ProtoField> parse(const QByteArray& data) const;

private:
    ParseLimits limits_;

    struct ParseOneResult {
        bool ok = false;
        ProtoField field;
    };

    [[nodiscard]] ParseOneResult parseNext(const QByteArray& data, int& offset, int depth, int& fieldsBudget) const;
    [[nodiscard]] bool parseMessage(const QByteArray& data, int& offset, int depth, QList<ProtoField>* out,
                                    int& fieldsBudget) const;
    [[nodiscard]] static bool readVarint(const QByteArray& data, int& offset, quint64* out);
};

[[nodiscard]] QString detectPacketContext(const QByteArray& payload);
[[nodiscard]] QString getFieldName(int fieldNum, const QString& context);
[[nodiscard]] QString formatProtoFields(const QList<ProtoField>& fields, int indent = 0,
                                        const QString& context = QString());

