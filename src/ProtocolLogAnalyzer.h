#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QString>
#include <QVector>

/// Tipos de mensaje por URL `type.ankama.com/…`.
enum class PacketKind {
    Unknown,
    DataGeneric,
    IriMovement,
    IrlList,
    IsoResources,
    IrxMonsters,
    IslEntities,
    IeeHarvest,
    IdrItemReceived,
    CommandData,
};

/// Regla `min-max:Etiqueta` o `min-max:Etiqueta:categoria` (categoría: recurso | monstruo | objeto).
struct IdRangeRule {
    quint64 lo = 0;
    quint64 hi = 0;
    QString label;
    QString category; // recurso, monstruo, objeto (vacío = recurso)
};

struct ProtocolPacketRecord {
    int index = 0;
    QDateTime received;
    bool fromClient = true;
    int byteSize = 0;
    PacketKind kind = PacketKind::Unknown;
    QString kindLabel;
    QString primaryUrl;
    QStringList stringsFound;
    QList<quint64> numericIds;
    QByteArray rawPayload;
};

struct CharacterSnapshot {
    QString name;
    int level = 0;
    QString classLine;
    int sourcePacketIndex = -1;
};

[[nodiscard]] PacketKind classifyPacketKind(const QByteArray& payload);

[[nodiscard]] QString packetKindDisplayString(PacketKind k);

[[nodiscard]] QVector<IdRangeRule> defaultBuiltinIdRules();

/// Líneas: `513600-513699:Trigo`, `# comentario`, vacías ignoradas. Categoría opcional `min-max:Nombre:monstruo`
[[nodiscard]] QVector<IdRangeRule> parseIdAliasRulesText(const QString& text);

[[nodiscard]] QString resolveIdWithRules(quint64 id, const QVector<IdRangeRule>& rules, QString* categoryOut);

[[nodiscard]] QString resourceDisplayNameForId(quint64 id);

void extractAnkamaTypeUrls(const QByteArray& payload, QStringList* outUrls);

void extractProtobufStyleVarints(const QByteArray& payload, QList<quint64>* outValues);

[[nodiscard]] ProtocolPacketRecord buildRecordFromPayload(int packetIndex, bool fromClient,
                                                          const QByteArray& payload);

[[nodiscard]] QList<quint64> filterResourceCandidateIds(const QList<quint64>& varints,
                                                         const QVector<IdRangeRule>& extraRules = {});

[[nodiscard]] quint64 guessMapIdHeuristic(const QByteArray& payload);

void guessCharacterFromServerPayload(const QByteArray& payload, int packetIndex, CharacterSnapshot* inOut);

[[nodiscard]] QString formatVarintsPreview(const QList<quint64>& v, int maxCount = 3);

[[nodiscard]] QString formatHexDumpWireshark(const QByteArray& data, int maxBytes = 256);

/// Agrupa varints típicos en IRX (monstruos vs jugadores vs otros).
[[nodiscard]] QString analyzeIrxStyleVarintBuckets(const QList<quint64>& numericIds);

[[nodiscard]] QString buildPacketAnalysisText(const ProtocolPacketRecord& rec, const QVector<IdRangeRule>& rulesChain,
                                               int hexMaxBytes = 256,
                                               const QHash<quint64, QString>* exactIdNotes = nullptr);

[[nodiscard]] bool parseExportedProxyLogText(const QString& text,
                                             QVector<QPair<bool, QByteArray>>* outChunks,
                                             QString* errorOut);
