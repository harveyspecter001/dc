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
    IdyItemDisplayed,
    IdwItemVanished,
    IsuClientSync,
    IrkSyncResponse,
    KjCompression,
    JmwMonsterCmd,
    CommandData,
    JrrCommandResponse,
    IspSync,
    ItvInteraction,
    /// Cliente ↔ servidor durante transición entre mapas (clic norte/sur…) — rutas vistas en dumps.
    IsaPingClient,
    ItrMapTransitClient,
    IshMapTinyServer,
    ItoMapTransitClient,
    /// Servidor ~106 B típ.: iue+iuc+knw en el mismo mensaje (contexto/coords mapa).
    MapHydrateTripleServer,
    /// Cliente ~88 B: mismo payload combina «jnr» e «isp» (paso de mapa característico).
    MapHopJnrIspClient,
    /// Carga voluminosa servidor (tiles / binario mapa típ.).
    ItxMapHeavyServer,
    KtaKeyedServer,
    JsaPulseClient,
    JsbPulseServer,
    /// Rutas vistas al farmear / tocar recurso en mapa (sin ISO tipico).
    MapGatherIerSnapshotServer,
    MapGatherIevTapClient,
    MapGatherIeuBundleServer,
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

class PacketTypeOverrides;

[[nodiscard]] PacketKind classifyPacketKind(const QByteArray& payload);

[[nodiscard]] QString packetKindDisplayString(PacketKind k);

/// Convierte etiquetas del menú / JSON (ej. «IRI (MOVIMIENTO)») a enum; Unknown si no coincide.
[[nodiscard]] PacketKind packetKindFromDisplayLabel(const QString& label);

[[nodiscard]] QStringList standardPacketKindLabels();

[[nodiscard]] QVector<IdRangeRule> defaultBuiltinIdRules();

/// Líneas: `513600-513699:Trigo`, `# comentario`, vacías ignoradas. Categoría opcional `min-max:Nombre:monstruo`
[[nodiscard]] QVector<IdRangeRule> parseIdAliasRulesText(const QString& text);

[[nodiscard]] QString resolveIdWithRules(quint64 id, const QVector<IdRangeRule>& rules, QString* categoryOut);

[[nodiscard]] QString resourceDisplayNameForId(quint64 id);

void extractAnkamaTypeUrls(const QByteArray& payload, QStringList* outUrls);

void extractProtobufStyleVarints(const QByteArray& payload, QList<quint64>* outValues);

/// Extrae números del wire-format Protobuf (varint + fixed32 + fixed64) recorriendo anidados best-effort.
/// Útil para RECO (IEU/IER) donde el ID del recurso puede no aparecer como varint plano.
void extractProtobufWireNumericScalars(const QByteArray& payload, QList<quint64>* outValues);

[[nodiscard]] ProtocolPacketRecord buildRecordFromPayload(int packetIndex, bool fromClient,
                                                          const QByteArray& payload,
                                                          const PacketTypeOverrides* overrides = nullptr);

[[nodiscard]] QList<quint64> filterResourceCandidateIds(const QList<quint64>& varints,
                                                         const QVector<IdRangeRule>& extraRules = {});

[[nodiscard]] quint64 guessMapIdHeuristic(const QByteArray& payload);

void guessCharacterFromServerPayload(const QByteArray& payload, int packetIndex, CharacterSnapshot* inOut);

[[nodiscard]] QString formatVarintsPreview(const QList<quint64>& v, int maxCount = 3);

[[nodiscard]] QString formatHexDumpWireshark(const QByteArray& data, int maxBytes = 256);

struct IrxVarintBuckets {
    QList<quint64> monsters;  // típico ≥ 1M
    QList<quint64> players;   // típico 1k–9k
    QList<quint64> structure; // típico < 1k
    QList<quint64> other;
};

[[nodiscard]] IrxVarintBuckets classifyIrxStyleVarints(const QList<quint64>& rawIds);

/// Agrupa varints típicos en IRX (monstruos vs jugadores vs otros).
[[nodiscard]] QString analyzeIrxStyleVarintBuckets(const QList<quint64>& numericIds);

[[nodiscard]] QString buildPacketAnalysisText(const ProtocolPacketRecord& rec, const QVector<IdRangeRule>& rulesChain,
                                               int hexMaxBytes = 256,
                                               const QHash<quint64, QString>* exactIdNotes = nullptr);

[[nodiscard]] bool parseExportedProxyLogText(const QString& text,
                                             QVector<QPair<bool, QByteArray>>* outChunks,
                                             QString* errorOut);
