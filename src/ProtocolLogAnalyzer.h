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

/// Estructura mínima para recursos (y eventos de recolección) extraída desde Protobuf.
struct ResourceInfo {
    quint64 typeId = 0;     // ej. 514663 (Fresno)
    quint64 instanceId = 0; // id de instancia en mapa (cuando exista)
    int x = 0;
    int y = 0;
    int cell = 0;
    bool hasXy = false;
    bool hasCell = false;
};

struct CharacterSnapshot {
    QString name;
    int level = 0;
    QString classLine;
    int sourcePacketIndex = -1;
};

/// Coordenadas isométricas internas de Dofus para una celda (MapPoint.as).
/// El mapa estándar tiene 560 celdas, con MAP_WIDTH=14 y MAP_HEIGHT=20.
struct DofusCellCoord {
    int x = 0;
    int y = 0;
    bool ok = false;
};

/// cellId [0..559] -> (x,y) usando la tabla CELLPOS (misma que MapPoint.as).
[[nodiscard]] DofusCellCoord dofusCellToCoord(int cellId);

/// (x,y) -> cellId [0..559] usando la fórmula de MapPoint.as.
/// Devuelve -1 si está fuera del mapa o si la paridad no cuadra.
[[nodiscard]] int dofusCoordToCell(int x, int y);

/// Ruta (sin obstáculos) entre dos celdas usando vecinos 8-dir de MapPoint.
/// Devuelve una lista de cellIds incluyendo origen y destino; vacía si inválido.
[[nodiscard]] QList<int> calculateCellPath(int cellFrom, int cellTo);

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

/// Extrae map_id "largo" de los paquetes más confiables de mapa.
/// - ISA: busca el varint que sigue al tag 0x20 dentro del mensaje `type.ankama.com/isa`.
/// - ITX: busca el varint que sigue al tag 0x18 dentro del mensaje `type.ankama.com/itx`.
/// Devuelve true si pudo extraer un ID en el rango típico (100M..400M).
[[nodiscard]] bool tryExtractMapIdLongFromIsaOrItx(const QByteArray& payload, quint64& mapIdOut);

/// Intenta extraer `map_id` desde IRI (field 2 en `iri.cs`).
[[nodiscard]] bool tryGetIriMapId(const QByteArray& payload, quint64& mapIdOut);

/// Intenta extraer una lista de varints «ruta» desde IRI (field 3: `ket`).
/// Nota: el tipo `ket` no es un `repeated` directo; esta función hace un best-effort
/// recolectando varints anidados dentro del field 3.
[[nodiscard]] bool tryGetIriPathVarints(const QByteArray& payload, QList<quint64>& pathOut);

/// Extrae `type_id` / `instance_id` desde IEV (en el log `fresnoo`: field1=type_id, field2=instance_id).
[[nodiscard]] bool tryGetIevTapInfo(const QByteArray& payload, ResourceInfo& out);

/// Heurística para ISO: intenta encontrar recursos (type_id + instance_id + cell/coords) recorriendo submensajes.
/// Útil mientras no tengamos `.proto` / clase C# del snapshot.
[[nodiscard]] QList<ResourceInfo> extractIsoResourcesHeuristic(const QByteArray& payload);

/// Heurística para ITX: intenta extraer entradas de recursos desde la carga pesada de mapa.
/// Busca submensajes que contengan un type_id en rango [512000..519999] y, dentro de anidados,
/// cell (<560) + instance_id (mediano, >1000).
[[nodiscard]] QList<ResourceInfo> extractResourcesFromItx(const QByteArray& payload);

/// Calcula un camino Manhattan simple entre (x1,y1) y (x2,y2).
/// Norte: y-1, Sur: y+1, Este: x+1, Oeste: x-1
[[nodiscard]] QList<QString> calculatePath(int x1, int y1, int x2, int y2);

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
