#pragma once

#include <QDialog>

class QTableWidget;

/// Editor visual para `ids_database.json` (recursos, monstruos, objetos, notas por ID).
class ResourceAliasEditor : public QDialog {
    Q_OBJECT
public:
    explicit ResourceAliasEditor(QWidget* parent = nullptr);

    void loadFromMaps(const QHash<quint64, QString>& resources,
                      const QHash<quint64, QString>& monsters,
                      const QHash<quint64, QString>& players,
                      const QHash<quint64, QString>& objects,
                      const QHash<quint64, QString>& notes);

    void applyToMaps(QHash<quint64, QString>* resources,
                     QHash<quint64, QString>* monsters,
                     QHash<quint64, QString>* players,
                     QHash<quint64, QString>* objects,
                     QHash<quint64, QString>* notes) const;

private:
    QTableWidget* table_ = nullptr;
};
