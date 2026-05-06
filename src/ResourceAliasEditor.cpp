#include "ResourceAliasEditor.h"

#include <QAbstractItemView>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <algorithm>

namespace {

QString catResource()
{
    return QStringLiteral("recurso");
}
QString catMonster()
{
    return QStringLiteral("monstruo");
}
QString catObject()
{
    return QStringLiteral("objeto");
}

} // namespace

ResourceAliasEditor::ResourceAliasEditor(QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("Editar recursos y monstruos"));
    resize(720, 440);

    auto* layout = new QVBoxLayout(this);
    auto* info =
        new QLabel(QStringLiteral("Filas: ID, nombre visible, categoría (mapa en JSON), notas opcionales. "
                                  "«Guardar» en el diálogo escribe ids_database.json."));
    info->setWordWrap(true);
    layout->addWidget(info);

    table_ = new QTableWidget(0, 4, this);
    table_->setHorizontalHeaderLabels(
        {QStringLiteral("ID"), QStringLiteral("Nombre"), QStringLiteral("Categoría"), QStringLiteral("Notas")});
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    layout->addWidget(table_, 1);

    auto* btnRow = new QHBoxLayout;
    auto* addBtn = new QPushButton(QStringLiteral("➕ Agregar fila"));
    auto* delBtn = new QPushButton(QStringLiteral("Eliminar fila"));
    btnRow->addWidget(addBtn);
    btnRow->addWidget(delBtn);
    btnRow->addStretch(1);
    layout->addLayout(btnRow);

    auto* bb = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    bb->button(QDialogButtonBox::Save)->setText(QStringLiteral("Guardar"));
    layout->addWidget(bb);

    connect(addBtn, &QPushButton::clicked, this, [this]() {
        const int row = table_->rowCount();
        table_->insertRow(row);
        table_->setItem(row, 0, new QTableWidgetItem(QStringLiteral("0")));
        table_->setItem(row, 1, new QTableWidgetItem(QStringLiteral("nombre")));
        auto* cb = new QComboBox;
        cb->addItem(catResource());
        cb->addItem(catMonster());
        cb->addItem(catObject());
        table_->setCellWidget(row, 2, cb);
        table_->setItem(row, 3, new QTableWidgetItem());
    });
    connect(delBtn, &QPushButton::clicked, this, [this]() {
        const int r = table_->currentRow();
        if (r >= 0) {
            table_->removeRow(r);
        }
    });
    connect(bb, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

void ResourceAliasEditor::loadFromMaps(const QHash<quint64, QString>& resources,
                                       const QHash<quint64, QString>& monsters,
                                       const QHash<quint64, QString>& objects,
                                       const QHash<quint64, QString>& notes)
{
    table_->setRowCount(0);

    QSet<quint64> all;
    for (auto it = resources.constBegin(); it != resources.constEnd(); ++it) {
        all.insert(it.key());
    }
    for (auto it = monsters.constBegin(); it != monsters.constEnd(); ++it) {
        all.insert(it.key());
    }
    for (auto it = objects.constBegin(); it != objects.constEnd(); ++it) {
        all.insert(it.key());
    }
    for (auto it = notes.constBegin(); it != notes.constEnd(); ++it) {
        all.insert(it.key());
    }

    QList<quint64> ids = all.values();
    std::sort(ids.begin(), ids.end());

    for (quint64 id : ids) {
        QString name;
        QString cat = catResource();
        if (monsters.contains(id)) {
            name = monsters.value(id);
            cat = catMonster();
        } else if (objects.contains(id)) {
            name = objects.value(id);
            cat = catObject();
        } else if (resources.contains(id)) {
            name = resources.value(id);
            cat = catResource();
        }
        const QString note = notes.value(id);

        const int row = table_->rowCount();
        table_->insertRow(row);
        table_->setItem(row, 0, new QTableWidgetItem(QString::number(id)));
        table_->setItem(row, 1, new QTableWidgetItem(name));
        auto* cb = new QComboBox;
        cb->addItem(catResource());
        cb->addItem(catMonster());
        cb->addItem(catObject());
        const int ix = cat == catMonster() ? 1 : (cat == catObject() ? 2 : 0);
        cb->setCurrentIndex(ix);
        table_->setCellWidget(row, 2, cb);
        table_->setItem(row, 3, new QTableWidgetItem(note));
    }
}

void ResourceAliasEditor::applyToMaps(QHash<quint64, QString>* resources,
                                      QHash<quint64, QString>* monsters,
                                      QHash<quint64, QString>* objects,
                                      QHash<quint64, QString>* notes) const
{
    if (resources == nullptr || monsters == nullptr || objects == nullptr || notes == nullptr) {
        return;
    }
    resources->clear();
    monsters->clear();
    objects->clear();
    notes->clear();

    for (int row = 0; row < table_->rowCount(); ++row) {
        auto* idIt = table_->item(row, 0);
        auto* nameIt = table_->item(row, 1);
        auto* noteIt = table_->item(row, 3);
        if (idIt == nullptr) {
            continue;
        }
        bool ok = false;
        const quint64 id = idIt->text().trimmed().toULongLong(&ok);
        if (!ok) {
            continue;
        }
        const QString name = nameIt ? nameIt->text().trimmed() : QString();
        const QString note = noteIt ? noteIt->text().trimmed() : QString();
        auto* cb = qobject_cast<QComboBox*>(table_->cellWidget(row, 2));
        const QString cat = cb ? cb->currentText() : catResource();

        if (!note.isEmpty()) {
            (*notes)[id] = note;
        }
        if (cat == catMonster()) {
            if (!name.isEmpty()) {
                (*monsters)[id] = name;
            }
        } else if (cat == catObject()) {
            if (!name.isEmpty()) {
                (*objects)[id] = name;
            }
        } else {
            if (!name.isEmpty()) {
                (*resources)[id] = name;
            }
        }
    }
}
