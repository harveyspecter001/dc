#include "DiagnosticsLogWindow.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QFile>
#include <QFileDialog>
#include <QFont>
#include <QIODevice>
#include <QScrollBar>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

DiagnosticsLogWindow::DiagnosticsLogWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("Logs de diagnóstico — DofusProcessHub"));
    setMinimumSize(680, 420);
    resize(900, 560);
    setAttribute(Qt::WA_QuitOnClose, false);

    auto* central = new QWidget(this);
    setCentralWidget(central);
    auto* root = new QVBoxLayout(central);

    auto* hint = new QLabel(QStringLiteral(
        "<p>Se registran aquí las mismas líneas que en la pestaña <b>Registro</b>, con hora. "
        "<b>Copiar todo</b> o <b>Guardar…</b> y pégame el archivo o el texto para revisar reconexiones / proxy.</p>"));
    hint->setWordWrap(true);
    root->addWidget(hint);

    edit_ = new QPlainTextEdit;
    edit_->setReadOnly(true);
    edit_->setMaximumBlockCount(25000);
    edit_->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    edit_->setPlaceholderText(QStringLiteral("Aún no hay líneas…"));
    {
        auto f = edit_->font();
        f.setFamily(QStringLiteral("Consolas"));
        f.setStyleHint(QFont::Monospace);
        edit_->setFont(f);
    }
    root->addWidget(edit_, 1);

    auto* row = new QHBoxLayout;
    auto* copyBtn = new QPushButton(QStringLiteral("Copiar todo"));
    connect(copyBtn, &QPushButton::clicked, this, &DiagnosticsLogWindow::copyAllToClipboard);
    row->addWidget(copyBtn);

    auto* saveBtn = new QPushButton(QStringLiteral("Guardar en archivo…"));
    connect(saveBtn, &QPushButton::clicked, this, &DiagnosticsLogWindow::saveToFile);
    row->addWidget(saveBtn);

    auto* clearBtn = new QPushButton(QStringLiteral("Borrar vista"));
    connect(clearBtn, &QPushButton::clicked, this, &DiagnosticsLogWindow::clearView);
    row->addWidget(clearBtn);

    onTop_ = new QCheckBox(QStringLiteral("Siempre visible (encima)"));
    connect(onTop_, &QCheckBox::toggled, this, [this](bool on) {
        setWindowFlag(Qt::WindowStaysOnTopHint, on);
        show();
        raise();
        activateWindow();
    });
    row->addWidget(onTop_);

    row->addStretch(1);
    root->addLayout(row);
}

void DiagnosticsLogWindow::appendLine(const QString& line)
{
    if (edit_ == nullptr) {
        return;
    }
    edit_->appendPlainText(line);
    {
        auto sb = edit_->verticalScrollBar();
        sb->setValue(sb->maximum());
    }
}

QString DiagnosticsLogWindow::fullPlainText() const
{
    return edit_ != nullptr ? edit_->toPlainText() : QString();
}

void DiagnosticsLogWindow::closeEvent(QCloseEvent* event)
{
    hide();
    event->ignore();
}

void DiagnosticsLogWindow::copyAllToClipboard()
{
    const QString t = fullPlainText();
    if (t.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Copiar"),
                                 QStringLiteral("No hay texto que copiar."));
        return;
    }
    QApplication::clipboard()->setText(t);
    QMessageBox::information(this, QStringLiteral("Copiar"),
                             QStringLiteral("Se copiaron %1 caracteres al portapapeles.").arg(t.size()));
}

void DiagnosticsLogWindow::saveToFile()
{
    const QString path = QFileDialog::getSaveFileName(
        this, QStringLiteral("Guardar log"), QStringLiteral("dofus_process_hub_log.txt"),
        QStringLiteral("Texto (*.txt);;Todos (*.*)"));
    if (path.isEmpty()) {
        return;
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, QStringLiteral("Guardar"),
                             QStringLiteral("No se pudo escribir: %1").arg(f.errorString()));
        return;
    }
    f.write(fullPlainText().toUtf8());
    f.close();
    QMessageBox::information(this, QStringLiteral("Guardar"), QStringLiteral("Guardado en:\n%1").arg(path));
}

void DiagnosticsLogWindow::clearView()
{
    if (edit_ != nullptr) {
        edit_->clear();
    }
}
