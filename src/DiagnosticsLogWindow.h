#pragma once

#include <QMainWindow>

class QCheckBox;
class QPlainTextEdit;

/// Ventana flotante con el mismo flujo de log que el panel principal (copiar / guardar / borrar vista).
class DiagnosticsLogWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit DiagnosticsLogWindow(QWidget* parent = nullptr);

    void appendLine(const QString& line);
    [[nodiscard]] QString fullPlainText() const;

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void copyAllToClipboard();
    void saveToFile();
    void clearView();

private:
    QPlainTextEdit* edit_ = nullptr;
    QCheckBox* onTop_ = nullptr;
};
