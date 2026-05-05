#include "MainWindow.h"

#include <QApplication>

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("proyecto1"));
    QApplication::setApplicationName(QStringLiteral("DofusProcessHub"));

    MainWindow w;
    w.resize(980, 640);
    w.show();
    return a.exec();
}
