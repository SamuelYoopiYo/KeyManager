#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QLineEdit>
#include <QJsonArray>
#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    bool readJSON();
    QJsonArray jsonArr;
    int decryptFile(const QByteArray& encryptedBytes, QByteArray& decryptedBytes);
    ~MainWindow();

private:
    Ui::MainWindow *ui;

private slots:
    void filterListWidget(const QString &searchStrings);
    void on_lineEdit_2_returnPressed();
    void on_pushButton_clicked();
};
#endif // MAINWINDOW_H
