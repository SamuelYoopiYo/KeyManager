#ifndef LISTITEM_H
#define LISTITEM_H

#include <QWidget>

#include <modalwindow.h>

namespace Ui {
class ListItem;
}

class ListItem : public QWidget
{
    Q_OBJECT

public:
    explicit ListItem(QString site, QString login_encrypted, QString password_encrypted, QWidget *parent = nullptr);
    int decryptString(const QByteArray& encryptedBytes, QByteArray& decryptedBytes);
    ~ListItem();

private slots:
    void on_pushButton_clicked(bool checked);
    void getData(QString pin);


private:
    Ui::ListItem *ui;
    char* pass_encr;
    char* log_encr;
    ModalWindow EnterPassword;
};

#endif // LISTITEM_H
