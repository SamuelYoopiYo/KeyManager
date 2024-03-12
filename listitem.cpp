#include "listitem.h"
#include "ui_listitem.h"
#include "mainwindow.h"

#include <openssl/evp.h>

#include <QBuffer>
#include <QCryptographicHash>

ListItem::ListItem(QString site, QString login_encrypted, QString password_encrypted, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ListItem)
{
    this->pass_encr = new char[password_encrypted.length()];
    QByteArray pass_ba = password_encrypted.toUtf8();
    strcpy(pass_encr, pass_ba.data());
    qDebug() << "***pass_encr" << pass_encr;

    this->log_encr = new char[login_encrypted.length()];
    QByteArray log_ba = login_encrypted.toUtf8();
    strcpy(log_encr, log_ba.data());
    qDebug() << "***log_encr" << log_encr;

    ui->setupUi(this);

    ui->label_2->setText(site);
    ui->lineEdit_2->setText("******");
    ui->lineEdit_3->setText("******");

    QPixmap pix(":/img/img/keys.png");
    int w = ui->label->width();
    int h = ui->label->height();

    ui->label->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
}

ListItem::~ListItem()
{
    delete [] pass_encr;
    delete ui;
}



void ListItem::on_pushButton_clicked(bool checked)
{
    if (checked)
    {
//        EnterPassword = new ModalWindow();
//        EnterPassword->setModal(true);
//        QObject::connect(EnterPassword, &ModalWindow::sendData, this, &ListItem::getData);
//        if (EnterPassword->exec() == ModalWindow::Rejected)
//        {

//        }

//        connect(&EnterPassword, SIGNAL(sendData(QString)), SLOT(getData(QString)));
//        QObject::connect(&EnterPassword, &ModalWin dow::sendData, this, &ListItem::getData);
        QString pin = ModalWindow::getPin();
        qDebug() << "***pin " << pin;

        QByteArray hexEncryptedPass(pass_encr);
        QByteArray encryptedPass = QByteArray::fromHex(hexEncryptedPass);
        QByteArray decryptedPass;

        if (decryptString(encryptedPass, decryptedPass) == 0)
        {
            QString password(decryptedPass);
            ui->lineEdit_2->setText(password);
        }

        else
        {
            ui->lineEdit_2->setText("Eror");
        }

        QByteArray hexEncryptedLog(log_encr);
        QByteArray encryptedLog = QByteArray::fromHex(hexEncryptedLog);
        QByteArray decryptedLog;

        if (decryptString(encryptedLog, decryptedLog) == 0)
        {
            QString login(decryptedLog);
            ui->lineEdit_3->setText(login);
        }

        else
        {
            ui->lineEdit_3->setText("Eror");
        }

    }

    else
    {
        ui->lineEdit_2->setText("******");
        ui->lineEdit_3->setText("******");
    }

}

int ListItem::decryptString(const QByteArray &encryptedBytes, QByteArray &decryptedBytes)
{

    QByteArray key_hex("060e33205a731400c2eb92bc12cf921a4e44cf1851d216f144337dd6ec5350a7");
    QByteArray key_ba = QByteArray::fromHex(key_hex);
    qDebug() << "***key_ba " << key_ba;
    unsigned char key[32] = {0};
    memcpy(key, key_ba.data(), 32);
    qDebug() << "key " << key;

    QByteArray iv_hex("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
    QByteArray iv_ba = QByteArray::fromHex(iv_hex);
//    qDebug() << "***iv_ba " << iv_ba;
    unsigned char iv[16] = {0};
    memcpy(iv, iv_ba.data(), 16);
//    qDebug() << "iv " << iv;

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex2(ctx, EVP_aes_256_cbc(), key, iv, NULL)) {
        qDebug() << "Error";
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    qDebug() << "NoError";

    #define BUF_LEN 256
    unsigned char encrypted_buf[BUF_LEN] = {0}, decrypted_buf[BUF_LEN] = {0};
    int encr_len, decr_len;

    QDataStream encrypted_stream(encryptedBytes);

    decryptedBytes.clear();
    QBuffer decryptedBuffer(&decryptedBytes);
    decryptedBuffer.open(QIODevice::ReadWrite);
//    QDataStream decrypted_stream(&buffer);


    encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
    while(encr_len > 0){
//        encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
        qDebug() << "***encr_len " << encr_len;
        if (!EVP_DecryptUpdate(ctx, decrypted_buf, &decr_len, encrypted_buf, encr_len)) {
            /* Error */
            qDebug() << "Error";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        decryptedBuffer.write(reinterpret_cast<char*>(decrypted_buf), decr_len);
        encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
        qDebug() << "***EVP_EncryptUpdate " << reinterpret_cast<char*>(decrypted_buf);
    }

    int tmplen;
    if (!EVP_DecryptFinal_ex(ctx, decrypted_buf, &tmplen)) {
          /* Error */
          EVP_CIPHER_CTX_free(ctx);
          return -1;
      }
      qDebug() << "***EVP_DecryptFinal_ex " << reinterpret_cast<char*>(decrypted_buf);
      decryptedBuffer.write(reinterpret_cast<char*>(decrypted_buf), tmplen);
      EVP_CIPHER_CTX_free(ctx);

    decryptedBuffer.close();
    return 0;
}

void ListItem::getData(QString pin)
{
    qDebug() << "***key22" << pin;
}
