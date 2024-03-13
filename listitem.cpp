#include "listitem.h"
#include "ui_listitem.h"
#include "mainwindow.h"

#include <openssl/evp.h>

#include <QBuffer>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonDocument>
#include <QClipboard>
#include <QMessageBox>

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

    ui->url->setText(site);
    ui->loginLineEdit->setText("******");
    ui->passwordLineEdit->setText("******");

    QPixmap pix(":/img/img/keys.png");
    int w = ui->icon->width();
    int h = ui->icon->height();

    ui->icon->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
}

bool ListItem::checkJSON(unsigned char *key)
{
    QFile jsonFile("/home/ezhik/pars/json/cridentials_encrypted.json");
    if(!jsonFile.open(QIODevice::ReadOnly)) return false;

    QByteArray hexEncryptedBytes = jsonFile.readAll();
//    qDebug() << "***hexEncryptedBytes" << hexEncryptedBytes;
    QByteArray encryptedBytes = QByteArray::fromHex(hexEncryptedBytes);
//    qDebug() << "***encryptedBytes" << encryptedBytes;
    QByteArray decryptedBytes;
//    qDebug() << "***decryptedBytes" << decryptedBytes;
    int ret_code = decryptFile(encryptedBytes, decryptedBytes, key);

//    qDebug() << "***decryptedBytes " << decryptedBytes;


    QJsonDocument jsonDoc = QJsonDocument::fromJson(decryptedBytes);
//    qDebug() << "***jsonDoc " << jsonDoc;

    if (!jsonDoc.isObject())
    {
        return 1;
    }

    jsonFile.close();
    return ret_code;
}

ListItem::~ListItem()
{
    delete [] pass_encr;
    delete ui;
}





int ListItem::decryptString(const QByteArray &encryptedBytes, QByteArray &decryptedBytes, unsigned char *key)
{

//    QByteArray key_hex("060e33205a731400c2eb92bc12cf921a4e44cf1851d216f144337dd6ec5350a7");
//    QByteArray key_ba = QByteArray::fromHex(key_hex);
//    qDebug() << "***key_ba " << key_ba;
//    unsigned char key[32] = {0};
//    memcpy(key, key_ba.data(), 32);
//    qDebug() << "key " << key;

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

int ListItem::decryptFile(const QByteArray& encryptedBytes, QByteArray& decryptedBytes, unsigned char *key)
{

//    QByteArray key_hex("060e33205a731400c2eb92bc12cf921a4e44cf1851d216f144337dd6ec5350a7");
//    QByteArray key_ba = QByteArray::fromHex(key_hex);
//    qDebug() << "***key_ba " << key_ba;
//    unsigned char key[32] = {0};
//    memcpy(key, key_ba.data(), 32);
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
          return 1;
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

void ListItem::on_loginCopyPushButton_clicked()
{
    QString pin = ModalWindow::getPin();

    QByteArray hash = QCryptographicHash::hash(pin.toUtf8(), QCryptographicHash::Sha256);

    qDebug() << "***Hash -> " << hash;


    unsigned char hash_key[32] = {0};
    memcpy(hash_key, hash.data(), 32);
    qDebug() << "***hash_key -> " << hash_key;

    if (checkJSON(hash_key) == 0)
    {
        QByteArray hexEncryptedLog(log_encr);
        QByteArray encryptedLog = QByteArray::fromHex(hexEncryptedLog);
        QByteArray decryptedLog;

        if (decryptString(encryptedLog, decryptedLog, hash_key) == 0)
        {
            QString login(decryptedLog);
            QClipboard *clipboard = QGuiApplication::clipboard();
            clipboard->setText(login);
            QMessageBox::about(this, " ", "ЛОГИН СКОПИРОВАН В БУФЕР ОБМЕНА");
        }

        else
        {
            ui->loginLineEdit->setText("Eror");
        }

    }

    else if (pin != "")
    {
        QMessageBox::critical(this, " ", "НЕВЕРНЫЙ ПИН");
    }


}


void ListItem::on_passwordCopyPushButton_clicked()
{
    QString pin = ModalWindow::getPin();

    QByteArray hash = QCryptographicHash::hash(pin.toUtf8(), QCryptographicHash::Sha256);

    qDebug() << "***Hash -> " << hash;


    unsigned char hash_key[32] = {0};
    memcpy(hash_key, hash.data(), 32);
    qDebug() << "***hash_key -> " << hash_key;

    if (checkJSON(hash_key) == 0)
    {
        QByteArray hexEncryptedPass(pass_encr);
        QByteArray encryptedPass = QByteArray::fromHex(hexEncryptedPass);
        QByteArray decryptedPass;

        if (decryptString(encryptedPass, decryptedPass, hash_key) == 0)
        {
            QString password(decryptedPass);
            QClipboard *clipboard = QGuiApplication::clipboard();
            clipboard->setText(password);
            QMessageBox::about(this, " ", "ПАРОЛЬ СКОПИРОВАН В БУФЕР ОБМЕНА");
        }

        else
        {
            ui->passwordLineEdit->setText("Eror");
        }

        return;

    }

    else if (pin != "")
    {
        QMessageBox::critical(this, " ", "НЕВЕРНЫЙ ПИН");
    }
}

