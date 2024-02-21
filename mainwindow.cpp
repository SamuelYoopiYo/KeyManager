#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "listitem.h"

#include <openssl/evp.h>


#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QPixmap>
#include <QLineEdit>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    qDebug() << "***reading JSON->" << readJSON();
    for (int i = 0; i != jsonArr.size(); ++i)
    {
        QJsonObject jsonItem = jsonArr[i].toObject();

        QListWidgetItem *newItem = new QListWidgetItem();
        ListItem *itemWidget = new ListItem(jsonItem["site"].toString());

        ui->listWidget->addItem(newItem);
        ui->listWidget->setItemWidget(newItem, itemWidget);

        newItem->setSizeHint(itemWidget->sizeHint());
    }

    QObject::connect(ui->lineEdit, &QLineEdit::textEdited, this, &MainWindow::filterListWidget);
}

MainWindow::~MainWindow()
{
    delete ui;
}

bool MainWindow::readJSON()
{
    QFile jsonFile("/home/ezhik/pars/json/cridentials_encrypted.txt");
    if(!jsonFile.open(QIODevice::ReadOnly)) return false;


    QByteArray hexEncryptedBytes = jsonFile.readAll();
    qDebug() << "***hexEncryptedBytes" << hexEncryptedBytes;
    QByteArray encryptedBytes = QByteArray::fromHex(hexEncryptedBytes);
    qDebug() << "***encryptedBytes" << encryptedBytes;
    QByteArray decryptedBytes;
    qDebug() << "***decryptedBytes" << decryptedBytes;
    int ret_code = decryptFile(encryptedBytes, decryptedBytes);


//    QJsonDocument jsonDoc = QJsonDocument::fromJson(decryptedBytes);

//    QJsonObject jsonObj = jsonDoc.object();

//    jsonArr = jsonObj["cridentials"].toArray();

    jsonFile.close();
    return true;
}

void MainWindow::filterListWidget(const QString &searchStrings)
{
    ui->listWidget->clear();

    for (int i = 0; i != jsonArr.size(); ++i)

    {
        QJsonObject jsonItem = jsonArr[i].toObject();

        if ((searchStrings == "") || jsonItem["site"].toString().toLower().contains(searchStrings.toLower()))
        {
            QListWidgetItem *newItem = new QListWidgetItem();
            ListItem *itemWidget = new ListItem(jsonItem["site"].toString());

            ui->listWidget->addItem(newItem);
            ui->listWidget->setItemWidget(newItem, itemWidget);

            newItem->setSizeHint(itemWidget->sizeHint());
        }
    }
}

int MainWindow::decryptFile(const QByteArray& encryptedBytes, QByteArray& decryptedBytes)
{
    unsigned char outbuf[1024];
    /*
     * Bogus key and IV: we'd normally set these from
     * another source.
     */

    QByteArray key_hex("4817ddb54d7a527a5cb1e069434fdfb5350bfdc910cc6a3aa35b54a4036b9809");
    QByteArray key_ba = QByteArray::fromHex(key_hex);
    qDebug() << "***key_ba " << key_ba;
    unsigned char key[32] = {0};
    memcpy(key, key_ba.data(), 32);
    qDebug() << "key " << key;

    QByteArray iv_hex("000102030405060708090a0b0c0d0e0f");
    QByteArray iv_ba = QByteArray::fromHex(iv_hex);
    qDebug() << "***iv_ba " << iv_ba;
    unsigned char iv[16] = {0};
    memcpy(key, key_ba.data(), 16);
    qDebug() << "iv " << key;

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex2(ctx, EVP_aes_256_cbc(), key, iv, NULL)) {
        qDebug() << "Error";
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    qDebug() << "NoError";

    #define BUF_LEN 256
    unsigned char encrypted_buf[BUF_LEN] = {0}, decrypted_buf[BUF_LEN] = {0};
    int encr_len, decr_len;

    QDataStream encrypted_stream(encryptedBytes);
    QDataStream decrypted_stream(&decryptedBytes, QIODevice::ReadWrite);


    encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
    while(encr_len > 0)
    {
        encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
        if (!EVP_EncryptUpdate(ctx, decrypted_buf, &decr_len, encrypted_buf, encr_len)) {
            /* Error */
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }

        qDebug() << "***EVP_EncryptUpdate " << reinterpret_cast<char*>(decrypted_buf);
        decrypted_stream << QByteArray(reinterpret_cast<char*>(decrypted_buf), decr_len);
        encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
    }

    int tmplen;
    if (!EVP_DecryptFinal_ex(ctx, decrypted_buf + decr_len, &tmplen)) {
          /* Error */
          EVP_CIPHER_CTX_free(ctx);
          return 0;
      }
      EVP_CIPHER_CTX_free(ctx);

    return 0;
}

//IV: 000102030405060708090a0b0c0d0e0f

//password = 4505

//key = sha256(password) = 4817ddb54d7a527a5cb1e069434fdfb5350bfdc910cc6a3aa35b54a4036b9809
