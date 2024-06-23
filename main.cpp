#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}

//QByteArray passHex = "060e33205a731400c2eb92bc12cf921a4e44cf1851d216f144337dd6ec5350a7";
//QByteArray pass = QByteArray::fromHex(passHex);
//unsigned char key[32] = {0};
//memcpy(key, pass.data(), 32);
//qDebug() << key;

//QByteArray nonceHex = "00000000a723ac65c7730000";
//QByteArray nonceBA = QByteArray::fromHex(nonceHex);
//unsigned char nonce[12] = {0};
//memcpy(nonce, nonceBA.data(), 12);
//qDebug() << nonce;
