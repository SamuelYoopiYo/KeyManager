#include "listitem.h"
#include "ui_listitem.h"
#include "mainwindow.h"

ListItem::ListItem(QString site, QString login_encrypted, QString password_encrypted, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ListItem)
{
    this->pass_encr = password_encrypted;
    this->log_encr = login_encrypted;

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
    delete ui;
}

void ListItem::on_lineEdit_2_selectionChanged()
{
    ui->lineEdit_2->setText("encrypted");
}

void ListItem::on_lineEdit_2_editingFinished()
{
    ui->lineEdit_2->setText("******");
}

