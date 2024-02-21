#include "listitem.h"
#include "ui_listitem.h"

ListItem::ListItem(QString site, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ListItem)
{
    ui->setupUi(this);

    ui->label_2->setText(site);

    QPixmap pix(":/img/img/keys.png");
    int w = ui->label->width();
    int h = ui->label->height();

    ui->label->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
}

ListItem::~ListItem()
{
    delete ui;
}
