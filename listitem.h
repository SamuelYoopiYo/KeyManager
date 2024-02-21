#ifndef LISTITEM_H
#define LISTITEM_H

#include <QWidget>

namespace Ui {
class ListItem;
}

class ListItem : public QWidget
{
    Q_OBJECT

public:
    explicit ListItem(QString site, QWidget *parent = nullptr);
    ~ListItem();

private:
    Ui::ListItem *ui;
};

#endif // LISTITEM_H
