#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QStandardItemModel>
#include <QtWidgets>
#include "devices.h"
#include "sniffer.h"
#include "packets.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_btn_run_clicked();

    void on_btn_stop_clicked();

    void on_packetTableView_doubleClicked(const QModelIndex &index);

    void on_btn_clear_clicked();

    void on_btn_rtn_clicked();

    void on_btn_find_clicked();

    void on_btn_aboutQt_clicked();

private:
    Ui::MainWindow          *ui;
    Devices                 *device_list;
    QStringListModel        *model_dev;
    Sniffer                 *sniffer;
    char                    *device;
    QStandardItemModel      *packetModel;
    QStandardItemModel      *packetdetails;
    QStandardItemModel      *findModel;
    int                     state;
    u_short                 find_option;
    bool                    ipv6_flag;
};

#endif // MAINWINDOW_H
