#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :    
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);


    /* packetinfo window */
    packetModel = new QStandardItemModel(0, 6, this);
    packetModel->setHorizontalHeaderItem(0, new QStandardItem("Nr"));
    packetModel->setHorizontalHeaderItem(1, new QStandardItem("Czas"));
    packetModel->setHorizontalHeaderItem(2, new QStandardItem("Źródło"));
    packetModel->setHorizontalHeaderItem(3, new QStandardItem("Cel"));
    packetModel->setHorizontalHeaderItem(4, new QStandardItem("Protokół"));
    packetModel->setHorizontalHeaderItem(5, new QStandardItem("Długość"));
    packetModel->setHorizontalHeaderItem(6, new QStandardItem("Informacje"));

    ui->packetTableView->setModel(packetModel);

    ui->packetTableView->setColumnWidth(0,40);
    ui->packetTableView->setColumnWidth(1,180);
    ui->packetTableView->setColumnWidth(2,110);
    ui->packetTableView->setColumnWidth(3,110);
    ui->packetTableView->setColumnWidth(4,70);
    ui->packetTableView->setColumnWidth(5,70);
    ui->packetTableView->setColumnWidth(6,450);
    ui->packetTableView->verticalHeader()->setMaximumSectionSize(ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->setDefaultSectionSize(ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->hide();

    ui->packetTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    /* packet details */
    packetdetails = new QStandardItemModel(this);
    ui->packetDetails->setModel(packetdetails);
    ui->packetDetails->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->packetDetails->setHeaderHidden(true);

    ui->packetDataview->setWordWrapMode(QTextOption::NoWrap);

    /* get all devices */
    model_dev = new QStringListModel(this);
    device_list = new Devices();
    device_list->Find_Devices();
    QStringList List;
    for (int i=0; i<device_list->device_count; i++) {
        List << device_list->device_all[i];
    }
    model_dev->setStringList(List);
    ui->comboBox->setModel(model_dev);
    sniffer = NULL;


    state = 1;
    ui->btn_rtn->setEnabled(false);
    ui->btn_clear->setEnabled(false);
    ui->btn_find->setEnabled(false);
    ui->btn_stop->setEnabled(false);
}


MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_btn_run_clicked(){
    QByteArray q = ui->comboBox->currentText().toLatin1();
    device = q.data();
    std::string device_string(device);

    if(sniffer==NULL) sniffer = new Sniffer(packetModel,device_string);
    sniffer->start();
    ui->btn_clear->setEnabled(true);
    ui->btn_find->setEnabled(true);
    ui->btn_stop->setEnabled(true);
    ui->btn_run->setEnabled(false);
    ui->comboBox->setEnabled(false);
}

void MainWindow::on_btn_stop_clicked(){
    sniffer->Stop();
    ui->btn_stop->setEnabled(false);
    ui->btn_run->setEnabled(true);
}

void MainWindow::on_packetTableView_doubleClicked(const QModelIndex &index){
    int dataindex,size;
    switch(state){
    case 1:
        dataindex = packetModel->data(packetModel->index(index.row(), 0)).toInt();
        size = packetModel->data(packetModel->index(index.row(), 5)).toInt();
        sniffer->Fill_Data(ui->packetDataview, dataindex-1, size);
        sniffer->Fill_Details(packetdetails,dataindex-1);
        ui->packetDetails->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
        break;
    case 2:
        dataindex = findModel->data(findModel->index(index.row(), 0)).toInt();
        size = findModel->data(findModel->index(index.row(), 4)).toInt();
        sniffer->Fill_Find_Data(ui->packetDataview, dataindex-1, size);
        sniffer->Fill_Find_Details(packetdetails,dataindex-1);
        ui->packetDetails->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
        break;
    }
}

void MainWindow::on_btn_clear_clicked(){
    sniffer->Stop();
    sniffer = NULL;
    delete sniffer;
    sniffer = NULL;
    delete packetModel;
    packetModel = new QStandardItemModel(0, 6, this);
    packetModel->setHorizontalHeaderItem(0, new QStandardItem("Nr"));
    packetModel->setHorizontalHeaderItem(1, new QStandardItem("Czas"));
    packetModel->setHorizontalHeaderItem(2, new QStandardItem("Źródło"));
    packetModel->setHorizontalHeaderItem(3, new QStandardItem("Cel"));
    packetModel->setHorizontalHeaderItem(4, new QStandardItem("Protokół"));
    packetModel->setHorizontalHeaderItem(5, new QStandardItem("Długość"));
    packetModel->setHorizontalHeaderItem(6, new QStandardItem("Informacje"));

    ui->packetTableView->setModel(packetModel);
    ui->btn_clear->setEnabled(false);
    ui->btn_find->setEnabled(false);
    ui->btn_stop->setEnabled(false);
    ui->btn_run->setEnabled(true);
    ui->comboBox->setEnabled(true);

    if(state == 2) MainWindow::on_btn_rtn_clicked();

    ui->packetDataview->clear();
    packetdetails->clear();

}

void MainWindow::on_btn_rtn_clicked(){
    ui->packetTableView->setModel(packetModel);
    ui->btn_rtn->setEnabled(false);
    ui->packetTableView->setColumnWidth(0,40);
    ui->packetTableView->setColumnWidth(1,180);
    ui->packetTableView->setColumnWidth(2,110);
    ui->packetTableView->setColumnWidth(3,110);
    ui->packetTableView->setColumnWidth(4,70);
    ui->packetTableView->setColumnWidth(5,70);
    ui->packetTableView->setColumnWidth(6,450);

    state = 1;
}

void MainWindow::on_btn_find_clicked(){
    QString text = QInputDialog::getText(this, "Wyszukaj", "Wprowadź szukany IPv6, IPv4 lub protokół IPv4");
    if(text.isEmpty()) return;
    ipv6_flag = false;

    if(text.contains(".",Qt::CaseInsensitive)) find_option = 1;
    else if (text.contains(":",Qt::CaseInsensitive)) {
        find_option = 2;
        ipv6_flag = true;
    }
    else find_option = 3;

    sniffer->Find_Packets(text, find_option);

    findModel = new QStandardItemModel(0, 6, this);
    findModel->setHorizontalHeaderItem(0, new QStandardItem("Nr"));
    findModel->setHorizontalHeaderItem(1, new QStandardItem("Źródło"));
    findModel->setHorizontalHeaderItem(2, new QStandardItem("Cel"));
    findModel->setHorizontalHeaderItem(3, new QStandardItem("Protokół"));
    findModel->setHorizontalHeaderItem(4, new QStandardItem("Długość"));
    findModel->setHorizontalHeaderItem(5, new QStandardItem("Informacje"));

    ui->packetTableView->setModel(findModel);

    ui->packetTableView->setColumnWidth(0,40);
    ui->packetTableView->setColumnWidth(1,120);
    ui->packetTableView->setColumnWidth(2,120);
    ui->packetTableView->setColumnWidth(3,70);
    ui->packetTableView->setColumnWidth(4,100);
    ui->packetTableView->setColumnWidth(5,450);

    ui->packetDataview->clear();
    packetdetails->clear();

    int size = sniffer->Find_Vec_Size();
    if(size<1){
        printf("zero wynikow\n");
    }
    else{
        if(!ipv6_flag) sniffer->Fill_Find_Info_v4(findModel);
        else sniffer->Fill_Find_Info_v6(findModel);
        }
    ui->btn_rtn->setEnabled(true);
    state = 2;

}

void MainWindow::on_btn_aboutQt_clicked(){
    QMessageBox::aboutQt(this,"about Qt");
}
