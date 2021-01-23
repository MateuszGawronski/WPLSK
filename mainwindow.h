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
    void on_btn_run_clicked();                                          /* pobiera z rozwijanej listy interfejs sieciowy a następnie tworzy nowy obiekt sniffer, który zostaje uruchomiony */

    void on_btn_stop_clicked();                                         /* zatrzymuje proces sniffera */

    void on_packetTableView_doubleClicked(const QModelIndex &index);    /* zależnie od stanu wywołuje funkcje Fill_Data oraz Fill_Details lub Fill_Find_Data oraz Fill_Find_Details */

    void on_btn_clear_clicked();                                        /* czyści listę pakietów i usuwa proces snifera */

    void on_btn_rtn_clicked();                                          /* przywraca pierwotną listę pakietów przed operacją wyszukiwania pakietów */

    void on_btn_find_clicked();                                         /* wyświetla okno z polem tekstowym do wprowadzenia wyszukiwanego ciągu, zmienia wartość zmiennej state, wywołuje funkcję Find_Packets(QString text, u_short find_option); */

    void on_btn_aboutQt_clicked();                                      /* wyświetla informacje odnośnie Qt */

private:
    Ui::MainWindow          *ui;                                        /* wskaźnik na główne okno programu */
    Devices                 *device_list;                               /* wskaźnik na listę interfejsów sieciowych */
    QStringListModel        *model_dev;                                 /* wskaźnik na listę rozwijaną, odpowiadającą za wybór interfejsu sieciowego */
    Sniffer                 *sniffer;                                   /* wskaźnik na obiekt sniffer, odpowiadający za przechwytywanie, dodawanie pakietów do listy oraz wyświetlanie informacji o pakietach */
    char                    *device;                                    /* wskaźnik na obecnie wybrany interfejs sieciowy w liście rozwijanej */
    QStandardItemModel      *packetModel;                               /* wskaźnik na tablicę przechowująca pakiety */
    QStandardItemModel      *packetdetails;                             /* wskaźnik na tablicę przechowująca informacje o danym pakiecie */
    QStandardItemModel      *findModel;                                 /* wskaźnik na tablicę przechowująca wyszukane pakiety */
    int                     state;                                      /* zmienna przechowująca stan tablic, czy tablice wyświetlają wszystkie pakiety czy tylko wyszukane funkcję Find_Packets(QString text, u_short find_option); */
    u_short                 find_option;                                /* zmienna sterująca przekazywana do funkcji Find_Packets(QString text, u_short find_option); */
    bool                    ipv6_flag;                                  /* zmienna służąca do wykrywania czy wyszukiwany pakiet jest w formacie ipv4 czy ipv6 */
};

#endif // MAINWINDOW_H
