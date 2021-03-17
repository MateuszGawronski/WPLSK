#ifndef SNIFFER_H
#define SNIFFER_H

#include <QThread>
#include "packets.h"

class Sniffer : public QThread{
public:
    Sniffer(QStandardItemModel *packetmodel,std::string device_string);
    ~Sniffer();
    void                Stop();                                                         /* zatrzymuje pracę sniffera */
    void                Fill_Data(QPlainTextEdit *text, int index, int size);           /* w przypadku podwójnego kliknięcia na pakiet wypełnia okno danych ciągiem szesnastkowym */
    void                Fill_Details(QStandardItemModel *packetdetails, int index);     /* w przypadku podwójnego kliknięcia na pakiet wypełnia okno detali informacjami o pakiecie */
    void				Find_Packets(QString text, u_short find_option);                /* poszukuje pakietów o zadanym IPv4, IPv6 lub protokole dla IPv4 */
    int                 Find_Vec_Size();                                                /* zwraca liczbę znalezionych pakietów */
    void                Fill_Find_Info_v4(QStandardItemModel *packetmodel);             /* wypełnia tabelę znalezionymi pakietami IPv4 */
    void                Fill_Find_Info_v6(QStandardItemModel *packetmodel);             /* wypełnia tabelę znalezionymi pakietami IPv6 */
    void                Fill_Find_Data(QPlainTextEdit *text, int index, int size);      /* w przypadku podwójnego kliknięcia na znaleziony pakiet wypełnia okno danych ciągiem szesnastkowym */
    void                Fill_Find_Details(QStandardItemModel *packetdetails,int index); /* w przypadku podwójnego kliknięcia na znaleziony pakiet wypełnia okno detali informacjami o pakiecie */

private:
    void                run();                  /* funkcja uruchamiająca proces sniffera oraz dodająca przechwycone pakiety do tabeli */
    std::string 		device;                 /* zmienna przechowuje wybrany interfejs sieciowy z którego będzie korzystać sniffer */
    bool                of_flag;                /* flaga sygnalizująca przepełnienie packetnum */
    bool                stop;                   /* zmienna odpowiada za stan pracy sniffera, stop == true zatrzymuje proces sniffera */
    int                 packetnum;              /* zmienna odpowiadająca za numerowanie pakietów */
    in_addr             find_info;              /* zmienna przechowująca wartość adresu nadawcy lub odbiorcy w przypadku wyszukiwania adresu IPv4 */
    bpf_u_int32 		mask;                   /* zmienna przechowująca wartość maski sieciowej */
    bpf_u_int32 		net;                    /* zmienna przechowująca wartość adresu sieci */
    QStandardItemModel  *packetmodel;           /* wskaźnik na tablicę do której mają być dodawane przechwycone pakiety */
    struct iphdr 		*iph;                   /* wskaźnik wykorzystywany przy wyszukiwaniu pakietów */
    QString				find;                   /* zmienna przechowująca szukaną wartość */
    QHash<QString, QColor> protocolColors;      /* zmienna odpowiadająca za możliwość zmiany kolorów  */
    std::vector<unsigned char *> data;          /* wskaźnik na tablicę przechowującą przechwycone pakiety */
    std::vector<unsigned char *> data_found;    /* wskaźnik na tablicę przechowującą wyszukane za pomocą metody Find_Packets pakiety */

/* Definicje kolorów dla protokołów */
#define ARP_Color QColor(255, 150, 150)
#define UDP_Color QColor(230, 200, 240)
#define TCP_Color QColor(154, 220, 255)
#define ICMP_Color QColor(255, 225, 125)
#define LLC_Color QColor(200, 200, 200)
};

#endif // SNIFFER_H
