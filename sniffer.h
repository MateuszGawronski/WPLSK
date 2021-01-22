#ifndef SNIFFER_H
#define SNIFFER_H

#include <QThread>
#include "packets.h"

class Sniffer : public QThread{
public:
    Sniffer(QStandardItemModel *packetmodel,std::string device_string);
    ~Sniffer();
    void                Stop();
    void                Fill_Data(QPlainTextEdit *text, int index, int size);
    void                Fill_Details(QStandardItemModel *packetdetails, int index);
    void				Find_Packets(QString text, u_short find_option);
    int                 Find_Vec_Size();
    void                Fill_Find_Info_v4(QStandardItemModel *packetmodel);
    void                Fill_Find_Info_v6(QStandardItemModel *packetmodel);
    void                Fill_Find_Data(QPlainTextEdit *text, int index, int size);
    void                Fill_Find_Details(QStandardItemModel *packetdetails,int index);

private:
    void                run();
    std::string 		device;
    bool                stop;
    int                 packetnum;
    in_addr             find_info;
    bpf_u_int32 		mask;
    bpf_u_int32 		net;
    QStandardItemModel  *packetmodel;
    struct iphdr 		*iph;
    QString				find;
    QHash<QString, QColor> protocolColors;
    std::vector<unsigned char *> data;
    std::vector<unsigned char *> data_found;

#define ARP_Color QColor(255, 100, 100)
#define UDP_Color QColor(255, 150, 255)
#define TCP_Color QColor(150, 255, 255)
#define ICMP_Color QColor(255, 255, 150)
};

#endif // SNIFFER_H
