#include "sniffer.h"




Sniffer::Sniffer(QStandardItemModel *packetmodel, std::string device_string){
    this->packetmodel = packetmodel;
    this->device = device_string;

    stop = false;
    packetnum = 0;
}
Sniffer::~Sniffer(){
    for(size_t i=0; i<data.size(); i++){
        free(data.at(i));
    }
    data.clear();
}
void    Sniffer::Stop(void){
    stop = true;
}
void    Sniffer::run(){
    protocolColors.insert("ARP", ARP_Color);
    protocolColors.insert("UDP", UDP_Color);
    protocolColors.insert("TCP", TCP_Color);
    protocolColors.insert("ICMP", ICMP_Color);
    int promiscuous = 0;
    int timeout = 1000;
    int snapshot_len = 66535;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t  *handle;
    pcap_pkthdr *packet_header;
    const u_char *packet;

    handle = pcap_open_live((char *) this->device.c_str(),snapshot_len,promiscuous,timeout,error_buffer);
    if(handle==NULL){
        printf("Blad urzadzenia\n");
        return;
    }

    if (pcap_lookupnet((char *)this->device.c_str(), &this->net, &this->mask, error_buffer) == -1) {
        fprintf(stderr, "Blad maski sieciowej\n");
        net = 0;
        mask = 0;
    }

    int tmp;
    while((tmp=pcap_next_ex(handle,&packet_header,&packet))>=0&&stop==false){
        QList<QStandardItem *>row;
        row.append(new QStandardItem(QString::number(++packetnum)));
        Packet(packet_header,packet,&row);

        while(row.size() < 7){
            row.append(new QStandardItem("Niezdefiniowane"));
        }

        u_char *newData = (u_char *)malloc(packet_header->len);
        if(newData == NULL){
            printf("Blad malloc\n");
            exit(1);
        }
        memcpy(newData, (void*)packet, packet_header->len);
        data.push_back(newData);

        if(protocolColors.contains(row.at(4)->text())){
            for(int i=0;i<7;i++)
            row.at(i)->setData(protocolColors.value(row.at(4)->text()), Qt::BackgroundColorRole);
        }

        packetmodel->appendRow(row);
    }

    stop = false;
    pcap_close(handle);
}
void    Sniffer::Fill_Data(QPlainTextEdit *text,int index,int size){
    text->clear();
    QString add;
    char d[4],o[9];
    int i,j;
    int offset = 0;
    for(i=0;i<size;i+=16){
        snprintf(o,sizeof(o),"%04x    ",offset);
        add.append(o);
        j=0;
        while(j<(((size-i)<16)?(size-i):16)){
            snprintf(d,sizeof(d),"%02x ",data.at(index)[offset+j]);
            add.append(d);
            j++;
        }
        add.append(QString('\n'));
        offset +=16;
    }

    text->appendPlainText(add);
}
void    Sniffer::Fill_Details(QStandardItemModel *packetdetails,int index){
    packetdetails->clear();
    Packet_Details(data.at(index),packetdetails);
}
void    Sniffer::Fill_Find_Info_v4(QStandardItemModel *packetmodel){
    protocolColors.insert("ARP", ARP_Color);
    protocolColors.insert("UDP", UDP_Color);
    protocolColors.insert("TCP", TCP_Color);
    protocolColors.insert("ICMP", ICMP_Color);
    int size = data_found.size();
    int i;
    int num = 0;

    const struct ipv4 *ip;

    for(i=0;i<size;i++){
        QList<QStandardItem *>row;
        row.append(new QStandardItem(QString::number(++num)));
        Packet_IPv4(data_found.at(i)+14,&row);
        while(row.size() < 5){
            row.append(new QStandardItem("Niezdefiniowane"));
        }
        ip = (struct ipv4*)(data_found.at(i)+ SIZE_ETHERNET);
        row.insert(4,new QStandardItem(QString::number(ntohs(ip->ip_len)+14)));
        if(protocolColors.contains(row.at(3)->text())){
            for(int i=0;i<6;i++)
            row.at(i)->setData(protocolColors.value(row.at(3)->text()), Qt::BackgroundColorRole);
        }
        packetmodel->appendRow(row);
    }
}
void    Sniffer::Fill_Find_Info_v6(QStandardItemModel *packetmodel){
    protocolColors.insert("ARP", ARP_Color);
    protocolColors.insert("UDP", UDP_Color);
    protocolColors.insert("TCP", TCP_Color);
    protocolColors.insert("ICMP", ICMP_Color);
    int size = data_found.size();
    int i;
    int num = 0;

    const struct ipv6 *ip;

    for(i=0;i<size;i++){
        QList<QStandardItem *>row;
        row.append(new QStandardItem(QString::number(++num)));
        Packet_IPv6(data_found.at(i)+14,&row);
        while(row.size() < 5){
            row.append(new QStandardItem("Niezdefiniowane"));
        }
        ip = (struct ipv6*)(data_found.at(i)+ SIZE_ETHERNET);
        row.insert(4,new QStandardItem(QString::number(ntohs(ip->ip6_len)+14)));
        if(protocolColors.contains(row.at(3)->text())){
            for(int i=0;i<6;i++)
            row.at(i)->setData(protocolColors.value(row.at(3)->text()), Qt::BackgroundColorRole);
        }
        packetmodel->appendRow(row);
    }
}
void    Sniffer::Fill_Find_Data(QPlainTextEdit *text,int index,int size){
    text->clear();
    QString add;
    char d[4],o[9];
    int i,j;
    int offset = 0;
    for(i=0;i<size;i+=16){
        snprintf(o,sizeof(o),"%04x    ",offset);
        add.append(o);
        j=0;
        while(j<(((size-i)<16)?(size-i):16)){
            snprintf(d,sizeof(d),"%02x ",data_found.at(index)[offset+j]);
            add.append(d);
            j++;
        }
        add.append(QString('\n'));
        offset +=16;
    }

    text->appendPlainText(add);
}
void    Sniffer::Fill_Find_Details(QStandardItemModel *packetdetails,int index){
    packetdetails->clear();
    Packet_Details(data_found.at(index),packetdetails);
}
int     Sniffer::Find_Vec_Size(){
    return data_found.size();
}
