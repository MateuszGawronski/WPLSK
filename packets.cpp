#include "packets.h"


void Packet(const struct pcap_pkthdr *header, const u_char *packet, QList<QStandardItem *> *row)
{
    const struct ethernet *ethernet;
    row->append(new QStandardItem(QString(ctime((const time_t *)&header->ts.tv_sec))));
    ethernet = (struct ethernet*)(packet);
    switch(ntohs(ethernet->ether_type)){
    case IPV4:
        Packet_IPv4((packet+SIZE_ETHERNET),row);
        break;
    case ARP:
        Packet_ARP(packet+SIZE_ETHERNET,row);
        break;
    case IPV6:
        Packet_IPv6(packet+SIZE_ETHERNET,row);
        break;
    case 0 ... IEEE802_3_LENGTH:
        Packet_LLC(packet+SIZE_ETHERNET,row);
        break;
    default:
        while(row->size() < 7){
            row->append(new QStandardItem("Niezdefiniowane"));
        }
    }
    row->insert(5,new QStandardItem(QString::number(header->caplen)));
}
void Packet_IPv4(const u_char *packet,QList<QStandardItem *> *row){
    const struct ipv4 *ip;
    int size_ip;
    ip = (struct ipv4*)packet;
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
     printf("   * błąd długości nagłówka IP: %u bajtów\n", size_ip);
     return;
    }
    row->append(new QStandardItem(QString(inet_ntoa(ip->ip_src))));
    row->append(new QStandardItem(QString(inet_ntoa(ip->ip_dst))));

    switch(ip->ip_p) {
    case IPPROTO_TCP:
        Packet_TCP((packet+size_ip),row);
        break;
    case IPPROTO_UDP:
        Packet_UDP((packet+size_ip),row);
        break;
    case IPPROTO_ICMP:
        Packet_ICMP((packet+size_ip),row, false);
        break;
    default:
        row->append(new QStandardItem("Niezdefiniowany"));
    }
}
void Packet_IPv6(const u_char *packet,QList<QStandardItem *> *row){
    const struct ipv6 *ip;
    ip = (struct ipv6 *)packet;

    char buffer[INET6_ADDRSTRLEN];
    row->append(new QStandardItem(QString(inet_ntop(AF_INET6, ip->ip6_src, buffer, sizeof(buffer)))));
    row->append(new QStandardItem(QString(inet_ntop(AF_INET6, ip->ip6_dst, buffer, sizeof(buffer)))));

    switch(ip->ip6_nh) {
    case IPPROTO_TCP:
        Packet_TCP((packet+IPV6_HEADER_LENGTH),row);
        break;
    case IPPROTO_UDP:
        Packet_UDP((packet+IPV6_HEADER_LENGTH),row);
        break;
    case IPPROTO_ICMP_IPV6:
        Packet_ICMP((packet+IPV6_HEADER_LENGTH),row, true);
        break;
    default:
        row->append(new QStandardItem("Niezdefiniowany"));
    }
}
void Packet_ARP(const u_char *packet,QList<QStandardItem *> *row){
    const struct arp *arp;
    arp = (struct arp *)packet;
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &arp->arp_sip, buffer, INET_ADDRSTRLEN);
    row->append(new QStandardItem(buffer));
    inet_ntop(AF_INET, &arp->arp_tip, buffer, INET_ADDRSTRLEN);
    row->append(new QStandardItem(QString(buffer)));
    row->append(new QStandardItem(QString("ARP")));

    QString info;
    switch(ntohs(arp->arp_opcode)){
    case ARP_REQ:
        info.append(QString("Kto ma "));
        inet_ntop(AF_INET, &arp->arp_tip, buffer, INET_ADDRSTRLEN);
        info.append(buffer);
        info.append(QString("? Przekaż "));
        inet_ntop(AF_INET, &arp->arp_sip, buffer, INET_ADDRSTRLEN);
        info.append(buffer);
        break;
    case ARP_REP:
        inet_ntop(AF_INET, &arp->arp_tip, buffer, INET_ADDRSTRLEN);
        info.append(buffer);
        info.append(QString(" jest pod "));
        char tmp[4];
        for(int i=0;i<6;i++){
            snprintf(tmp,sizeof(tmp),((i==5)?"%02x":"%02x:"),*(arp->arp_tp+i));
            info.append(tmp);
        }
        break;
    default:
        info.append(QString("Niezdefiniowany"));
    }
    row->append(new QStandardItem(QString(info)));
}
void Packet_LLC(const u_char *packet,QList<QStandardItem *> *row){
    const struct llc *llc;
    llc = (struct llc *)packet;

    char tmp5[5];
    snprintf(tmp5,sizeof(tmp5),"0x%02x",llc->llc_dsap);
    row->append(new QStandardItem(tmp5));
    snprintf(tmp5,sizeof(tmp5),"0x%02x",llc->llc_ssap);
    row->append(new QStandardItem(tmp5));

    row->append(new QStandardItem(QString("LLC")));

    QString info;

    switch(llc->llc_cf){
    case LLCPROTO_XID ... (LLCPROTO_XID+1):
        info.append(QString("XID"));
        break;
    default:
        info.append(QString("Niezdefiniowane"));
    }

    row->append(new QStandardItem(QString(info)));
}
void Packet_TCP(const u_char *packet,QList<QStandardItem *> *row){
    const struct tcp *tcp;
    tcp = (struct tcp *)packet;
    row->append(new QStandardItem(QString("TCP")));

    QString info;
    info.append(QString::number(ntohs(tcp->th_sport)));
    info.append(QString(" do "));
    info.append(QString::number(ntohs(tcp->th_dport)));
    info.append(" [ ");
    if((tcp->th_flags&TH_FIN)==TH_FIN)info.append("FIN ");
    if((tcp->th_flags&TH_SYN)==TH_SYN)info.append("SYN ");
    if((tcp->th_flags&TH_RST)==TH_RST)info.append("RST ");
    if((tcp->th_flags&TH_PUSH)==TH_PUSH)info.append("PUSH ");
    if((tcp->th_flags&TH_ACK)==TH_ACK)info.append("ACK ");
    if((tcp->th_flags&TH_URG)==TH_URG)info.append("URG ");
    if((tcp->th_flags&TH_ECE)==TH_ECE)info.append("ECE ");
    if((tcp->th_flags&TH_CWR)==TH_CWR)info.append("CWR ");
    if((tcp->th_flags&TH_NS)==TH_NS)info.append("NS ");
    info.append("] Seq=");
    info.append(QString::number(ntohl(tcp->th_seq)));
    info.append(" Ack=");
    info.append(QString::number(ntohl(tcp->th_ack)));
    info.append(" Win=");
    info.append(QString::number(ntohs(tcp->th_win)));

    row->append(new QStandardItem(info));
}
void Packet_UDP(const u_char *packet,QList<QStandardItem *> *row){
    const struct udp *udp;
    udp = (struct udp *)packet;
    row->append(new QStandardItem(QString("UDP")));

    QString info;
    info.append(QString::number(ntohs(udp->udp_sp)));
    info.append(QString(" do "));
    info.append(QString::number(ntohs(udp->udp_dp)));
    info.append(QString(" długość="));
    info.append(QString::number(ntohs(udp->udp_l)));
    row->append(new QStandardItem(info));

}
void Packet_ICMP(const u_char *packet,QList<QStandardItem *> *row, bool ipv6_flag){
    const struct icmp *icmp;
    icmp = (struct icmp *)packet;
    if(!ipv6_flag){
        row->append(new QStandardItem(QString("ICMP")));
        switch(icmp->icmp_t){
        case ICMP_REPLY:
            row->append(new QStandardItem(QString("(Echo (ping) odpowiedź)")));
            break;
        case ICMP_DU:
            row->append(new QStandardItem(QString("(Nieosiągalność miejsca przeznaczenia)")));
            break;
        case ICMP_REQUEST:
            row->append(new QStandardItem(QString("(Echo (ping) zapytanie)")));
            break;
        }
    }else{
        row->append(new QStandardItem(QString("ICMP")));
        switch(icmp->icmp_t){
        case ICMPv6_REPLY:
            row->append(new QStandardItem(QString("(Echo (ping) odpowiedź)")));
            break;
        case ICMPv6_REQUEST:
            row->append(new QStandardItem(QString("(Echo (ping) zapytanie)")));
            break;
        case ICMPv6_NA:
            row->append(new QStandardItem(QString("(Ogłoszenie adresu)")));
            break;
        }
    }
}

void Packet_Details(const u_char *packet, QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Ethernet II"));
    details->appendRow(root);

    const struct ethernet *ethernet;
    ethernet = (struct ethernet*)(packet);

    int i;
    QString dh("Adres Docelowy:  "),
            sh("Adres Źródłowy:  "),
            pro("Typ Ethernetu/Długość:  ");
    char tmp[4];
    for(i=0;i<6;i++){
        snprintf(tmp,sizeof(tmp),((i==5)?"%02x":"%02x:"),*(ethernet->ether_dmac+i));
        dh.append(tmp);
        snprintf(tmp,sizeof(tmp),((i==5)?"%02x":"%02x:"),*(ethernet->ether_smac+i));
        sh.append(tmp);
    }

    root->appendRow(new QStandardItem(dh));
    root->appendRow(new QStandardItem(sh));

    switch(ntohs(ethernet->ether_type)){
    case IPV4:
        pro.append(QString("IPV4(0x0800) "));
        IPv4_Details(packet+SIZE_ETHERNET,details);
        break;
    case ARP:
        pro.append(QString("ARP(0x0806)"));
        ARP_Details(packet+SIZE_ETHERNET,details);
        break;
    case IPV6:
        pro.append(QString("IPV6(0x86dd)"));
        IPv6_Details(packet+SIZE_ETHERNET,details);
        break;
    case 0 ... IEEE802_3_LENGTH:
        pro.append("LLC(");
        char tmp7[7];
        snprintf(tmp7,sizeof(tmp7),"0x%04x",ntohs(ethernet->ether_type));
        pro.append(tmp7);
        pro.append(")");
        LLC_Details(packet+SIZE_ETHERNET,details);
        break;
    default:pro.append(QString("inny niż zdefiniowany: "));
        pro.append(QString::number(ntohs(ethernet->ether_type)));
    }
    root->appendRow(new QStandardItem(pro));
}
void IPv4_Details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("IPv4"));
    details->appendRow(root);

    const struct ipv4 *ip;
    ip = (struct ipv4*)packet;
    int size_ip;
    size_ip = IP_HL(ip)*4;

    QString ver("Wersja IP:  "),
            hl("Długość Nagłówka:  "),
            tos("Typ Usługi:  "),
            tl("Całkowita Długość:  "),
            id("Identyfikacja:  "),
            flag("Flagi:  "),
            of("Przesunięcie:  "),
            ttl("Czas Życia Pakietu:  "),
            pro("Protokół:  "),
            hc("Suma kontrolna nagłówka:  "),
            sip("IP Źródłowe:  "),
            dip("IP Docelowe:  ");

    ver.append(QString::number(IP_V(ip)));
    hl.append(QString::number(size_ip));
    hl.append(QString(" bajtów"));
    char tmp5[5],tmp7[7];
    snprintf(tmp5,sizeof(tmp5),"0x%02x",ip->ip_tos);
    tos.append(tmp5);
    tl.append(QString::number(ntohs(ip->ip_len)));
    snprintf(tmp7,sizeof(tmp7),"0x%04x",ntohs(ip->ip_id));
    id.append(tmp7);

    switch(ntohs(ip->ip_off)&0xe000){
    case IP_RF:
        snprintf(tmp5,sizeof(tmp5),"0x%02x",IP_RF>>13);
        flag.append(tmp5);
        flag.append(QString("(Zarezerwowany bit)"));
        break;
    case IP_DF:
        snprintf(tmp5,sizeof(tmp5),"0x%02x",IP_DF>>13);
        flag.append(tmp5);
        flag.append(QString("(Flaga nie fragmentuj)"));
        break;
    case IP_MF:
        snprintf(tmp5,sizeof(tmp5),"0x%02x",IP_MF>>13);
        flag.append(tmp5);
        flag.append(QString("(Flaga więcej fragmentów)"));
        break;
    default:flag.append(QString("0x00"));
    }

    of.append(QString::number(ntohs(ip->ip_off)&IP_OFFMASK));
    ttl.append(QString::number(ip->ip_ttl));

    switch(ip->ip_p) {
    case IPPROTO_TCP:
        pro.append(QString("TCP(6)"));
        TCP_Details((packet+size_ip),details,ntohs(ip->ip_len)-size_ip);
        break;
    case IPPROTO_UDP:
        pro.append(QString("UDP(17)"));
        UDP_Details((packet+size_ip),details,ntohs(ip->ip_len)-size_ip);
        break;
    case IPPROTO_ICMP:
        pro.append(QString("ICMP(1)"));
        ICMP_Details((packet+size_ip),details,ntohs(ip->ip_len)-size_ip, false);
        break;
    case IPPROTO_IGMP:
        pro.append(QString("IGMP(2)"));
        //IGMP_Details((packet+size_ip),details,ntohs(ip->ip_len)-size_ip);
        break;
    default:
        pro.append(QString("Niezdefiniowany "));
        pro.append(QString::number(ip->ip_p));
    }

    snprintf(tmp7,sizeof(tmp7),"0x%04x",ntohs(ip->ip_sum));
    hc.append(tmp7);
    sip.append(QString(inet_ntoa(ip->ip_src)));
    dip.append(QString(inet_ntoa(ip->ip_dst)));

    root->appendRow(new QStandardItem(ver));
    root->appendRow(new QStandardItem(hl));
    root->appendRow(new QStandardItem(tos));
    root->appendRow(new QStandardItem(tl));
    root->appendRow(new QStandardItem(id));
    root->appendRow(new QStandardItem(flag));
    root->appendRow(new QStandardItem(of));
    root->appendRow(new QStandardItem(ttl));
    root->appendRow(new QStandardItem(pro));
    root->appendRow(new QStandardItem(hc));
    root->appendRow(new QStandardItem(sip));
    root->appendRow(new QStandardItem(dip));
}
void IPv6_Details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("IPv6"));
    details->appendRow(root);

    const struct ipv6 *ip;
    ip = (struct ipv6*)packet;

    QString ver("Wersja:  "),
            tc("Klasa ruchu:  "),
            f("Etykieta przepływu:  "),
            pl("Długość Danych:  "),
            nh("Następny Nagłówek:  "),
            hl("Limit Przeskoków:  "),
            sip("IP Źródłowe:  "),
            dip("IP Docelowe:  ");


    ver.append(QString::number(IPV6_VERSION(ntohl(ip->ip6_vtcfl))));
    char tmp5[5],tmp8[8];
    snprintf(tmp5,sizeof(tmp5),"0x%02x",IPV6_TC(ntohl(ip->ip6_vtcfl)));
    tc.append(tmp5);
    snprintf(tmp8,sizeof(tmp8),"0x%05x",IPV6_FL(ntohl(ip->ip6_vtcfl)));
    f.append(tmp8);
    pl.append(QString::number(ntohs(ip->ip6_len)));

    switch(ip->ip6_nh){
    case IPPROTO_TCP:
        nh.append(QString("TCP(6)"));
        TCP_Details((packet+IPV6_HEADER_LENGTH),details,ntohs(ip->ip6_len));
        break;
    case IPPROTO_UDP:
        nh.append(QString("UDP(17)"));
        UDP_Details((packet+IPV6_HEADER_LENGTH),details,ntohs(ip->ip6_len));
        break;
    case IPPROTO_ICMP_IPV6:
        nh.append(QString("ICMP(58)"));
        ICMP_Details((packet+IPV6_HEADER_LENGTH),details,ntohs(ip->ip6_len), true);
        break;
    default:
        nh.append(QString("Niezdefiniowany "));
        nh.append(QString::number(ntohs(ip->ip6_nh)));
    }

    hl.append(QString::number(ip->ip6_hl));
    char buffer[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip->ip6_src, buffer, sizeof(buffer));
    sip.append(QString(buffer));
    inet_ntop(AF_INET6, ip->ip6_dst, buffer, sizeof(buffer));
    dip.append(QString(buffer));

    root->appendRow(new QStandardItem(ver));
    root->appendRow(new QStandardItem(tc));
    root->appendRow(new QStandardItem(f));
    root->appendRow(new QStandardItem(pl));
    root->appendRow(new QStandardItem(nh));
    root->appendRow(new QStandardItem(hl));
    root->appendRow(new QStandardItem(sip));
    root->appendRow(new QStandardItem(dip));
}
void ARP_Details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Address Resolution Protocol (ARP)"));
    details->appendRow(root);

    const struct arp *arp;
    arp = (struct arp *)packet;

    QString ht("Typ Sprzętu:  "),
            pt("Typ Protokołu:  "),
            hs("Długość Adresu Sprzętowego:  "),
            ps("Długość Protokołu wyższej Warstwy:  "),
            o("Kod Operacji:  "),
            sm("MAC Nadawcy:  "),
            sip("IP Nadawcy:  "),
            tm("Docelowy MAC:  "),
            tip("Docelowe IP:  ");

    if(ntohs(arp->arp_ht)==0x0001)ht.append(QString("Ethernet(1)"));
    else ht.append(QString("Niezdefiniowane"));
    if(ntohs(arp->arp_pt)==IPV4)pt.append(QString("IPV4(0x0800)"));
    else pt.append(QString("Niezdefiniowane"));
    hs.append(QString::number(arp->arp_htlen));
    ps.append(QString::number(arp->ptlen));

    switch(ntohs(arp->arp_opcode)){
    case ARP_REQ:
        o.append(QString("zapytanie(1)"));
        break;
    case ARP_REP:
        o.append(QString("odpowiedź(2)"));
        break;
    default:
        o.append(QString("Niezdefiniowany "));
        o.append(QString::number(ntohs(arp->arp_opcode)));
    }

    int i;
    char tmp[4];
    for(i=0;i<6;i++){
        snprintf(tmp,sizeof(tmp),((i==5)?"%02x":"%02x:"),*(arp->arp_sp+i));
        sm.append(tmp);
    }
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &arp->arp_sip, buffer, INET_ADDRSTRLEN);
    sip.append(buffer);
    for(i=0;i<6;i++){
        snprintf(tmp,sizeof(tmp),((i==5)?"%02x":"%02x:"),*(arp->arp_tp+i));
        tm.append(tmp);
    }
    inet_ntop(AF_INET, &arp->arp_tip, buffer, INET_ADDRSTRLEN);
    tip.append(buffer);

    root->appendRow(new QStandardItem(ht));
    root->appendRow(new QStandardItem(pt));
    root->appendRow(new QStandardItem(hs));
    root->appendRow(new QStandardItem(ps));
    root->appendRow(new QStandardItem(o));
    root->appendRow(new QStandardItem(sm));
    root->appendRow(new QStandardItem(sip));
    root->appendRow(new QStandardItem(tm));
    root->appendRow(new QStandardItem(tip));

}
void LLC_Details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Logical Link Control (LLC)"));
    details->appendRow(root);

    const struct llc *llc;
    llc = (struct llc *)packet;

    QString da("Docelowowy punkt dostępu:  "),
            di("Bit użytkownika:  "),
            dg("Typ adresu:  "),
            sa("Źródłowy punkt dostępu:  "),
            si("Bit użytkownika:  "),
            sr("Komenda/Odpowiedź:  "),
            cf("Pole kontrolujące:  ");


    da.append(QString::number(LLC_ADDR(llc->llc_dsap)));
    di.append(QString::number(LLC_IEEE(llc->llc_dsap)));
    if(LLC_GAR(llc->llc_dsap)) dg.append("1 (adres grupowy)");
    else dg.append("0 (adres indywidualny)");
    sa.append(QString::number(LLC_ADDR(llc->llc_ssap)));
    si.append(QString::number(LLC_IEEE(llc->llc_ssap)));
    sr.append(QString::number(LLC_GAR(llc->llc_ssap)));

    switch(llc->llc_cf){
    case LLCPROTO_XID ... (LLCPROTO_XID+1):
        cf.append(QString("XID("));
        cf.append(QString::number(llc->llc_cf));
        cf.append(")");
        XID_Details(packet+LLC_HEADER_LENGTH, details);
        break;
    default:
        cf.append(QString("Niezdefiniowany "));
        cf.append(QString::number(llc->llc_cf));
    }

    root->appendRow(new QStandardItem(da));
    root->appendRow(new QStandardItem(di));
    root->appendRow(new QStandardItem(dg));
    root->appendRow(new QStandardItem(sa));
    root->appendRow(new QStandardItem(si));
    root->appendRow(new QStandardItem(sr));
    root->appendRow(new QStandardItem(cf));

}
void XID_Details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Exchange Identification (XID)"));
    details->appendRow(root);

    const struct llc_xid *llc_xid;
    llc_xid = (struct llc_xid *)packet;

    QString id("Identyfikator ramki XID:  "),
            tc("Typ/Klasa:  "),
            ws("Rozmiar okna:  ");

    if(llc_xid->xid_id == LLC_IBF)id.append("0x81");
    else{
        char tmp5[5];
        snprintf(tmp5,sizeof(tmp5),"0x%02x",llc_xid->xid_id);
        id.append(tmp5);
    }

    switch(llc_xid->xid_tc){
    case 7:
        tc.append("Typ 1, 2 oraz 3 LLC (Klasa IV LLC)");
        break;
    case 6:
        tc.append("Typ 2 oraz 3 LLC");
        break;
    case 5:
        tc.append("Typ 1 oraz 3 LLC (Klasa III LLC)");
        break;
    case 4:
        tc.append("Typ 3 LLC");
        break;
    case 3:
        tc.append("Typ 1 oraz 2 LLC (Klasa II LLC)");
        break;
    case 2:
        tc.append("Typ 2 LLC");
        break;
    case 1:
        tc.append("Typ 1 LLC (Klasa I LLC)");
        break;
    default:
        tc.append("Niezdefiniowany ");
        tc.append(QString::number(llc_xid->xid_tc));
    }

    ws.append(QString::number((llc_xid->xid_ws) >> 1));

    root->appendRow(new QStandardItem(id));
    root->appendRow(new QStandardItem(tc));
    root->appendRow(new QStandardItem(ws));
}
void TCP_Details(const u_char *packet,QStandardItemModel *details,int size){
    QStandardItem *root = new QStandardItem(QString("Transmission Control Protocol (TCP)"));
    details->appendRow(root);

    const struct tcp *tcp;
    tcp = (struct tcp *)packet;
    int size_tcp = TH_OFF(tcp)*4;

    QString sp("Port źródłowy:  "),
            dp("Port docelowy:  "),
            sn("Numer sekwencyjny:  "),
            an("Numer potwierdzenia:  "),
            hl("Długość nagłówka:  "),
            flag("Flagi:  "),
            ws("Szerokość okna:  "),
            cs("Suma kontrolna:  "),
            up("Wskaźnik priorytetu:  ");
    sp.append(QString::number(ntohs(tcp->th_sport)));
    dp.append(QString::number(ntohs(tcp->th_dport)));
    sn.append(QString::number(ntohl(tcp->th_seq)));
    an.append(QString::number(ntohl(tcp->th_ack)));
    hl.append(QString::number(size_tcp));
    hl.append(QString("(bajty)"));

    char tmp5[5],tmp7[7];
    snprintf(tmp5,sizeof(tmp5),"0x%02x",tcp->th_flags);
    flag.append(tmp5);
    flag.append('(');
    if((tcp->th_flags&TH_FIN)==TH_FIN)flag.append("FIN ");
    if((tcp->th_flags&TH_SYN)==TH_SYN)flag.append("SYN ");
    if((tcp->th_flags&TH_RST)==TH_RST)flag.append("RST ");
    if((tcp->th_flags&TH_PUSH)==TH_PUSH)flag.append("PUSH ");
    if((tcp->th_flags&TH_ACK)==TH_ACK)flag.append("ACK ");
    if((tcp->th_flags&TH_URG)==TH_URG)flag.append("URG ");
    if((tcp->th_flags&TH_ECE)==TH_ECE)flag.append("ECE ");
    if((tcp->th_flags&TH_CWR)==TH_CWR)flag.append("CWR ");
    if((tcp->th_flags&TH_NS)==TH_NS)flag.append("NS ");
    flag.append(')');
    ws.append(QString::number(ntohs(tcp->th_win)));
    snprintf(tmp7,sizeof(tmp7),"0x%04x",ntohs(tcp->th_sum));
    cs.append(tmp7);
    up.append(QString::number(ntohs(tcp->th_urp)));

    root->appendRow(new QStandardItem(sp));
    root->appendRow(new QStandardItem(dp));
    root->appendRow(new QStandardItem(sn));
    root->appendRow(new QStandardItem(an));
    root->appendRow(new QStandardItem(hl));
    root->appendRow(new QStandardItem(flag));
    root->appendRow(new QStandardItem(ws));
    root->appendRow(new QStandardItem(cs));
    root->appendRow(new QStandardItem(up));

    if(size>size_tcp){
        int len = size-size_tcp;
        QString dataroot("Dane (");
        QString data;
        dataroot.append(QString::number(size-size_tcp));
        dataroot.append(" bytes)");
        QStandardItem *datarootitem = new QStandardItem(dataroot);
        details->appendRow(datarootitem);
        char tmp[2];
        const u_char *ch=packet+size_tcp;
        for(int i =0;i<len;i++){
            if(isprint(*ch)){
                snprintf(tmp,sizeof(tmp),"%c",*ch);
                data.append(tmp);
            }
            else
                data.append('.');
            ch++;
        }
        datarootitem->appendRow(new QStandardItem(data));
    }
}
void UDP_Details(const u_char *packet,QStandardItemModel *details,int size){
    QStandardItem *root = new QStandardItem(QString("User Datagram Protocol (UDP)"));
    details->appendRow(root);

    const struct udp *udp;
    udp = (struct udp *)packet;

    QString sp("Port źródłowy:  "),
            dp("Port docelowy:  "),
            len("Długość:  "),
            cs("Suma kontrolna:  ");

    sp.append(QString::number(ntohs(udp->udp_sp)));
    dp.append(QString::number(ntohs(udp->udp_dp)));
    len.append(QString::number(ntohs(udp->udp_l)));
    char tmp7[7];
    snprintf(tmp7,sizeof(tmp7),"0x%04x",ntohs(udp->udp_cs));
    cs.append(tmp7);

    root->appendRow(new QStandardItem(sp));
    root->appendRow(new QStandardItem(dp));
    root->appendRow(new QStandardItem(len));
    root->appendRow(new QStandardItem(cs));

    if(size>8){
        int len = size-8;
        QString dataroot("Dane (");
        QString data;
        dataroot.append(QString::number(len));
        dataroot.append(" bajty)");
        QStandardItem *datarootitem = new QStandardItem(dataroot);
        details->appendRow(datarootitem);
        char tmp[2];
        const u_char *ch=packet+8;
        for(int i =0;i<len;i++){
            if(isprint(*ch)){
                snprintf(tmp,sizeof(tmp),"%c",*ch);
                data.append(tmp);
            }
            else
                data.append('.');
            ch++;
        }
        datarootitem->appendRow(new QStandardItem(data));
    }
}
void ICMP_Details(const u_char *packet, QStandardItemModel *details, int size, bool ipv6_flag){

    QString v("Internet Control Message Protocol ");
    if(!ipv6_flag) v.append("(ICMP)");
    else v.append("version 6 (ICMPv6)");

    QStandardItem *root = new QStandardItem(v);

    details->appendRow(root);

    const struct icmp *icmp;
    icmp = (struct icmp *)packet;
    QString t("Typ:  "),
            c("Kod:  "),
            cs("Suma kontrolna:  "),
            icmp_1(""),
            icmp_2(""),
            icmp_3("");
    t.append(QString::number(icmp->icmp_t));
    if(!ipv6_flag){
        switch(icmp->icmp_t){
        case ICMP_REPLY:
            t.append(" (Echo (ping) odpowiedź)");
            icmp_1.append("Identyfikator: ");
            icmp_1.append(QString::number(ICMP_ID(ntohl(icmp->icmp_rt))));
            icmp_2.append("Sekwencja: ");
            icmp_2.append(QString::number(ICMP_SQ(ntohl(icmp->icmp_rt))));
            break;
        case ICMP_REQUEST:
            t.append(" (Echo (ping) zapytanie)");
            icmp_1.append("Identyfikator: ");
            icmp_1.append(QString::number(ICMP_ID(ntohl(icmp->icmp_rt))));
            icmp_2.append("Sekwencja: ");
            icmp_2.append(QString::number(ICMP_SQ(ntohl(icmp->icmp_rt))));
            break;
        case ICMP_DU:
            t.append(" Nieosiągalność miejsca przeznaczenia");
            icmp_1.append("Długość: ");
            icmp_1.append(QString::number(ICMP_L(ntohl(icmp->icmp_rt))));
            icmp_2.append("MTU następnego skoku: ");
            icmp_2.append(QString::number(ICMP_NH(ntohl(icmp->icmp_rt))));
            break;
        default:
            t.append("Niezdefiniowany ICMP ");
            t.append(icmp->icmp_t);
        }
    }else{
        switch(icmp->icmp_t){
        case ICMPv6_REPLY:
            t.append(" (Echo (ping) odpowiedź)");
            icmp_1.append("Identyfikator: ");
            icmp_1.append(QString::number(ICMP_ID(ntohl(icmp->icmp_rt))));
            icmp_2.append("Sekwencja: ");
            icmp_2.append(QString::number(ICMP_SQ(ntohl(icmp->icmp_rt))));
            break;
        case ICMPv6_REQUEST:
            t.append(" (Echo (ping) zapytanie)");
            icmp_1.append("Identyfikator: ");
            icmp_1.append(QString::number(ICMP_ID(ntohl(icmp->icmp_rt))));
            icmp_2.append("Sekwencja: ");
            icmp_2.append(QString::number(ICMP_SQ(ntohl(icmp->icmp_rt))));
            break;
        case ICMPv6_NA:
            t.append(" (Ogłoszenie adresu (NA))");
            icmp_1.append("R: ");
            icmp_1.append(QString::number(ICMPV6_R(ntohl(icmp->icmp_rt))));
            icmp_2.append("S: ");
            icmp_2.append(QString::number(ICMPV6_S(ntohl(icmp->icmp_rt))));
            icmp_3.append("O: ");
            icmp_3.append(QString::number(ICMPV6_O(ntohl(icmp->icmp_rt))));
            break;
            t.append("Niezdefiniowany ICMPv6 ");
            t.append(icmp->icmp_t);
        }
    }
    c.append(QString::number(icmp->icmp_c));
    char tmp7[7];
    snprintf(tmp7,sizeof(tmp7),"0x%04x",ntohs(icmp->icmp_cs));
    cs.append(tmp7);

    root->appendRow(new QStandardItem(t));
    root->appendRow(new QStandardItem(c));
    root->appendRow(new QStandardItem(cs));
    if(!icmp_1.isEmpty())root->appendRow(new QStandardItem(icmp_1));
    if(!icmp_2.isEmpty())root->appendRow(new QStandardItem(icmp_2));
    if(!icmp_3.isEmpty())root->appendRow(new QStandardItem(icmp_3));

    if(size>8){
        int len = size-8;
        QString dataroot("Dane (");
        QString data;
        dataroot.append(QString::number(len));
        dataroot.append(" bajty)");
        QStandardItem *datarootitem = new QStandardItem(dataroot);
        details->appendRow(datarootitem);
        char tmp[2];
        const u_char *ch=packet+8;
        for(int i =0;i<len;i++){
            if(isprint(*ch)){
                snprintf(tmp,sizeof(tmp),"%c",*ch);
                data.append(tmp);
            }
            else
                data.append('.');
            ch++;
        }
        datarootitem->appendRow(new QStandardItem(data));
    }
}
