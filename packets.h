#ifndef PACKETS_H
#define PACKETS_H

#include <pcap.h>
#include <QStandardItem>
#include <QPlainTextEdit>
#include <QDebug>

#include <net/ethernet.h>
#include <netinet/ip.h>

#define     SNAP_LEN        1518 //maksymalny rozmiar pakietów w bajtach
#define     SIZE_ETHERNET   14 // Rozmiar nagłówka Ethernet

// kody EtherType, na podstawie https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml oraz https://tools.ietf.org/html/rfc7042
#define     IPV4        0x0800
#define     ARP         0x0806
#define     IPV6        0x86dd


/* nagłówek Ethernet */
struct ethernet {
    u_char ether_dmac[ETHER_ADDR_LEN];
    u_char ether_smac[ETHER_ADDR_LEN];
    u_short ether_type;
};

/* Nagłówek IP, na podstawie Sieci komputerowe. Wydanie V - Andrew S. Tanenbaum, David J. Wetherall, Rozdział 5.6.1, Protokół IPv4 */
struct ipv4 {
        u_char  ip_vhl;                 /* wersja oraz długość nagłówka */
        u_char  ip_tos;                 /* usługi zróżnicowane / typ usługi */
        u_short ip_len;                 /* długość całkowita */
        u_short ip_id;                  /* identyfikacja */
        //u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* zarezerwowany bit, musi być zero, RFC 3514 evil bit, pakiety o wartości tego bitu równego jeden zawierają złe zamiary */
        #define IP_DF 0x4000            /* flaga nie fragmentuj */
        #define IP_MF 0x2000            /* flaga więcej fragmentów */
        u_short ip_off;                 /* pozycja fragmentu */
        #define IP_OFFMASK 0x1fff       /* maska do przesunięcia */
        u_char  ip_ttl;                 /* czas zycia */
        u_char  ip_p;                   /* protokół */
        u_short ip_sum;                 /* suma kontrolna */
        struct  in_addr ip_src, ip_dst; /* aders źródłowy oraz adres docelowy */
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
};

/* Nagłówek TCP, na podstawie Sieci komputerowe. Wydanie V - Andrew S. Tanenbaum, David J. Wetherall, Rozdział 6.5.4, Nagłówek Segmentu TCP, oraz RFC 7125 */
struct tcp {
        uint16_t    th_sport;               /* port źródłowy */
        uint16_t    th_dport;               /* port docelowy */
        uint32_t    th_seq;                 /* numer sekwencyjny */
        uint32_t    th_ack;                 /* numer potwierdzenia */
        u_char      th_offx2;               /* długość nagłówka */
        #define     TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char      th_flags;
        #define     TH_FIN  0x001
        #define     TH_SYN  0x002
        #define     TH_RST  0x004
        #define     TH_PUSH 0x008
        #define     TH_ACK  0x010
        #define     TH_URG  0x020
        #define     TH_ECE  0x040
        #define     TH_CWR  0x080
        #define     TH_NS   0x100           /* Na podstawie RFC 7125 */
        #define     TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR|TH_NS)
        uint16_t    th_win;                 /* rozmiar okna */
        u_short     th_sum;                 /* suma kontrolna */
        u_short     th_urp;                 /* wskaźnik pilności */
};

/* nagłówek UDP, na podstawie Sieci komputerowe. Wydanie V - Andrew S. Tanenbaum, David J. Wetherall, Rozdział 6.4.1, Wprowadzenie do protokołu UDP */
struct udp
{
    u_short udp_sp;              	/* port źródłowy */
    u_short udp_dp;                	/* port docelowy */
    u_short udp_l;                	/* długość */
    u_short udp_cs;                	/* suma kontrolna */
};

/* nagłówek ICMP,  */
struct icmp
{
    u_char	icmp_t;
#define ICMP_REPLY          0x00
#define ICMP_REPLY_IPV6     0x81
#define ICMP_DU             0x03
#define ICMP_REQUEST        0x08
#define ICMP_REQUEST_IPV6   0x80
    u_char	icmp_c;             /* kod */
    u_short	icmp_cs;            /* suma kontrolna */
    u_short icmp_id;            /* Identyfikator */
    u_short icmp_sq;            /* Sekwencja */

};


/* ARP header */
struct arp
{
    u_short arp_ht,arp_pt;          /*hardware type & protocol type*/
    u_char	arp_htlen,ptlen;        /*hardware length & protocol length*/
    u_short arp_opcode;             /* kod operacji */
#define ARP_REQ 0x0001
#define ARP_REP 0x0002
    u_char	arp_sp[ETHER_ADDR_LEN]; /*source physics*/
    char    arp_sip[4];             /*source ip */
    u_char	arp_tp[ETHER_ADDR_LEN];	/*target physics*/
    char    arp_tip[4];             /*target ip*/
};

/* Nagłówek IPv6, na podstawie Sieci komputerowe. Wydanie V - Andrew S. Tanenbaum, David J. Wetherall, Rozdział 5.6.3, IPv6*/
struct ipv6 {
    uint32_t    ip6_vtcfl;          /* wersja, klasa ruchu, etykieta przepływu */
    uint16_t    ip6_len;			/* długość ładunku */
    uint8_t     ip6_nh;             /* następny nagłówek */
#define IPPROTO_ICMP_IPV6   58
    uint8_t     ip6_hl;             /* limit przeskoków */
    char        ip6_src[16];		/* adres źródłowy */
    char        ip6_dst[16];		/* adres docelowy */
#define IPV6_HEADER_LENGTH 	40
#define IPV6_VERSION(ip6_vtclf) 	((ip6_vtclf & 0xf0000000) >> 28)
#define IPV6_TC(ip6_vtclf) 	((ip6_vtclf & 0x0ff00000) >> 20)
#define IPV6_FL(ip6_vtclf) 	(ip6_vtclf & 0x000fffff)
};

void Packet(const struct pcap_pkthdr *header, const u_char *packet, QList<QStandardItem *>*row);
void Packet_IPv4(const u_char *packet, QList<QStandardItem *> *row);
void Packet_IPv6(const u_char *packet, QList<QStandardItem *> *row);
void Packet_ARP(const u_char *packet, QList<QStandardItem *> *row);
void Packet_TCP(const u_char *packet, QList<QStandardItem *> *row);
void Packet_UDP(const u_char *packet, QList<QStandardItem *> *row);
void Packet_ICMP(const u_char *packet, QList<QStandardItem *> *row);
void Packet_ICMP_IPV6(const u_char *packet, QList<QStandardItem *> *row);

void Packet_Details(const u_char *packet, QStandardItemModel *details);
void IPv4_Details(const u_char *packet, QStandardItemModel *details);
void IPv6_Details(const u_char *packet, QStandardItemModel *details);
void ARP_Details(const u_char *packet, QStandardItemModel *details);
void TCP_Details(const u_char *packet, QStandardItemModel *details, int size);
void UDP_Details(const u_char *packet, QStandardItemModel *details, int size);
void ICMP_Details(const u_char *packet, QStandardItemModel *details, int size, bool ipv6_flag);

#endif //PACKETS_H
