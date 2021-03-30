#include "sniffer.h"

void Sniffer::Find_Packets(QString text_get, u_short find_option){
    data_found.clear();
    find = text_get;
    std::vector<unsigned char*> ::iterator i;
    int data_number = 0;

    switch(find_option){
    case 1:
        for (i = this->data.begin(); i != this->data.end(); i++){
            iph = (struct iphdr*)(*i + sizeof(struct ethhdr));
            find_info.s_addr = iph->daddr;
            if(find.toStdString() == inet_ntoa(find_info)){
                data_found.push_back(data[data_number]);
            }else{
                find_info.s_addr = iph->saddr;
                if(find.toStdString() == inet_ntoa(find_info)){
                    data_found.push_back(data[data_number]);
                }
            }
            data_number = data_number + 1;
        }
        break;
    case 2:
        for (i = this->data.begin(); i != this->data.end(); i++){
            const struct ipv6 *ip;
            ip = (struct ipv6*)(*i + sizeof(struct ethhdr));
            char buffer[INET6_ADDRSTRLEN];
            if(find.toStdString() == inet_ntop(AF_INET6, ip->ip6_dst, buffer, sizeof(buffer))){
                data_found.push_back(data[data_number]);
            }else{
                if(find.toStdString() == inet_ntop(AF_INET6, ip->ip6_src, buffer, sizeof(buffer))){
                    data_found.push_back(data[data_number]);
                }
            }
            data_number = data_number + 1;
        }
        break;
    case 3:
        if(find.toStdString() == "ICMP") find = 1;
        else if(find.toStdString() == "TCP") find = 6;
        else if(find.toStdString() == "UDP") find = 17;
        else return;
        for (i = this->data.begin(); i != this->data.end(); i++){
            iph = (struct iphdr*)(*i + sizeof(struct ethhdr));
            if (iph->protocol == find) data_found.push_back(data[data_number]);;
            data_number = data_number + 1;
        }
        break;
    }
}
