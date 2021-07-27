#include <stdio.h>
#include <stdint.h>
#include "hdr.h"
#include <pcap.h>
#include <arpa/inet.h>

#pragma pack(push, 1)
typedef struct Packet{
    Ether eth;
    IP ip;
    TCP tcp;
}Packet;
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]){
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle == nullptr){
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* data;
        int res = pcap_next_ex(handle, &header, &data);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
        }

        Packet* packet = (Packet*)data;

//        if(ntohs(packet->eth.pkt_type) != 2048){
//            continue;
//        }
        if(ntohs(packet->eth.pkt_type) != 0x0800){
            continue;
        }
        uint8_t ip_header_len = (packet->ip.verison_hl & 0xF)*4;
        uint8_t tcp_header_len = (packet->tcp.offset_reserve >> 4)*4;

        uint16_t ip_total_len = ntohs(packet->ip.total_len);

        if(packet->ip.protocol != 6){
            continue;
        }

        printf("Packet length : %d\n",ip_total_len);
        printf("IP header length : %d\n", ip_header_len);
        printf("TCP header length : %d\n",tcp_header_len);
        printf("=======================================\n");

        printf("Destination MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", packet->eth.des[0],packet->eth.des[1],packet->eth.des[2],packet->eth.des[3],packet->eth.des[4],packet->eth.des[5]);
        printf("Source MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",packet->eth.src[0],packet->eth.src[1],packet->eth.src[2],packet->eth.src[3],packet->eth.src[4],packet->eth.src[5]);
        printf("Ehter_type: %04x\n", packet->eth.pkt_type);
        printf("=======================================\n");

        printf("Destination IP : %d.%d.%d.%d\n",packet->ip.des_ip&0xFF, (packet->ip.des_ip>>8)&0xFF, (packet->ip.des_ip>>16)&0xFF, (packet->ip.des_ip>>24)&0xFF);
        printf("Source IP : %d.%d.%d.%d\n", packet->ip.src_ip&0xFF, (packet->ip.src_ip>>8)&0xFF, (packet->ip.src_ip>>16)&0xFF, (packet->ip.src_ip>>24)&0xFF);
        printf("Protocol : %04x\n",packet->ip.protocol);
        printf("=======================================\n");
        printf("Destination port : %d\n",ntohs(packet->tcp.des_port));
        printf("Source port : %d\n",ntohs(packet->tcp.src_port));
        printf("=======================================\n");

        unsigned char* payload;

        if(ip_total_len - ip_header_len - tcp_header_len > 0){
            payload = (unsigned char*)(packet + sizeof(Ether) + ip_header_len + tcp_header_len);
            printf("payload : ");
            for(int i =0; i < ip_total_len - ip_header_len - tcp_header_len; i++){
                printf("%02x ",payload[i]);
                if(i % 16 == 0)
                    printf("\n");
            }
        }
        printf("\n");
        printf("=======================================\n");

    }
    pcap_close(handle);
    return 0;
}
