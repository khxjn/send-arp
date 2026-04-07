#ifndef SEND_ARP_H
#define SEND_ARP_H

#include "struct_hdr.h"
#include <pcap.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define ETHTYPE_ARP 0x0806
#define ETHTYPE_IP  0x0800
#define ARPOP_REQUEST 1
#define ARPOP_REPLY   2

#pragma pack(push, 1)
typedef struct {
    Eth_hdr eth_;
    Arp_hdr arp_;
} EthArp_packet;
#pragma pack(pop)

bool get_my_ip(const char* dev, uint32_t* my_ip);
bool get_my_mac(const char* dev, uint8_t* my_mac);
bool get_sender_mac(pcap_t* handle, uint32_t my_ip, const uint8_t* my_mac, uint32_t sender_ip, uint8_t* sender_mac);
void send_attack(pcap_t* handle, const uint8_t* my_mac, uint32_t target_ip, const uint8_t* sender_mac, uint32_t sender_ip);
const char* mac_to_str(const uint8_t* mac, char* mac_str, size_t mac_str_size);

#endif