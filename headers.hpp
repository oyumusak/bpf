#pragma once
#include <sys/types.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <netinet/in.h>

typedef struct s_ethernet_frame
{
    uint8_t dest_mac[6];
    uint8_t source_mac[6];
    uint16_t ether_type;

} ethernetHeader;

typedef struct MyIPHeader {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    in_addr source_ip;
    in_addr dest_ip;
} ipHeader;

typedef struct s_MyTCPHeader {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint8_t data_offset_reserved_flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} tcpHeader;

typedef struct s_MyICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    // Diğer ICMP başlık alanları
} icmpHeader;

typedef struct s_MyUDPHeader {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
    // Diğer UDP başlık alanları
} udpHeader;

typedef struct s_MySNMPHeader {
    // SNMP başlık alanları
    // Örnek:
    uint8_t version;
    uint8_t community_length;
    char community[64];  // Örnek olarak maksimum 64 karakter uzunluğunda bir topluluk adı
    // Diğer SNMP başlık alanları
} snmpHeader;