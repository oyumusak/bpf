#include "printHeaders.hpp"
#include "iostream"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
# include <openssl/hmac.h>
# include <openssl/evp.h>
# include <openssl/engine.h>
# include <openssl/hmac.h>
# include <openssl/evp.h>
# include <openssl/ssl.h>

void printEthernetHeader(ethernetHeader *ethHeader) {
    std::cout << "-------------Begin Ethernet Header--------------" << std::endl;

    // Destination MAC Address
    std::cout << "Destination MAC : ";
    for (int i = 0; i < 6; ++i) {
        std::cout << std::hex << static_cast<int>(ethHeader->dest_mac[i]) << std::dec;
        if (i < 5) {
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    // Source MAC Address
    std::cout << "Source MAC: ";
    for (int i = 0; i < 6; ++i) {
        std::cout << std::hex << static_cast<int>(ethHeader->source_mac[i]) << std::dec;
        if (i < 5) {
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    std::cout << "Ethernet Type: 0x" << std::hex << ntohs(ethHeader->ether_type) << std::dec << std::endl;
    std::cout << "-------------End Ethernet Header--------------" << std::endl;
}

void printIPHeader(ipHeader *ipHeader) {

    char source_ip_str[INET_ADDRSTRLEN];
    char dest_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->source_ip), source_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->dest_ip), dest_ip_str, INET_ADDRSTRLEN);

    

    /*
    struct in_addr deneme;
    inet_pton(AF_INET, source_ip_str, &deneme);
    std::cout << "Debug Begin" << std::endl;
    std::cout << deneme.s_addr << std::endl << ipHeader->source_ip.s_addr << std::endl;
    std::cout << "Debug End" << std::endl;
    */

    std::cout << "-------------Begin Ip Header--------------" << std::endl;
    std::cout << "IP Header:" << std::endl;
    std::cout << "Version & IHL: 0x" << std::hex << static_cast<int>(ipHeader->version_ihl) << std::dec << std::endl;
    std::cout << "Type of Service (TOS): 0x" << std::hex << static_cast<int>(ipHeader->tos) << std::dec << std::endl;
    std::cout << "Total Length: " << ntohs(ipHeader->total_length) << std::endl;
    std::cout << "ID: " << ntohs(ipHeader->id) << std::endl;
    std::cout << "Fragment Offset: " << ntohs(ipHeader->fragment_offset) << std::endl;
    std::cout << "TTL: " << static_cast<int>(ipHeader->ttl) << std::endl;
    std::cout << "Protocol: " << static_cast<int>(ipHeader->protocol) << std::endl;
    std::cout << "Checksum: 0x" << std::hex << ntohs(ipHeader->checksum) << std::dec << std::endl;
    std::cout << "Source IP: " << source_ip_str << std::endl;
    std::cout << "Destination IP: " << dest_ip_str << std::endl;
    std::cout << "-------------End Ip Header--------------" << std::endl;
    
}

void printTcpHeader(tcpHeader *tcpHdr, ipHeader *ipHdr)
{
    std::cout << "-------------Begin Tcp Header--------------" << std::endl;
    std::cout << "Source Port: " << ntohs(tcpHdr->source_port) << std::endl;
    std::cout << "Destination Port: " << ntohs(tcpHdr->dest_port) << std::endl;
    std::cout << "Sequence Number: " << ntohl(tcpHdr->sequence_number) << std::endl;
    std::cout << "Acknowledgment Number: " << ntohl(tcpHdr->ack_number) << std::endl;
    std::cout << "Data Offset & Reserved & Flags: 0x" << std::hex << static_cast<int>(tcpHdr->data_offset_reserved_flags) << std::dec << std::endl;
    std::cout << "Window Size: " << ntohs(tcpHdr->window_size) << std::endl;
    std::cout << "Checksum: 0x" << std::hex << ntohs(tcpHdr->checksum) << std::dec << std::endl;
    std::cout << "Urgent Pointer: " << ntohs(tcpHdr->urgent_pointer) << std::endl;

    int tcpHeaderLength = (tcpHdr->data_offset_reserved_flags >> 4) * 4;
    uint8_t *dataStart = (unsigned char *)tcpHdr + tcpHeaderLength;
    int dataSize = ntohs(ipHdr->total_length) - tcpHeaderLength;
    std::cout << "TCP Verisi: " << std::endl;
    for (int i = 0; i < dataSize; ++i) {
        if (dataStart[i] == '\r' && dataStart[i + 1] == '\n')
        {
            std::cout << std::endl;
            i++;
        }
        else
            printf("%c", isprint(dataStart[i]) ? dataStart[i] : '.');
    }
    std::cout << std::endl;
    std::cout << "-------------End Tcp Header--------------" << std::endl;
}


void printIcmpHeader(icmpHeader* icmpHdr)
{
    std::cout << "-------------Icmp Header--------------" << std::endl;

    switch (icmpHdr->type) {
        case 0:
            if (icmpHdr->code == 0)
                std::cout << "Echo Reply (Ping Response)" << std::endl;
            else
                std::cout << "Reserved" << std::endl;
            break;
        case 3:
            switch (icmpHdr->code) {
                case 0:
                    std::cout << "Destination Network Unreachable" << std::endl;
                    break;
                case 1:
                    std::cout << "Destination Host Unreachable" << std::endl;
                    break;
                case 2:
                    std::cout << "Destination Protocol Unreachable" << std::endl;
                    break;
                case 3:
                    std::cout << "Destination Port Unreachable" << std::endl;
                    break;
                case 4:
                    std::cout << "Fragmentation Required, and DF (Don't Fragment) Flag Set" << std::endl;
                    break;
                case 5:
                    std::cout << "Source Route Failed" << std::endl;
                    break;
                case 6:
                    std::cout << "Destination Network Unknown" << std::endl;
                    break;
                case 7:
                    std::cout << "Destination Host Unknown" << std::endl;
                    break;
                case 8:
                    std::cout << "Source Host Isolated" << std::endl;
                    break;
                case 9:
                    std::cout << "Network Administratively Prohibited" << std::endl;
                    break;
                case 10:
                    std::cout << "Host Administratively Prohibited" << std::endl;
                    break;
                case 11:
                    std::cout << "Network Unreachable for Type of Service (ToS)" << std::endl;
                    break;
                case 12:
                    std::cout << "Host Unreachable for Type of Service (ToS)" << std::endl;
                    break;
                case 13:
                    std::cout << "Communication Administratively Prohibited" << std::endl;
                    break;
                case 14:
                    std::cout << "Host Precedence Violation" << std::endl;
                    break;
                case 15:
                    std::cout << "Precedence Cutoff in Effect" << std::endl;
                    break;
                default:
                    std::cout << "Unknown Code: " << static_cast<int>(icmpHdr->code) << std::endl;
                    break;
            }
            break;
        case 4:
            if (icmpHdr->code == 0)
                std::cout << "Source Quench (Deprecated)" << std::endl;
            else
                std::cout << "Reserved" << std::endl;
            break;
        case 5:
            switch (icmpHdr->code) {
                case 0:
                    std::cout << "Redirect Datagram for the Network" << std::endl;
                    break;
                case 1:
                    std::cout << "Redirect Datagram for the Host" << std::endl;
                    break;
                case 2:
                    std::cout << "Redirect Datagram for the ToS & Network" << std::endl;
                    break;
                case 3:
                    std::cout << "Redirect Datagram for the ToS & Host" << std::endl;
                    break;
                case 4:
                    std::cout << "Alternate Host Address (Deprecated)" << std::endl;
                    break;
                default:
                    std::cout << "Unknown Code: " << static_cast<int>(icmpHdr->code) << std::endl;
                    break;
            }
            break;
        case 6:
            std::cout << "Echo Request" << std::endl;
            break;
        // Diğer ICMP tipleri için case'leri ekleyebilirsiniz
        default:
            std::cout << "Unknown ICMP Type: " << static_cast<int>(icmpHdr->type) << std::endl;
            break;
    }

    std::cout << "-------------End Icmp Header--------------" << std::endl << std::endl;
}

void pprintTcpHeader(tcpHeader *tcpHdr, ipHeader *ipHdr)
{
    char source_ip_str[INET_ADDRSTRLEN];
    char dest_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHdr->source_ip), source_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHdr->dest_ip), dest_ip_str, INET_ADDRSTRLEN);

    //        std::cout << "Destination Ip: " << dest_ip_str << std::endl;
    //    std::cout << "Source Ip: " << source_ip_str << std::endl;

    if (/*ntohs(tcpHdr->source_port) != 443 && ntohs(tcpHdr->dest_port) != 443  &&*/ strcmp(dest_ip_str, "192.168.1.54") != 0 && strcmp(source_ip_str, "192.168.1.54") != 0)
    {
        
        std::cout << "-------------Begin Tcp Header--------------" << std::endl;
        std::cout << "Destination Ip: " << dest_ip_str << std::endl;
        std::cout << "Source Ip: " << source_ip_str << std::endl;
        std::cout << "Source Port: " << ntohs(tcpHdr->source_port) << std::endl;
        std::cout << "Destination Port: " << ntohs(tcpHdr->dest_port) << std::endl;
        std::cout << "Sequence Number: " << ntohl(tcpHdr->sequence_number) << std::endl;
        std::cout << "Acknowledgment Number: " << ntohl(tcpHdr->ack_number) << std::endl;
        std::cout << "Data Offset & Reserved & Flags: 0x" << std::hex << static_cast<int>(tcpHdr->data_offset_reserved_flags) << std::dec << std::endl;
        std::cout << "Window Size: " << ntohs(tcpHdr->window_size) << std::endl;
        std::cout << "Checksum: 0x" << std::hex << ntohs(tcpHdr->checksum) << std::dec << std::endl;
        std::cout << "Urgent Pointer: " << ntohs(tcpHdr->urgent_pointer) << std::endl;

        int tcpHeaderLength = (tcpHdr->data_offset_reserved_flags >> 4) * 4;
        uint8_t *dataStart = (unsigned char *)tcpHdr + tcpHeaderLength;
        int dataSize = ntohs(ipHdr->total_length) - tcpHeaderLength;
        std::cout << "TCP Verisi: " << std::endl;

        //SSL_load_error_strings();
        //SSL_library_init();
        //SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
        //SSL *ssl = SSL_new(ssl_ctx);

        //int bytesRead = SSL_read(ssl, )
        
        for (int i = 0; i < dataSize; ++i) {
            if (dataStart[i] == '\r' && dataStart[i + 1] == '\n')
            {
                std::cout << std::endl;
                i++;
            }
            else
                printf("%c", isprint(dataStart[i]) ? dataStart[i] : '.');
        }
        
        std::cout << std::endl;
        std::cout << "-------------End Tcp Header--------------" << std::endl;
    }
}