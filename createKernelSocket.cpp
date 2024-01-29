#include "kernelSocket.hpp"
#include "printHeaders.hpp"
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>
#include "string.h"
#include "string"
#include "defines.hpp"
#include <net/if.h>

int g_run = 1;

int analyze(char *ptr) //tcp udp icmp snmp packets
{
    ethernetHeader *ethHeader;
    ipHeader   *ipHdr;

    ethHeader = (ethernetHeader *)ptr;
    ipHdr = (ipHeader *)((char *)ethHeader + sizeof(ethernetHeader));
    //std::cout << "ethHeader: " << ethHeader->ether_type << std::endl;
    //std::cout << "Protocol: " << ipHdr->protocol << std::endl;
    //std::cout << "Protocol Static Cast: " << static_cast<int>(ipHdr->protocol) << std::endl;
    //printEthernetHeader(ethHeader);

    if (ethHeader->ether_type != 8)
        return (-1);

    //std::cout << (int)ipHdr->protocol << std::endl;

    if (ipHdr->protocol == 1) // icmp
        return (ICMP);
    else if (ipHdr->protocol == 161) //snmp
        return (SNMP);
    else if (ipHdr->protocol == 6) //Tcp
        return (TCP);
    else if (ipHdr->protocol == 17) //Udp
        return (UDP);
    return (-1);
}



void handleCtrlC(int sigNo)
{
    g_run = 0;
}

kernelSocket::kernelSocket()
{
    signal(SIGINT, handleCtrlC);
}

int kernelSocket::createKernelSocket(int bpfNumber, const char *interface)
{
    std::string buff;
    struct ifreq    boundif;

    buff = "/dev/bpf";
    buff += std::to_string(bpfNumber);

    this->sockFd = open(buff.c_str(), O_RDWR);
    if (this->sockFd == -1)
    {
        perror("Socket Create Error = ");
        exit(1);
    }

    //memcpy(&boundif, 0, sizeof(struct ifreq));
    strcpy(boundif.ifr_name, interface);



    
    //boundif.ifr_ifru.ifru_flags = IFF_PROMISC;

    if (ioctl(this->sockFd, BIOCSETIF, &boundif) == -1)
    {
        perror("ioctl BIOCSETIF error = ");
        close(this->sockFd);
        exit(0);
    }

    this->buffLen = 1; // biocpromisc: set the if to promiscuous mode
    if (ioctl(this->sockFd, BIOCPROMISC, &this->buffLen) < 0) {
        perror("Error enabling promiscuous mode");
        return 1;
    }

    boundif.ifr_flags |= IFF_PROMISC;

    if (ioctl(sockFd, BIOCSETIF, &boundif) == -1) {
        perror("ioctl BIOCSETIF error");
        close(sockFd);
        exit(EXIT_FAILURE);
    }



    this->buffLen = 1;

    int enable = 1;
    if (ioctl(this->sockFd, BIOCSHDRCMPLT, &enable) == -1)
    {
        perror("ioctl BIOCSHDRCMPLT error = ");
        close(this->sockFd);
        exit(1);
    }

    if (ioctl(this->sockFd, BIOCIMMEDIATE, &this->buffLen) == -1)
    {
        perror("ioctl BIOCIMMADIATE error = ");
        close(this->sockFd);
        exit(1);
    }

    if (ioctl(this->sockFd, BIOCGBLEN, &this->buffLen))
    {
        perror("ioctl BIOCBLEN error = ");
        close(this->sockFd);
        exit(1);
    }

    this->bpfBuff = new struct bpf_hdr[this->buffLen];
    
    return (this->sockFd);
}

char *kernelSocket::captureData()
{
    int readBytes;
    char    *ptr;
    ethernetHeader *frame;
    ipHeader *iphdr;
    icmpHeader *icmpHdr;
    tcpHeader *tcpHdr;
    int packetType;

    while (g_run)
    {
        memset(this->bpfBuff, 0, this->buffLen);
        readBytes = read(this->sockFd, bpfBuff, this->buffLen);
        if (readBytes > 0)
        {
            //ptr bpf buff'un başlangıcını ifade eder
            ptr = reinterpret_cast<char *>(this->bpfBuff);
            //bpf buff aynı anda birden fazla paket yakalayabildiği için yakaladığı paketler boyunca döngü oluşturulur
            while (ptr < (reinterpret_cast<char *>(this->bpfBuff) + readBytes))
            {
                this->bpfPacket = reinterpret_cast<bpf_hdr *>(ptr);
                packetType = analyze((char *) this->bpfPacket + bpfPacket->bh_hdrlen);
                if (packetType == ICMP)
                {
                    frame = (ethernetHeader *)((char *) this->bpfPacket + bpfPacket->bh_hdrlen);
                    iphdr = (ipHeader *)((char *) frame + sizeof(ethernetHeader));
                    icmpHdr = (icmpHeader *)((char *) iphdr + sizeof(ipHeader));
                    printEthernetHeader(frame);
                    printIPHeader(iphdr);
                    printIcmpHeader(icmpHdr);
                }
                /*
                if (packetType == TCP)
                {
                    frame = (ethernetHeader *)((char *) this->bpfPacket + bpfPacket->bh_hdrlen);
                    iphdr = (ipHeader *)((char *) frame + sizeof(ethernetHeader));
                    tcpHdr = (tcpHeader *)((char *) iphdr + sizeof(ipHeader));
                    //printEthernetHeader(frame);
                    //printIPHeader(iphdr);
                    pprintTcpHeader(tcpHdr, iphdr);
                }*/
                frame = (ethernetHeader *)((char *) this->bpfPacket + bpfPacket->bh_hdrlen);
                iphdr = (ipHeader *)((char *) frame + sizeof(ethernetHeader));
                printEthernetHeader(frame);
                printIPHeader(iphdr);
                // bir sonraki pakete geçebilmek için paket uzunluğu ve header kadar arttırıyoruz
                ptr += BPF_WORDALIGN(bpfPacket->bh_hdrlen + bpfPacket->bh_caplen);

            }
        }
    }
    delete[] this->bpfBuff;
    close(this->sockFd);
    return (NULL);
}