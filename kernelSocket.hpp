#pragma once
#include <sys/types.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <net/bpf.h>
#include <iostream>



class kernelSocket
{
    public:
        kernelSocket();
        int sockFd;
        int buffLen;
        struct bpf_hdr  *bpfBuff;
        struct bpf_hdr  *bpfPacket;
        int createKernelSocket(int bpfNumber, const char *interface);
        char *captureData();
};