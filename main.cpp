#include "kernelSocket.hpp"

int main()
{
    kernelSocket mySocket;

    mySocket.createKernelSocket(2, "en0");

    mySocket.captureData();
}