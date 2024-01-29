#pragma once

#include "headers.hpp"

void printEthernetHeader(ethernetHeader *ethHeader);
void printIPHeader(ipHeader *ipHeader);
void printTcpHeader(tcpHeader *tcpHdr, ipHeader *ipHdr);
void printIcmpHeader(icmpHeader *icmpHdr);
void pprintTcpHeader(tcpHeader *tcpHdr, ipHeader *ipHdr);