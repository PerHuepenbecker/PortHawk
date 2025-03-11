//
// Created by Per Hüpenbecker on 11.03.25.
//

#ifndef DOORSCAN_HELPERS_H
#define DOORSCAN_HELPERS_H

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>


// *b: buffer for checksum || len: length of buffer
unsigned short ip_checksum(void *b, int len);

#endif //DOORSCAN_HELPERS_H
