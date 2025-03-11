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
#include <ifaddrs.h>
#include <unistd.h>
#include <arpa/inet.h>


// *b: buffer for checksum || len: length of buffer
unsigned short ip_checksum(void *b, int len);

unsigned short tcp_checksum(struct ip* ip_header, struct tcphdr* tcp_header, std::vector<uint8_t>& payload);

std::string get_local_ip();

#endif //DOORSCAN_HELPERS_H
