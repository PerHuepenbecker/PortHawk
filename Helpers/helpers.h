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
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <cstring>
#include <ifaddrs.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include "PortStatus.h"
#include "ReceiveStatus.h"
#include <sstream>
#include <map>

#include <pcap.h>

using PORT = uint16_t;

#define MTU_ETHERNET 1500

typedef struct {
    std::string address;
    std::string interface_name;
} ConnectionInfo;

namespace Helpers {


    unsigned short ip_checksum(void *b, int len);

    unsigned short tcp_checksum(struct ip* ip_header, struct tcphdr* tcp_header, std::vector<uint8_t>& payload);

    size_t get_tcp_header_length(const struct tcphdr* tcp_header);

    ConnectionInfo get_connection_info();

    std::string resolve_receive_status(ReceiveStatus status);
    std::string resolve_port_status(PortStatus status);
}


#endif //DOORSCAN_HELPERS_H
