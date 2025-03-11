//
// Created by Per Hüpenbecker on 11.03.25.
//

#ifndef DOORSCAN_SCANTCPSOCKET_H
#define DOORSCAN_SCANTCPSOCKET_H

using SOCKET = int;

#include "PacketHandler.h"

class ScanTCPSocket {
private:
    SOCKET sock;
    PacketHandler packetBuilder;
    std::vector<in_addr_t> target_list_IPv4;
    std::vector<in6_addr_t> target_list_IPv6;

    std::vector<unsigned short> target_list_ports;

public:
    ScanTCPSocket();
    ~ScanTCPSocket();

    void assign_target_address(in_addr_t target);
    void assing_target_address(in6_addr_t target);

    void assign_target_port(unsigned short first, unsigned short last);
};


#endif //DOORSCAN_SCANTCPSOCKET_H
