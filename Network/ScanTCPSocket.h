//
// Created by Per Hüpenbecker on 11.03.25.
//

#ifndef DOORSCAN_SCANTCPSOCKET_H
#define DOORSCAN_SCANTCPSOCKET_H

#include "ScanStrategy/SynScan.h"
#include "PacketBuilder.h"



class ScanTCPSocket {
private:
    SOCKET sock;
    std::unique_ptr<PacketBuilder> packet_builder;
    std::unique_ptr<ScanStrategy> scan_strategy;

    // Local buffer to store the crafted packets. Taken out of the build packet method and placed
    // as an attribute here to avoid frequent expensive and unnecessary reallocations. They are being
    // preallocated in the constructor to house the maximum size of an ethernet packet.

    std::vector<uint8_t> packet_buffer;
    std::vector<uint8_t> response_buffer;

    std::string source_ip;
    in_port_t source_port;

    std::vector<std::string> target_list_IPv4;
    //std::vector<std::string> target_list_IPv6; => After base functionality for IPv4 is implemented

    std::vector<unsigned short> target_list_ports;

public:
    ScanTCPSocket(std::string source_ip, PORT source_port);
    ~ScanTCPSocket();

    void assign_target_address_v4(std::string target);


    void assign_target_port(unsigned short first, unsigned short last);
};


#endif //DOORSCAN_SCANTCPSOCKET_H
