//
// Created by Per Hüpenbecker on 11.03.25.
//

#include "ScanTCPSocket.h"

ScanTCPSocket::ScanTCPSocket(std::string source_ip_val, in_port_t source_port_val) {

    target_list_IPv4 = {};
    //target_list_IPv6 = {};
    target_list_ports = {};
    source_ip = source_ip_val;

    // preallocation of the buffers
    packet_buffer = std::vector<uint8_t>(MTU_ETHERNET);
    response_buffer = std::vector<uint8_t>(MTU_ETHERNET);

    // default function to assign a local_ip
    if(source_ip.empty()){
        source_ip = Helpers::get_local_ip();
    }

    source_port = source_port_val;
    packet_builder = std::make_unique<PacketBuilder>(ProtocolType::TCP, source_ip, source_port_val);


}

void ScanTCPSocket::assign_target_address_v4(std::string target) {

    target_list_IPv4.push_back(target);
}

void ScanTCPSocket::assign_target_port(unsigned short first, unsigned short last) {

    if(last < first) {
        throw std::invalid_argument("Invalid port range");
    }

    for(unsigned short i = first; i <= last; i++){
        target_list_ports.push_back(i);
    }
}
