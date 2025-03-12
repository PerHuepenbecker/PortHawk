//
// Created by Per Hüpenbecker on 11.03.25.
//

#include <string>
#include <cstring>

#include "SynScan.h"
#include "../../Helpers/helpers.h"

// Definitely optimizable, since for a number of ports, a lot of the ip address and other params will be the same
// but for now it works as the base functionality

[[nodiscard]] std::vector<uint8_t> SynScan::build_packet(PacketBuilder& packet_builder, const std::string &target_ip, uint16_t port) {

    std::vector<uint8_t> dummy_payload(100);
    std::fill(dummy_payload.begin(), dummy_payload.end(), 0x1);


    auto packet = packet_builder.set_destination_ip(target_ip)
            .set_port_dst(port)
            .set_SYN_flag()
            .add_payload(dummy_payload)
            .build_ip_header()
            .build_tcp_header()
            .build();
    return packet;
}

ScanResult SynScan::interpret_response(const std::vector<uint8_t> &response_packet, ReceiveStatus status, in_port_t target_port) {
    if(status == TIMEOUT){
        return ScanResult{target_port, PortStatus::FILTERED, status};
    }


    std::cout << "\tDEBUG" << std::endl;
    std::cout <<  std::endl;
    for(size_t i = 0; i < response_packet.size(); i++){
        std::cout << response_packet[i] << " ";
        if(i % 20 == 0){
            std::cout << std::endl;
        }
    }
    std::cout <<  std::endl;
    std::cout <<  std::endl;



    auto* ip_header = reinterpret_cast<const struct ip*>(response_packet.data());
    size_t ip_header_len = ip_header->ip_hl * 4;
    auto* tcp_header = reinterpret_cast<const struct tcphdr*>(response_packet.data()+ip_header_len);

    uint16_t response_port = ntohs(tcp_header->th_sport);

    if(response_port != target_port) {

        std::cout << "Ports dont match up"  << std::endl;
        std::cout << "Expected: " << target_port << "Received: " << response_port << std::endl;

        return ScanResult {target_port, PortStatus::UNKNOWN, status};
    }

    if((tcp_header->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
        return ScanResult {target_port, PortStatus::OPEN, status};
    }

    if (tcp_header->th_flags & TH_RST) {
        return ScanResult {target_port, PortStatus::CLOSED, status};
    }

    return ScanResult {target_port, PortStatus::FILTERED, status};
}
