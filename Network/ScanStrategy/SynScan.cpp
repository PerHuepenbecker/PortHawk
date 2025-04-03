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

    auto packet = packet_builder.set_destination_ip(target_ip)
            .set_port_dst(port)
            .set_SYN_flag()
            .set_mss_value(1460)
            .build_ip_header()
            .build_tcp_header()
            .build();

    return packet;
}

std::pair<std::string, ScanResult> SynScan::interpret_response(RawScanResult&& rawScan) {

    auto scan = rawScan;
    std::array<char, INET6_ADDRSTRLEN> address_buffer{};
    PortStatus status;

    in_port_t checked_port = ntohs(scan.sourcePort);

    if(!inet_ntop(AF_INET, &scan.source_ip.s_addr, address_buffer.data(), INET_ADDRSTRLEN)){
        throw std::invalid_argument("[SynScan::interpret_response] Bad IP received");
    }

    // Check for TCP flags sent in response
    switch(rawScan.tcp_flags){
        // ACK
        case 0x12:
            status = OPEN;
            break;
        // RST
        case 0x14:
            status = CLOSED;
            break;
        // Default case - only for malformed response packets
        default:
            status = UNKNOWN;
    }

    return std::make_pair(address_buffer.data(), ScanResult{.port = checked_port, .status_port = status});
}

ProtocolType SynScan::get_protocol_type() const {
    return ProtocolType::TCP;
}