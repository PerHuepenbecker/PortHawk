//
// Created by Per Hüpenbecker on 11.03.25.
//

#include <string>
#include <cstring>

#include "SynScan.h"
#include "../../Helpers/helpers.h"


[[nodiscard]] std::vector<uint8_t>& SynScan::build_packet(PacketBuilder& packet_builder, const std::string &target_ip, uint16_t port) {
    auto packet = packet_builder.set_destination_ip(target_ip)
        .set_port_dst(port)
        .set_SYN_flag()
        .build_ip_header()
        .build_tcp_header()
        .build();

}

ScanResult SynScan::interpret_response(const std::vector<uint8_t> &response_packet, in_port_t target_port) {
    if(response_packet.empty()) {
        std::cerr << "[SynScan::interpret_response] Invalid response. Respone buffer empty" << std::endl;
        return ScanResult {target_port, PortStatus::ERROR};
    }

    auto* ip_header = reinterpret_cast<const struct ip*>(response_packet.data());
    size_t ip_header_len = ip_header->ip_hl * 4;
    auto* tcp_header = reinterpret_cast<const struct tcphdr*>(response_packet.data()+ip_header_len);

    uint16_t response_port = ntohs(tcp_header->th_sport);
    if(response_port != target_port) {
        return ScanResult {target_port, PortStatus::UNKNOWN};
    }

    if((tcp_header->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
        return ScanResult {target_port, PortStatus::OPEN};
    }

    if (tcp_header->th_flags & TH_RST) {
        return ScanResult {target_port, PortStatus::CLOSED};
    }

    return ScanResult {target_port, PortStatus::FILTERED};
}
