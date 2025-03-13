//
// Created by Per Hüpenbecker on 11.03.25.
//

#ifndef DOORSCAN_PACKETBUILDER_H
#define DOORSCAN_PACKETBUILDER_H

#include <vector>
#include <random>
#include "../Helpers/helpers.h"
#include "ProtocolType.h"

class PacketBuilder {
private:
    // Randomization members for packet building
    std::mt19937 random_engine;
    std::uniform_int_distribution<uint16_t> randomizer;

    // Protocol type for packet creation
    ProtocolType protocol;

    // Source IP address as a class attribute. I decided to but it here as a standard option to keep
    // the signature of the build_packet function in SynScan.h clean and simple. It remains possible
    // to change the source ip here for some advanced scanning setup with possible redirections.

    std::string source_ip;
    in_port_t source_port;

    // Packet buffer
    std::vector<uint8_t> packet_buffer;
    std::vector<uint8_t> packet;

    // Packet parameters
    struct {
        in_addr ip_src;
        in_addr ip_dst;
        uint16_t ip_id = 0;
        uint8_t ip_ttl = 64;
        uint16_t port_src = 0;
        uint16_t port_dst = 0;
        uint8_t tcp_flags = 0;
        uint16_t window_size = 65535;
        uint32_t tcp_seq_num = 0;
        uint32_t tcp_ack_num = 0;
        uint16_t tcp_mss_value = 0;
        uint16_t payload_size = 0;
        uint8_t th_off = 5;
        std::vector<uint8_t> payload = {};
    } params;

    uint8_t set_protocol_type(ProtocolType protocol);
    uint16_t random_port();
    uint16_t random_seq_number();

    PacketBuilder& update_ip_header(size_t payload_len);
    PacketBuilder& update_tcp_checksum(size_t );


public:
    explicit PacketBuilder(ProtocolType protocol, std::string source_ip, in_port_t source_port);

    PacketBuilder& set_source_ip(const std::string &ip_src);
    PacketBuilder& set_destination_ip(const std::string &ip_dst);
    PacketBuilder& set_port_src(uint16_t port_src);
    PacketBuilder& set_port_dst(uint16_t port_dst);

    PacketBuilder& set_SYN_flag();
    PacketBuilder& set_ACK_flag();
    PacketBuilder& set_RST_flag();
    PacketBuilder& set_FIN_flag();

    PacketBuilder& set_tcp_flags(uint8_t tcp_flags);
    PacketBuilder& set_window_size(uint16_t window_size);
    PacketBuilder& set_tcp_seq_num(uint16_t tcp_seq_num);
    PacketBuilder& set_tcp_ack_num(uint16_t tcp_ack_num);
    PacketBuilder& set_mss_value(uint16_t mss_value);

    PacketBuilder& build_ip_header();
    PacketBuilder& build_tcp_header();
    PacketBuilder& build_udp_header();
    PacketBuilder& build_icmp_header();


    PacketBuilder& add_payload(const std::vector<uint8_t> &payload);

    std::vector<uint8_t> build();
};


#endif //DOORSCAN_PACKETBUILDER_H
