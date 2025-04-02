//
// Created by Per Hüpenbecker on 11.03.25.
//

#include "PacketBuilder.h"


PacketBuilder::PacketBuilder(ProtocolType protocol, std::string source_ip, in_port_t source_port) : protocol(protocol), source_ip(source_ip) {
    random_engine = std::mt19937(std::random_device()());
    randomizer = std::uniform_int_distribution<uint16_t>(1024, 65535);

    if(!inet_pton(AF_INET, source_ip.c_str(), &params.ip_src)){
        throw std::invalid_argument("[Source IP] Invalid IP address argument");
    }
    source_port_ = source_port;
    params.port_src = source_port_;

    std::cout << "PacketBuilder::PacketBuilder - Initialized with source port " << source_port << std::endl;

    packet.resize(sizeof(struct ip) + sizeof(struct tcphdr));
}

PacketBuilder &PacketBuilder::set_source_ip(const std::string &ip_src) {
    if (!inet_pton(AF_INET, ip_src.c_str(), &params.ip_src)){
        throw std::invalid_argument("[Source IP] Invalid IP address argument");
    };
    return *this;
}

PacketBuilder &PacketBuilder::set_destination_ip(const std::string& ip_dst) {
    if(!inet_pton(AF_INET, ip_dst.c_str(), &params.ip_dst)){
        std::stringstream ss;
        ss << "[Destination IP] Invalid IP address argument: " << ip_dst;
        throw std::invalid_argument(ss.str());
    };
    return *this;
}

PacketBuilder &PacketBuilder::set_port_src(uint16_t port_src) {
    params.port_src = port_src;
    return *this;
}

PacketBuilder &PacketBuilder::set_port_dst(uint16_t port_dst) {
    params.port_dst = port_dst;
    return *this;
}

PacketBuilder &PacketBuilder::set_SYN_flag() {
    params.tcp_flags |= TH_SYN;
    return *this;
}

PacketBuilder &PacketBuilder::set_mss_value(uint16_t mss_value){
    params.tcp_mss_value = mss_value;
    params.th_off += 1;

    std::vector<uint8_t> mss_option(4);
    mss_option[0] = 2;
    mss_option[1] = 4;
    mss_option[2] = (mss_value >> 8) & 0xFF;
    mss_option[3] = mss_value & 0xFF;

    this->add_payload(mss_option);
    return *this;
}

PacketBuilder &PacketBuilder::set_ACK_flag() {
    params.tcp_flags |= TH_ACK;
    return *this;
}

PacketBuilder &PacketBuilder::set_RST_flag() {
    params.tcp_flags |= TH_RST;
    return *this;;
}

PacketBuilder &PacketBuilder::set_FIN_flag() {
    params.tcp_flags |= TH_FIN;
    return *this;
}

PacketBuilder &PacketBuilder::set_tcp_flags(uint8_t tcp_flags) {
    params.tcp_flags = tcp_flags;
    return *this;
}

PacketBuilder &PacketBuilder::set_window_size(uint16_t window_size) {
    params.window_size = window_size;
    return *this;
}

PacketBuilder &PacketBuilder::set_tcp_seq_num(uint16_t tcp_seq_num) {
    params.tcp_seq_num = tcp_seq_num;
    return *this;
}

PacketBuilder &PacketBuilder::set_tcp_ack_num(uint16_t tcp_ack_num) {
    params.tcp_ack_num = tcp_ack_num;
    return *this;
}

uint8_t PacketBuilder::set_protocol_type(ProtocolType protocol) {
    switch (protocol) {
        case ProtocolType::TCP:
            return IPPROTO_TCP;
        case ProtocolType::UDP:
            return IPPROTO_UDP;
        case ProtocolType::ICMP:
            return IPPROTO_ICMP;
    }
}

PacketBuilder& PacketBuilder::build_ip_header(){
    auto *ip_header = (struct ip*) packet.data();
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = (sizeof(struct ip) + sizeof(struct tcphdr) + params.payload_size);

    if(params.ip_id == 0){
        params.ip_id = random_seq_number();
    }
    ip_header->ip_id = htons(params.ip_id);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = params.ip_ttl;
    ip_header->ip_p = set_protocol_type(protocol);
    ip_header->ip_src = (in_addr)params.ip_src;
    ip_header->ip_dst = (in_addr)params.ip_dst;

    ip_header->ip_sum = Helpers::ip_checksum((unsigned short*) packet.data(), sizeof(struct ip));

    return *this;
}

PacketBuilder& PacketBuilder::build_tcp_header(){
    auto *tcp_header = (struct tcphdr*) (packet.data() + sizeof(struct ip));

    if(params.port_src == 0 || source_port_ == 0) {
        params.port_src = random_port();
    }

    tcp_header->th_sport = htons(params.port_src);
    tcp_header->th_dport = htons(params.port_dst);

    if (params.tcp_seq_num == 0){
        params.tcp_seq_num = random_seq_number();
    }

    tcp_header->th_seq = htonl(params.tcp_seq_num);
    tcp_header->th_ack = htonl(params.tcp_ack_num);
    tcp_header->th_off = params.th_off;
    params.th_off = 5;
    tcp_header->th_flags = params.tcp_flags;
    tcp_header->th_win = htons(params.window_size);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;

    std::cout << "TCP TH_OFF = " << tcp_header->th_off << std::endl;

    tcp_header->th_sum = Helpers::tcp_checksum((struct ip*) packet.data(), tcp_header, params.payload);


    return *this;
}

PacketBuilder& PacketBuilder::build_udp_header(){
    return *this;
}

PacketBuilder& PacketBuilder::build_icmp_header(){
    return *this;
}

std::vector<uint8_t> PacketBuilder::build() {

    std::cout << "[BUILD] Packet size: " << packet.size() << std::endl;

    return packet;
}

uint16_t PacketBuilder::random_port() {
    return randomizer(random_engine);
}

uint16_t PacketBuilder::random_seq_number() {
    return randomizer(random_engine);
}

PacketBuilder &PacketBuilder::add_payload(const std::vector<uint8_t> &payload) {
    size_t header_size = sizeof(struct ip) + sizeof(struct tcphdr);

    std::cout << "Payload size: " << payload.size() << std::endl;
    std::cout << "Packet size: " << packet.size() << std::endl;

    packet.resize(header_size+payload.size());

    std::cout << "Packet size after: " << packet.size() << std::endl;
    // Using efficient C functions for buffer management

    memset(packet.data() + header_size, 0, payload.size());
    memcpy(packet.data() + header_size, payload.data(), payload.size());

    params.payload_size = payload.size();
    params.payload = payload;

    return *this;
}