//
// Created by Per Hüpenbecker on 11.03.25.
//

#include "ScanTCPSocket.h"

ScanTCPSocket::ScanTCPSocket(std::shared_ptr<ScanStrategy> scan_strategy,ConnectionInfo& info, in_port_t source_port, bool debug) {

    //target_list_IPv6 = {};
    target_list_ports_ = {};

    source_ip_ = Helpers::get_connection_info().address;

    // preallocation of the buffer
    packet_buffer_ = std::vector<uint8_t>(MTU_ETHERNET);

    debug_mode = debug;

    scan_strategy_ = scan_strategy;
    source_port_ = source_port;

    packet_builder_ = std::make_unique<PacketBuilder>(scan_strategy_->get_protocol_type(), source_ip_, source_port);

}

void ScanTCPSocket::assign_target_address_v4(std::string target) {
    target_IPv4 = target;

    if(debug_mode){
        std::cout << "[ScanTCPSocket::assign_target_address_v4] Assigned " << target << "\n";
    }
}

void ScanTCPSocket::set_scan_strategy(std::shared_ptr<ScanStrategy> strategy){
    scan_strategy_ = strategy;
}

void ScanTCPSocket::assign_target_port(unsigned short first, unsigned short last) {

    if(last < first) {
        throw std::invalid_argument("Invalid port range");
    }

    for(unsigned short i = first; i <= last; i++){
        target_list_ports_.push_back(i);
    }
}

bool ScanTCPSocket::scan() {

    if (!socket_.open_raw_socket()) {
        return false;
    }

    for (const auto port: target_list_ports_) {


        packet_buffer_ = scan_strategy_->build_packet(*packet_builder_, target_IPv4, port);

        if (!socket_.send_packet(packet_buffer_, target_IPv4)) {
            std::cerr << "[ScanTCPSocket::scan] Error sending packet" << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));

    }
    socket_.close_raw_socket();
    return true;
}

void ScanTCPSocket::assign_target_port(unsigned short port){
    target_list_ports_.push_back(port);
    }