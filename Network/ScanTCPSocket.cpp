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

    scan_strategy = std::make_unique<SynScan>();
    source_port = source_port_val;
    packet_builder = std::make_unique<PacketBuilder>(ProtocolType::TCP, source_ip, source_port_val);

}

void ScanTCPSocket::assign_target_address_v4(std::string target) {

    target_list_IPv4.push_back(target);
    std::cout << "Target address assigned" << std::endl;
}

void ScanTCPSocket::assign_target_port(unsigned short first, unsigned short last) {

    if(last < first) {
        throw std::invalid_argument("Invalid port range");
    }

    for(unsigned short i = first; i <= last; i++){
        target_list_ports.push_back(i);
    }

    std::cout << "Target port assigned" << std::endl;
}

bool ScanTCPSocket::scan() {

    if(!socket.open_raw_socket()){
        return false;
    }

    for(const auto address: target_list_IPv4){

        scan_results.insert({address,{}});

        for(const auto port: target_list_ports){

            std::cout << "Scanning " << port << std::endl;

            packet_buffer = scan_strategy->build_packet(*packet_builder, address, port);

            if(!socket.send_packet(packet_buffer, address)){
                std::cerr<< "[ScanTCPSocket::scan] Error sending packet" << std::endl;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(1));

/*            ReceiveStatus status = socket.receive_packet(response_buffer, response_size);

            if(status != ReceiveStatus::ERROR){
                scan_results[address].push_back(scan_strategy->interpret_response(response_buffer, status, port));
            } else {
                scan_results[address].push_back(ScanResult{port, PortStatus::UNKNOWN, status});
            }*/
        }

    }

    socket.close_raw_socket();
    return true;
}

void ScanTCPSocket::print(){
    for (const auto& [key, value] : scan_results){
        std::cout << key << std::endl;
        for(const auto& element: value){
            std::cout << "\t" << element.port<< "\t" << Helpers::resolve_port_status(element.status_port) << "\t" << Helpers::resolve_receive_status(element.status_receive) << std::endl;
        }
    }
}
void ScanTCPSocket::assign_target_port(unsigned short port){
    assign_target_port(port, port);
}