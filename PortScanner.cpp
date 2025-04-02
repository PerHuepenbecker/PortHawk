//
// Created by Per Hüpenbecker on 13.03.25.
//

#include "PortScanner.h"

PortScanner::PortScanner(ScanTypes scan_type, in_port_t source_port, bool debug) {
    source_port_ = source_port;

    raw_queue = std::make_shared<ThreadSafeQueue<RawScanResult>>();

    pcap_receiver.set_debug(debug);
    pcap_receiver.set_raw_queue(raw_queue);
    pcap_receiver.set_source_port(source_port_);

    debug_mode = debug;

    connectionInfo_ = Helpers::get_connection_info();

    // Set the chosen scan type based on the supplied ScanTypes enum in the constructor
    switch (scan_type){
        case TCP_SYN:
            scan_strategy = std::make_shared<SynScan>();
            break;
        default:
            std::stringstream ss;
            throw std::invalid_argument("Unsupported Scan type for PortScanner construction supplied");
    }
}

PortScanner::~PortScanner(){
    pcap_receiver.stop();
}

void PortScanner::add_target_address(const std::string& address) {
    target_addresses.push_back(address);
}

void PortScanner::add_target_port(in_port_t port) {
    target_ports.push_back(port);
}

// Method that initializes the scanner with the supplied target values.
void PortScanner::initialize(){
    size_t index = 0;
    for(const auto & address: target_addresses){

        scan_sockets.push_back(std::make_unique<ScanTCPSocket>(scan_strategy, connectionInfo_, 0, debug_mode));
        scan_sockets.at(index)->assign_target_address_v4(address);
        pcap_receiver.register_target(address);

        scan_results[address] = std::move(std::make_pair(std::make_unique<std::mutex>(), std::map<in_port_t,ScanResult>{}));

        // Target port specific initialization
        for(const auto port: target_ports){
            // Assignment of the target ports
            scan_sockets.at(index)->assign_target_port(port);
            // Prepopulation of the scan_results map. Since not every sent packet is tracked, only the received
            // packets are being processed as possible CLOSED or OPEN responses. The mutex is not used in this case because the
            // initialization is single thread only.
            scan_results[address].second[port] = ScanResult {.port = port, .status_port = FILTERED};
        }
        index++;
    }
};

void PortScanner::scan() {
    if (target_addresses.empty() || target_ports.empty()) {
        throw std::invalid_argument("Invalid arguments supplied. No address or port specified");
    }
    initialize();
    pcap_receiver.start(connectionInfo_);

    for (size_t i = 0; i < scan_sockets.size(); ++i){
        scan_sockets.at(i).get()->scan();
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
    pcap_receiver.stop();
}

void PortScanner::debug_output(){
    RawScanResult tmp{};

    std::array<char, INET6_ADDRSTRLEN> address_buffer{};
    while(raw_queue->try_pop(tmp)){
        if(!inet_ntop(AF_INET, &tmp.source_ip, address_buffer.data(), INET_ADDRSTRLEN)){
            continue;
        }
        std::cout << address_buffer.data() << " : " << ntohs(tmp.sourcePort) << "\n";
    }

};