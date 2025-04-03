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

        scan_sockets.push_back(std::make_unique<ScanTCPSocket>(scan_strategy, connectionInfo_, source_port_, debug_mode));
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

    running = true;

    // Setting up the result_worker_threads container for handling of the responses. Standard are currently two result
    // workers that collect raw scan results ready for further processing. This design follows a Producer-Consumer pattern.
    // Future plan is to make the thread count configurable.
    for(size_t i = 0; i < 2; ++i) {

        result_worker_threads.emplace_back([this]() {
            RawScanResult raw;
            unsigned int pause = 10;

            while (running) {

                bool available = raw_queue->try_pop(raw);

                // Avoid constant polling if no data is available
                if (!available) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(pause));
                    // Continue statement to check after the sleep if the port scan is still running
                    continue;
                }

                auto res = scan_strategy->interpret_response(std::move(raw));

                // Thread synchronization via std::lock_guard on the inner map of the scan_results map
                auto mutex = scan_results[res.first].first.get();
                std::lock_guard<std::mutex> lock(*mutex);

                // Assignment of the scan result to the corresponding container element
                scan_results[res.first].second[res.second.port] = res.second;
            }
        });
    }

    for (size_t i = 0; i < scan_sockets.size(); ++i){
        scan_sockets.at(i).get()->scan();
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
    pcap_receiver.stop();
    running = false;

    for(auto &thread: result_worker_threads){
        if (thread.joinable()){
            thread.join();
        }
    }

    display_results();
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

// Method to display the prot scan results. Current default behavior is that only the open ports are being printed to avoid
// unnecessarily verbose output. Remaining ports will be counted as CLOSED or FILTERED.
void PortScanner::display_results(){
    size_t closed_ports{};
    size_t filtered_ports{};
    size_t unknown_ports{};

    auto port_display_lambda = [](size_t count){
        return (count == 1)? "port" : "ports";
    };

    std::cout << "\n-- Scan Results --" << "\n";
    for(const auto & element: scan_results){
        closed_ports = 0; filtered_ports = 0; unknown_ports = 0;
        std::cout << "+++++++++++++++++++++++++++++++++++++\n";
        std::cout << "Address: " << element.first << "\n";
        std::cout << "Ports: \n";

        for(const auto& result: element.second.second){
            auto status = result.second.status_port;
            switch (status){
                case OPEN:
                    std::cout << "  " << result.second.port << "  " << Helpers::resolve_port_status(status) << "\n";
                    break;
                case CLOSED:
                    closed_ports++;
                    break;
                case FILTERED:
                    filtered_ports++;
                    break;
                default:
                    unknown_ports++;
            }
        }

        std::cout << "-------------------------------------\n";
        std::cout << closed_ports <<" " << port_display_lambda(closed_ports)<< " closed \n";
        std::cout << filtered_ports << " " << port_display_lambda(filtered_ports) << " filtered" << "\n";
        if(unknown_ports > 0) {
            std::cout << unknown_ports << " ports with unknown status. Possible malformed responses" << "\n";
        }
        std::cout << "+++++++++++++++++++++++++++++++++++++\n";
    }
}