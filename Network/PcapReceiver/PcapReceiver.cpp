//
// Created by Per Hüpenbecker on 12.03.25.
//

#include "PcapReceiver.h"
#include <iostream>
#include <iomanip>

void PcapReceiver::capture_loop() {
    if(debug_mode){
        std::cout << "[PcapReceiver::capture_loop] Capture loop started" << std::endl;
    }

    while(running){
        pcap_dispatch(pcap_handler, 10, packet_handler, reinterpret_cast<u_char*>(this));

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void PcapReceiver::packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet){

    auto* receiver = reinterpret_cast<PcapReceiver*>(user);
    receiver->process_packet(header, packet);
}

void PcapReceiver::process_packet(const struct pcap_pkthdr *header, const u_char *packet) {

    if(debug_mode){
        std::cout << "[PcapReceiver::process_packet] Packet captured" << std::endl;
    }

    received_packets ++;

    const tcphdr* tcp_header = nullptr;
    const ip* ip_header = nullptr;

    size_t ip_header_offset = 0;
    bool ipv4 = false;

    int linktype = pcap_datalink(pcap_handler);

    if(linktype == DLT_EN10MB){
        auto ethernet_header = reinterpret_cast<const struct ether_header*>(packet);
        ip_header_offset = sizeof(struct ether_header);
        if(ntohs(ethernet_header->ether_type) != 0x0800){
            if(debug_mode){
                std::cout << "[PcapReceiver::process_packet] Not an IPv4 packet" << std::endl;
                std::cout << "[PcapReceiver::process_packet] Packet type: 0x" << std::hex << ntohs(ethernet_header->ether_type) << std::dec << std::endl;
            }
        } else{
            ipv4 = true;
        }
    }

    else if(linktype == DLT_NULL || linktype == DLT_LOOP){
        // Since the first 4 bytes contain the address family
        uint32_t family = *reinterpret_cast<const uint32_t*>(packet);
        if(family == 2 || family == 0x02000000){
            ipv4 = true;
            ip_header_offset = 4;
        }
        else{
            if(debug_mode){
                std::cout << "[PcapReceiver::process_packet] Not an IPv4 packet" << std::endl;
                std::cout << "[PcapReceiver::process_packet] Packet type: 0x" << std::hex << family << std::dec << std::endl;
            }
            return;
        }
    } else{
        std::cerr << "Currently unsupported linktype" << std::endl;
        return;
    }

    // If captured packet is no IPv4 packet, skip further processing, because it's not relevant for
    // current feature set

    ip_header = reinterpret_cast<const struct ip*>(packet + ip_header_offset);

    switch(ip_header->ip_p){
        case 0x06:
            tcp_header = reinterpret_cast<const struct tcphdr*>(packet + sizeof(struct ether_header) + sizeof(struct ip));
            break;
        case 0x1:
            // Implement ICMP detection for UDP port scanning in the future
            break;
        default:
            std::cout << "[PcapReceiver::process_packet] Unknown protocol type" << std::endl;
            std::cout << "[PcapReceiver::process_packet] Protocol type: " << ntohs(ip_header->ip_p) << std::endl;



            for (const u_int8_t* i = packet+ip_header_offset; i < packet+ip_header_offset+sizeof(ip); i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(*i) << " ";
            }

            return;
    }

    if (!inet_ntop(AF_INET, &(ip_header->ip_src), address_buffer.data(), INET_ADDRSTRLEN)){
        std::cerr << "Address resolution failed" << std::endl;
        return;
    };

    tcp_header = reinterpret_cast<const struct tcphdr*>(packet + ip_header_offset + sizeof(struct ip));

    std::cout << "Response from address " << address_buffer.data() << std::endl;


    if(tcp_header == nullptr){
        std::cout << "TCP Header == NULL";
    } else{
        std::cout << "TCP header flags: 0x" << std::hex << (int)tcp_header->th_flags << std::dec << std::endl;
        std::cout << "Source port: " << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "Dest port: " << ntohs(tcp_header->th_dport) << std::endl;
    }

}

PcapReceiver::PcapReceiver(const std::string filtering_rule, bool debug):filtering_rule(filtering_rule), debug_mode(debug) {}

PcapReceiver::~PcapReceiver() {
    stop();
}

bool PcapReceiver::start(const std::string& interface){
    if (running) return true;

    if (interface.empty()){
        std::cerr << "No interface specified" << std::endl;
        return false;
    }

    if (filtering_rule.empty()){
        std::cerr << "No filtering rule specified" << std::endl;
        return false;
    }

    if(_source_port == 0){
        std::cerr << "No source port specified" << std::endl;
        return false;
    }

    if (debug_mode){
        std::cout << "------------------------------------------------" << std::endl;
        std::cout << "[PcapReceiver::start] Starting pcap receiver on interface: " << interface << std::endl;
        std::cout << "[PcapReceiver::start] Filtering rule: " << filtering_rule << std::endl;
        std::cout << "------------------------------------------------" << std::endl;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handler = pcap_open_live(interface.c_str(), BUFSIZ, 1, 100, errbuf);

    if(!pcap_handler){
        std::cerr << "Failed to open pcap_handler" << std::endl;
        return false;
    }

    //std::string filter = "host " + filtering_rule;

    std::cout << "Source port: " << _source_port << std::endl;
    filtering_rule = "dst port " + std::to_string(_source_port);
    std::cout << "Filtering rule: " << filtering_rule << std::endl;

    struct bpf_program fp;
    if(pcap_compile(pcap_handler, &fp, filtering_rule.c_str(), 0, INADDR_ANY) == -1){
        std::cerr << "Failed to compile filter" << std::endl;
        pcap_close(pcap_handler);
        return false;
    }

    if(pcap_setfilter(pcap_handler, &fp) == -1) {
        std::cerr << "Failed to set filter" << std::endl;
        pcap_close(pcap_handler);
        return false;
    }

    running = true;
    capture_thread = std::thread(&PcapReceiver::capture_loop, this);

    if (debug_mode){
        std::cout << "[PcapReceiver::start] Capture thread started" << std::endl;
    }

    return true;
}

void PcapReceiver::stop(){

    running = false;
    if(capture_thread.joinable()){
        capture_thread.join();
    }

    if(pcap_handler){
        pcap_close(pcap_handler);
        pcap_handler = nullptr;
    }

    if (debug_mode){
        std::cout << "[PcapReceiver::stop] Capture thread stopped" << std::endl;
        std::cout << "[PcapReceiver::stop] Collected "<< received_packets << " packets" << std::endl;
    }
}


// Method for target registration so that the results can be filtered by target ips even if
// multiple addresses are getting scanned simultaneously

void PcapReceiver::register_target(const std::string& target_ip){
    std::lock_guard<std::mutex>lock(results_mutex);
    scan_results.insert({target_ip, {}});
    if (filtering_rule.empty()){
        filtering_rule += "src host ";
        filtering_rule += target_ip;
    } else {
        filtering_rule += " or src host ";
        filtering_rule += "target_ip";
    }

    if (debug_mode){
        std::cout << "[PcapReceiver::register_target] Target registered: " << target_ip << std::endl;
    }
}

std::vector<ScanResult> PcapReceiver::get_results(const std::string& target_ip){
    return scan_results[target_ip];
}

void PcapReceiver::set_source_port(in_port_t source_port) {
    _source_port = source_port;
}
