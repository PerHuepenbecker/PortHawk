//
// Created by Per Hüpenbecker on 12.03.25.
//

#include "PcapReceiver.h"

void PcapReceiver::capture_loop() {
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

    std::cout<< "Packet received!" << std::endl;

    std::lock_guard<std::mutex> lock(results_mutex);
}

PcapReceiver::PcapReceiver(in_port_t source_port):source_port(source_port) {}

PcapReceiver::~PcapReceiver() {
    stop();
}

bool PcapReceiver::start(const std::string& interface){
    if (running) return true;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handler = pcap_open_live(interface.c_str(), BUFSIZ, 1, 100, errbuf);

    if(!pcap_handler){
        std::cerr << "Failed to open pcap_handler" << std::endl;
        return false;
    }

    std::string filter = "tcp and dst port " + std::to_string(source_port);

    struct bpf_program fp;
    if(pcap_compile(pcap_handler, &fp, filter.c_str(), 0, INADDR_ANY) == -1){
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
}

void PcapReceiver::register_target(const std::string& target_ip){
    std::lock_guard<std::mutex>lock(results_mutex);
    scan_results.insert({target_ip, {}});
}

std::vector<ScanResult> PcapReceiver::get_results(const std::string& target_ip){
    return scan_results[target_ip];
}




