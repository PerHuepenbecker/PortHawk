//
// Created by Per Hüpenbecker on 12.03.25.
//

#ifndef DOORSCAN_PCAPRECEIVER_H
#define DOORSCAN_PCAPRECEIVER_H

#include "../../Helpers/helpers.h"
#include "../Datastructures/ScanResult.h"

class PcapReceiver {
private:
    pcap_t* pcap_handler;
    std::thread capture_thread;
    std::atomic<bool> running;
    std::mutex results_mutex;

    std::map<std::string, std::vector<ScanResult>> scan_results;
    uint16_t source_port;

    void capture_loop();

    static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

    void process_packet(const struct pcap_pkthdr* header, const u_char* packet);

public:
    PcapReceiver(in_port_t source_port);
    ~PcapReceiver();

    bool start(const std::string& interface = "lo0");
    void stop();
    void register_target(const std::string& target_ip);

    std::vector<ScanResult> get_results(const std::string& target_ip);
};


#endif //DOORSCAN_PCAPRECEIVER_H
