//
// Created by Per Hüpenbecker on 12.03.25.
//

#ifndef DOORSCAN_PCAPRECEIVER_H
#define DOORSCAN_PCAPRECEIVER_H

#include "../../Helpers/helpers.h"
#include "../../Datastructures/RawScanResult.h"
#include "../../Datastructures/ScanResult.h"
#include "../../Datastructures/ThreadSafeQueue.h"

class PcapReceiver {
private:
    pcap_t* pcap_handler;
    std::thread capture_thread;
    std::atomic<bool> running;
    std::mutex results_mutex;
    std::shared_ptr<ThreadSafeQueue<RawScanResult>> raw_queue_ptr;

    bool debug_mode = false;

    size_t received_packets = 0;

    std::map<std::string, std::vector<ScanResult>> scan_results;

    // Example: "host 192.168.0.1 or host 127.0.0.1" for ip-based filtering on multiple hosts
    std::string filtering_rule;
    in_port_t _source_port;

    std::array<char, INET6_ADDRSTRLEN> address_buffer;

    void capture_loop();

    static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

    void process_packet(const struct pcap_pkthdr* header, const u_char* packet);

public:
    explicit PcapReceiver(std::string filtering_rule = "", bool debug = false);
    ~PcapReceiver();

    bool start(ConnectionInfo& connection_info);
    void stop();
    void register_target(const std::string& target_ip);

    void set_raw_queue(std::shared_ptr<ThreadSafeQueue<RawScanResult>> raw_queue);
    void set_source_port(in_port_t source_port);
    void set_debug(bool value){
        debug_mode = value;
    }

    std::vector<ScanResult> get_results(const std::string& target_ip);
};


#endif //DOORSCAN_PCAPRECEIVER_H
