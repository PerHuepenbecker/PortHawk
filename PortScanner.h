//
// Created by Per Hüpenbecker on 13.03.25.
//

#ifndef DOORSCAN_PORTSCANNER_H
#define DOORSCAN_PORTSCANNER_H

#include <sstream>
#include "Network/Datastructures/ThreadSafeQueue.h"
#include "Network/Datastructures/RawScanResult.h"
#include "Network/Datastructures/ScanResult.h"
#include "Network/PcapReceiver/PcapReceiver.h"
#include "Network/RawSocket/RawSocket.h"
#include "Network/ScanStrategy/ScanTypes.h"
#include "Network/ScanTCPSocket.h"
#include "Network/ScanStrategy/SynScan.h"


// Central PortScanner object that will be the base for the application
class PortScanner {

private:
    std::shared_ptr<ThreadSafeQueue<RawScanResult>> raw_queue;

    PcapReceiver pcap_receiver;
    std::shared_ptr<ScanStrategy> scan_strategy;

    std::vector<std::thread> result_worker_threads;
    std::vector<std::unique_ptr<ScanTCPSocket>> scan_sockets;
    std::atomic<bool> running = false;
    bool debug_mode;

    std::mutex results_mutex;

    // Container for storing the scan results for each scanned ip address. The mutex is necessary since the
    // container will be filled by the concurrent result_worker_threads.
    std::map<std::string, std::pair<std::unique_ptr<std::mutex>,std::map<in_port_t,ScanResult>>> scan_results;

    std::vector<std::string> target_addresses;
    std::vector<in_port_t> target_ports;

    ConnectionInfo connectionInfo_;
    in_port_t source_port_;

    void initialize();

public:

    explicit PortScanner(ScanTypes scan_type = TCP_SYN, in_port_t source_port = 0, bool debug = false);
    ~PortScanner();

    void add_target_address(const std::string& address);
    void add_target_port(in_port_t port);

    void scan();
    void display_results();

    void debug_output();
};


#endif //DOORSCAN_PORTSCANNER_H
