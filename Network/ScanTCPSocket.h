//
// Created by Per Hüpenbecker on 11.03.25.
//

#ifndef DOORSCAN_SCANTCPSOCKET_H
#define DOORSCAN_SCANTCPSOCKET_H

#include "ScanStrategy/SynScan.h"
#include "PacketBuilder.h"
#include "RawSocket/RawSocket.h"

#include <unordered_map>

class ScanTCPSocket {
private:
    // RawSocket object that wraps the send and receive functions for the ScanTCPSocket
    RawSocket socket_;

    std::unique_ptr<PacketBuilder> packet_builder_;
    std::shared_ptr<ScanStrategy> scan_strategy_;

    // Local buffer to store the crafted packets. Taken out of the build packet method and placed
    // as an attribute here to avoid frequent expensive and unnecessary reallocations. They are being
    // preallocated in the constructor to house the maximum size of an ethernet packet.

    std::vector<uint8_t> packet_buffer_;

    std::string source_ip_;
    in_port_t source_port_;
    bool debug_mode;

    std::string target_IPv4;
    //std::vector<std::string> target_list_IPv6; => After base functionality for IPv4 is implemented

    std::vector<unsigned short> target_list_ports_;

public:
    ScanTCPSocket(std::shared_ptr<ScanStrategy> scan_strategy,ConnectionInfo& info, in_port_t source_port = 0, bool debug = false);
    ~ScanTCPSocket() = default;

    bool scan();

    void assign_target_address_v4(std::string target);
    void assign_target_port(unsigned short first, unsigned short last);
    void assign_target_port(unsigned short port);
    void set_scan_strategy(std::shared_ptr<ScanStrategy> strategy);
};


#endif //DOORSCAN_SCANTCPSOCKET_H
