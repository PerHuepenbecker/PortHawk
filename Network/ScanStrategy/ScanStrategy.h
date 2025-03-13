//
// Created by Per Hüpenbecker on 11.03.25.
//

#ifndef DOORSCAN_SCANSTRATEGY_H
#define DOORSCAN_SCANSTRATEGY_H

#include <vector>
#include "../PacketBuilder.h"
#include "../../Helpers/PortStatus.h"
#include "../Datastructures/ScanResult.h"

class ScanStrategy {
public:
    virtual ~ScanStrategy() = default;
    [[nodiscard]] virtual std::vector<uint8_t> build_packet(PacketBuilder& packet_builder, const std::string &target, uint16_t port) = 0;
    virtual ScanResult interpret_response(const std::vector<uint8_t> &response_packet, ReceiveStatus status,in_port_t target_port) = 0;
};


#endif //DOORSCAN_SCANSTRATEGY_H
