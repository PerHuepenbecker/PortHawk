//
// Created by Per Hüpenbecker on 11.03.25.
//

#ifndef DOORSCAN_SCANSTRATEGY_H
#define DOORSCAN_SCANSTRATEGY_H

#include <vector>
#include "../PacketBuilder.h"
#include "../../Helpers/PortStatus.h"
#include "../../Datastructures/ScanResult.h"
#include "../../Datastructures/RawScanResult.h"
#include "../ProtocolType.h"

class ScanStrategy {
public:
    virtual ~ScanStrategy() = default;
    [[nodiscard]] virtual std::vector<uint8_t> build_packet(PacketBuilder& packet_builder, const std::string &target, uint16_t port) = 0;
    virtual std::pair<std::string, ScanResult>  interpret_response(RawScanResult&& rawScan) = 0;
    virtual ProtocolType get_protocol_type() const = 0;
};


#endif //DOORSCAN_SCANSTRATEGY_H
