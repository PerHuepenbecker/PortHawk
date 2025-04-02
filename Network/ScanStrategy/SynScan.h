//
// Created by Per Hüpenbecker on 11.03.25.
//

#ifndef DOORSCAN_SYNSCAN_H
#define DOORSCAN_SYNSCAN_H

#include "ScanStrategy.h"


class SynScan: public ScanStrategy {
public:
    [[nodiscard]] std::vector<uint8_t> build_packet(PacketBuilder& packetBuilder, const std::string &target, uint16_t port) override;
    std::pair<std::string, ScanResult> interpret_response(RawScanResult&& rawScan) override;
    virtual ProtocolType get_protocol_type() const override;
};



#endif //DOORSCAN_SYNSCAN_H
