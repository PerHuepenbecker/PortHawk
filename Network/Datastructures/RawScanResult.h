//
// Created by Per Hüpenbecker on 13.03.25.
//

#ifndef DOORSCAN_RAWSCANRESULT_H
#define DOORSCAN_RAWSCANRESULT_H

#include "../../Helpers/helpers.h"

typedef struct{

    struct in_addr source_ip;
    in_port_t sourcePort;
    uint8_t protocol;
    uint8_t tcp_flags;

} RawScanResult;

#endif //DOORSCAN_RAWSCANRESULT_H
