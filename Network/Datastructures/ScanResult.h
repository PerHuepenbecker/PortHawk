//
// Created by Per Hüpenbecker on 12.03.25.
//

#ifndef DOORSCAN_SCANRESULT_H
#define DOORSCAN_SCANRESULT_H

#include "../../Helpers/Helpers.h"
#include "../PortStatus.h"

typedef struct{
    in_port_t port;
    PortStatus status;
} ScanResult;


#endif //DOORSCAN_SCANRESULT_H
