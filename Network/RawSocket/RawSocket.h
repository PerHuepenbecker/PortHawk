//
// Created by Per Hüpenbecker on 12.03.25.
//

#ifndef DOORSCAN_RAWSOCKET_H
#define DOORSCAN_RAWSOCKET_H


#include "../../Helpers/Helpers.h"

class RawSocket {
private:
    int socket_fd;
    bool is_open;

public:
    RawSocket();
    ~RawSocket();

    bool open(int protocol = IPPROTO_RAW);
    bool send_packet(const std::vector<uint8_t> &packet, const std::string& destination_ip);
};


#endif //DOORSCAN_RAWSOCKET_H
