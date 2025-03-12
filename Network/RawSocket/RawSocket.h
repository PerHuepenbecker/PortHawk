//
// Created by Per Hüpenbecker on 12.03.25.
//

#ifndef DOORSCAN_RAWSOCKET_H
#define DOORSCAN_RAWSOCKET_H


#include "../../Helpers/helpers.h"



class RawSocket {
private:
    int socket_fd_send;
    int socket_fd_receive;
    bool is_open;

public:
    RawSocket();
    ~RawSocket();

    bool open_raw_socket(int protocol = IPPROTO_RAW);
    bool close_raw_socket();
    bool send_packet(const std::vector<uint8_t> &packet, const std::string& destination_ip) const;
    ReceiveStatus receive_packet(std::vector<uint8_t>& response_buffer, ssize_t& response_size, unsigned short timeout_ms=2000);
};


#endif //DOORSCAN_RAWSOCKET_H
