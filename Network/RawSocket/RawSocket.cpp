//
// Created by Per Hüpenbecker on 12.03.25.
//

#include "RawSocket.h"

RawSocket::RawSocket():socket_fd(-1),is_open(false) {}

RawSocket::~RawSocket() {
    if(is_open){
        close(socket_fd);
    }
}

bool RawSocket::open(int protocol) {
    // Socket setup as a raw socket
    socket_fd = socket(AF_INET, SOCK_RAW, protocol);

    // Check if socket initialization successful
    if(socket_fd < 0){
        std::cerr << "[RawSocket::open] Failed to create raw socket. Are you running as root?" << std::endl;
        return false;
    }

    int one;
    if(setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        close(socket_fd);
        std::cerr << "[RawSocket::open] Failed to set up IP_HDRINCL socket option" << std::endl;
        return false;
    }

    is_open = true;
    return true;
}

