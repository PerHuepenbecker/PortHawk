//
// Created by Per Hüpenbecker on 12.03.25.
//

#include "RawSocket.h"

RawSocket::RawSocket():socket_fd_send(-1), socket_fd_receive(-1) ,is_open(false) {}

RawSocket::~RawSocket() {
    if(is_open){
        close(socket_fd_send);
    }
}

bool RawSocket::open_raw_socket(int protocol) {
    // Socket setup as a raw socket
    socket_fd_send = socket(AF_INET, SOCK_RAW, protocol);


    // Check if socket initialization successful
    if(socket_fd_send < 0){
        std::cerr << "[RawSocket::open] Failed to create raw socket. Are you running as root?" << std::endl;
        return false;
    }

    int one = 1;
    if(setsockopt(socket_fd_send, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        close(socket_fd_send);
        std::cerr << "[RawSocket::open] Failed to set up IP_HDRINCL socket option" << std::endl;
        return false;
    }

    is_open = true;
    return true;
}

ReceiveStatus RawSocket::receive_packet(std::vector<uint8_t> &response_buffer, ssize_t &response_size, unsigned short timeout_ms) {
    if(!is_open){
        std::cerr << "Closes socket cannot receive any network data" << std::endl;
        return ERROR;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms /1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if(setsockopt(socket_fd_send, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv)) < 0){
        std::cerr << "Failed to set timeout option on the socket" << std::endl;
        return ERROR;
    }

    struct sockaddr_in source{};
    socklen_t source_len = sizeof(source);

    response_size = recvfrom(socket_fd_send, response_buffer.data(), response_buffer.size(), 0, (sockaddr*)&source, &source_len);

    std::cout << "Received " << response_size << " Bytes" << std::endl;

    if(response_size < 0){

        // EAGAIN (Resource temporarily unavailable)
        // EWOULDBLOCK (Socket has no data available yet)
        // Checks for the timeout.

        if(errno == EAGAIN || errno == EWOULDBLOCK){
            response_buffer.clear();
            response_size = 0;
            return TIMEOUT;
        }

        // Checks for an actual error

        std::cerr << "Error receiving packet: " << strerror(errno) << std::endl;
        response_size = 0;
        response_buffer.clear();
        return ERROR;
    }

    return OK;
}

bool RawSocket::send_packet(const std::vector<uint8_t> &packet, const std::string &destination_ip) const {

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;

    if(inet_pton(AF_INET, destination_ip.c_str(), &dest.sin_addr) != 1){
        std::cerr << "Error sending packet: Invalid IP address" << std::endl;
        return false;
    }

    dest.sin_port = 0;
    ssize_t bytes_sent = sendto(socket_fd_send, packet.data(), packet.size(), 0, (struct sockaddr*)&dest, sizeof(dest));

    if(bytes_sent <= 0){
        std::cerr << "[RawSocket::send] Failed to send packet with size: " << packet.size() << std::endl;
        std::cerr << " - Error: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        return false;
    }

    if (static_cast<size_t>(bytes_sent) != packet.size()){
        std::cerr<< "Incomplete packet sent" << std::endl;
        return false;
    }


    std::cout<< "Sent!" << std::endl;

    return true;
}

bool RawSocket::close_raw_socket() {
    close(socket_fd_send);
    return true;
}