//
// Created by Per Hüpenbecker on 12.03.25.
//

#ifndef DOORSCAN_RAWSOCKET_H
#define DOORSCAN_RAWSOCKET_H


#include "../../Helpers/helpers.h"



class RawSocket {
private:
    char errbuf[PCAP_ERRBUF_SIZE];
    int socket_fd_send;
    int socket_fd_receive;
    pcap_t* pcap_handle = nullptr;
    bool is_open;



public:
    RawSocket();
    ~RawSocket();

    bool open_raw_socket(int protocol = IPPROTO_RAW);
    bool pcap_receive(const std::string &filter_expression, uint32_t timeout = 2000);
    bool close_raw_socket();
    bool send_packet(const std::vector<uint8_t> &packet, const std::string& destination_ip) const;
    ReceiveStatus receive_packet(std::vector<uint8_t>& response_buffer, ssize_t& response_size, unsigned short timeout_ms=2000) const;
};

static void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char* packet);


#endif //DOORSCAN_RAWSOCKET_H
