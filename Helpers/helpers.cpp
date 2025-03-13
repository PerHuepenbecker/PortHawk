//
// Created by Per Hüpenbecker on 11.03.25.
//

#include "helpers.h"

// *b: buffer for checksum || len: length of buffer
unsigned short Helpers::ip_checksum(void *b, int len){
    auto *buf = (unsigned short*) b;
    unsigned int sum = 0;

    for (sum = 0; len>1; len -= 2){
        sum += *buf++;
    }

    // if len is odd it means that theres a single byte left which would
    // not be included in the checksum calculation on the 16 Bit / 2 Byte blocks
    // so we add it as a remainder to the sum

    if (len == 1){
        sum += *(unsigned char*) buf;
    }

    // adding the carry to the sum (if there is any) to get the 16 Bit checksum

    sum = (sum>>16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // returning the 1's complement of the sum
    unsigned short result = ~sum;
    return result;
}

unsigned short Helpers::tcp_checksum(struct ip* ip_header, struct tcphdr* tcp_header, std::vector<uint8_t>& payload){
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_len;
    } pseudo_header;

    tcp_header->th_sum = 0;

    pseudo_header.src_addr = ip_header->ip_src.s_addr;
    pseudo_header.dst_addr = ip_header->ip_dst.s_addr;
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_len = htons(sizeof(struct tcphdr) + payload.size());

    unsigned short total_len = sizeof(pseudo_header) + sizeof(struct tcphdr) + payload.size();
    std::vector<uint8_t> buffer(total_len);

    auto pseudo_header_pointer = reinterpret_cast<const uint8_t*>(&pseudo_header);
    std::copy(pseudo_header_pointer, pseudo_header_pointer+(sizeof(pseudo_header)), buffer.begin());

    auto tcp_header_pointer = reinterpret_cast<const uint8_t*> (tcp_header);
    std::copy(tcp_header_pointer, tcp_header_pointer+(sizeof(struct tcphdr)), buffer.begin()+ sizeof(pseudo_header));

    if(payload.empty()){
       std::cout << "TCP Checksum without payload" << std::endl;
    }

    if (!payload.empty()){

        std::cout << "TCP Checksum with payload" << std::endl;
        std::cout << "Payload size: " << payload.size() << std::endl;

        std::copy(payload.begin(), payload.end(), buffer.begin() + sizeof(pseudo_header) + sizeof(struct tcphdr));
    }

    unsigned short checksum = ip_checksum(buffer.data(), total_len);

    return checksum;
}

std::string Helpers::get_local_ip(){
    struct ifaddrs *ifaddr, *ifa;
    std::string ip_address;

    if(getifaddrs(&ifaddr) == -1){
        return "";
    }

    for(ifa = ifaddr; ifa!= nullptr; ifa = ifa->ifa_next){
        if(ifa->ifa_addr == nullptr) continue;

        if(ifa -> ifa_addr ->sa_family == AF_INET){
            std::cout << ifa->ifa_name << std::endl;
            if(strcmp(ifa->ifa_name, "lo0") != 0) {
                char host[INET_ADDRSTRLEN];
                struct sockaddr_in *addr = (struct sockaddr_in*) ifa->ifa_addr;
                inet_ntop(AF_INET, &(addr->sin_addr), host, INET_ADDRSTRLEN);
                ip_address = host;
                break;
            }
        }
    }
    freeifaddrs(ifaddr);
    return ip_address;
}

std::string Helpers::resolve_receive_status(ReceiveStatus status){
    switch (status){
        case OK:
            return "ok";
        case TIMEOUT:
            return "timeout";
        case ERROR:
            return "error";
        default:
            return "-";
    }
}

std::string Helpers::resolve_port_status(PortStatus status){
    switch (status){
        case OPEN:
            return "open";
        case CLOSED:
            return "closed";
        case FILTERED:
            return "filtered";
        case UNKNOWN:
            return "unknown";
        default:
            return "-";
    }
}

size_t get_tcp_header_length(const struct tcphdr* tcp_header){
    return (tcp_header->th_off * 4);
}