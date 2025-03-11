//
// Created by Per Hüpenbecker on 11.03.25.
//


// *b: buffer for checksum || len: length of buffer
unsigned short ip_checksum(void *b, int len){
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

