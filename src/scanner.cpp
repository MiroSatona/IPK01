#include "scanner.hpp"
#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>



unsigned short Scanner::calculateChecksum(const char* pdu, size_t dataLen) {
    unsigned long checksum = 0;
    size_t offset = 0;

    while (offset < dataLen-1){
        checksum += *(unsigned short *)&pdu[offset];
        offset += 2;
    }

    if (dataLen%2) checksum += (unsigned char) pdu[offset];
    while (checksum >> 16) checksum = (checksum & 0xFFFF) + (checksum >> 16);

    return (unsigned short) ~checksum;
}


int Scanner::createSocket(int ipvType, int protocol) {
    int fdSock = socket(ipvType, SOCK_RAW, protocol);
    if (fdSock == -1) throw std::runtime_error("Could not create socket!");
    return fdSock;
}

void Scanner::closeSocket(int fdSock) {
    close(fdSock);
}