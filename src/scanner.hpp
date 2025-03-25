#ifndef SCANNER_HPP
#define SCANNER_HPP // SCANNER_HPP

#include <iostream>
#include "scanner_params.hpp"

#define MAX_RETRIES 2
#define MAX_BUFFER_SIZE 4096
#define MAX_EVENTS 1024
#define DEFAULT_SOURCE_PORT 50000
#define MAX_SOURCE_PORT 60000
class Scanner{
    public:
        Scanner(const ScannerParams &scanParams);
        virtual void scan() = 0;
    protected:
        unsigned short calculateChecksum(const char* pdu, size_t dataLen);
        int createSocket(int ipvType, int protocol);
        int createEpoll();
        void closeSocket(int fdSock);
        void closeEpoll(int epollFd);
        ScannerParams scanParams;

};
    
class TcpIpv4Scanner : public Scanner {
public:
    TcpIpv4Scanner(const ScannerParams& params);
    void scan() override;
};

class TcpIpv6Scanner : public Scanner {
public:
    TcpIpv6Scanner(const ScannerParams& params);
    void scan() override;
};

class UdpIpv4Scanner : public Scanner {
public:
    UdpIpv4Scanner(const ScannerParams& params);
    void scan() override;
};

class UdpIpv6Scanner : public Scanner {
public:
    UdpIpv6Scanner(const ScannerParams& params);
    void scan() override;
};

#endif // SCANNER_HPP
