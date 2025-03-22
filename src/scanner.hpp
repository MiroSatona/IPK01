#ifndef SCANNER_HPP
#define SCANNER_HPP // SCANNER_HPP

#include <iostream>
#include "scanner_params.hpp"
class Scanner{
    public:
        virtual void scan() = 0;
        Scanner(ScannerParams scanParams);
    protected:
        unsigned short calculateChecksum(const char* pdu, size_t dataLen);
        int createSocket(int ipvType, int protocol);
        void closeSocket(int fdSock);
        ScannerParams scanParams;

};
    
class TcpIpv4Scanner : public Scanner {
public:
    TcpIpv4Scanner(const ScannerParams& params) : Scanner(params) {}
    void scan() override;
};

class TcpIpv6Scanner : public Scanner {
public:
    TcpIpv6Scanner(const ScannerParams& params) : Scanner(params) {}
    void scan() override;
};

class UdpIpv4Scanner : public Scanner {
public:
    UdpIpv4Scanner(const ScannerParams& params) : Scanner(params) {}
    void scan() override;
};

class UdpIpv6Scanner : public Scanner {
public:
    UdpIpv6Scanner(const ScannerParams& params) : Scanner(params) {}
    void scan() override;
};
    
#endif // SCANNER_HPP
