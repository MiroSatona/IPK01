#include "scanner.hpp"
#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <chrono>
#include <netinet/ip6.h> 



Scanner::Scanner(const ScannerParams& scanParams) : scanParams(scanParams) {}
TcpIpv4Scanner::TcpIpv4Scanner(const ScannerParams& params): Scanner(params) {}
TcpIpv6Scanner::TcpIpv6Scanner(const ScannerParams& params): Scanner(params) {}
/* 
UdpIpv4Scanner::UdpIpv4Scanner(const ScannerParams& params): Scanner(params) {}
UdpIpv6Scanner::UdpIpv6Scanner(const ScannerParams& params): Scanner(params) {}
*/


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
    if (fdSock == -1) {
        throw std::runtime_error("Could not create socket!");
    }

    if(setsockopt(fdSock, SOL_SOCKET, SO_BINDTODEVICE, scanParams.getInterfaceName().c_str(), scanParams.getInterfaceName().size())){
        close(fdSock);
        throw std::runtime_error("Could not bind socket to interface!");

    }
    
    return fdSock;
}

int Scanner::createEpoll() {
    int epollFd = epoll_create1(0);
    if (epollFd == -1) {
        throw std::runtime_error("Could not create epoll file descriptor!");
    }

    return epollFd;
}

void Scanner::closeSocket(int fdSock) {
    close(fdSock);
}

void Scanner::closeEpoll(int epollFd) {
    close(epollFd);
}

void TcpIpv4Scanner::scan() {
    int srcPort = 50000;
    int fdSock = this->createSocket(AF_INET, IPPROTO_TCP);
    int epollFd = this->createEpoll();
    
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = fdSock;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fdSock, &ev) == -1) {
        close(fdSock);
        close(epollFd);
        throw std::runtime_error("Could not add socket to epoll!");
    }

    for (std::string dstIpv4 : scanParams.getIp4AddrDest()) {
        for (int port : scanParams.getTcpPorts()) {
            struct tcphdr tcpHeader;
            memset(&tcpHeader, 0, sizeof(tcphdr));
            tcpHeader.th_sport = htons(srcPort);
            tcpHeader.th_dport = htons(port);
            tcpHeader.th_flags = TH_SYN;
            tcpHeader.th_seq = htonl(rand());
            tcpHeader.th_win = htons(65535);
            tcpHeader.th_off = 5;
            tcpHeader.th_ack = 0;
            tcpHeader.th_urp = 0;
            tcpHeader.th_sum = 0;

            if (srcPort < 60000) srcPort++;
            else srcPort = 50000;

            struct checkSumPseudoHdr {
                uint32_t srcAddr;
                uint32_t dstAddr;
                uint8_t zero;
                uint8_t protocol;
                uint16_t tcpLength;
            };

            struct checkSumPseudoHdr pseudoHdr;
            memset(&pseudoHdr, 0, sizeof(struct checkSumPseudoHdr));
            pseudoHdr.srcAddr = inet_addr(scanParams.getInterfaceIpv4().c_str());
            pseudoHdr.dstAddr = inet_addr(dstIpv4.c_str());
            pseudoHdr.protocol = IPPROTO_TCP;
            pseudoHdr.zero = 0;
            pseudoHdr.tcpLength = htons(sizeof(struct tcphdr));

            size_t datagramLength = sizeof(struct tcphdr) + sizeof(struct checkSumPseudoHdr);
            std::vector<char> datagram(datagramLength);
            memcpy(datagram.data(), &pseudoHdr, sizeof(struct checkSumPseudoHdr));
            memcpy(datagram.data() + sizeof(struct checkSumPseudoHdr), &tcpHeader, sizeof(struct tcphdr));
            tcpHeader.th_sum = this->calculateChecksum(datagram.data(), datagramLength);

            struct sockaddr_in dstAddr;
            memset(&dstAddr, 0, sizeof(dstAddr));
            dstAddr.sin_family = AF_INET;
            dstAddr.sin_port = htons(port);
            dstAddr.sin_addr.s_addr = inet_addr(dstIpv4.c_str());

            bool notFiltered = false;
            struct iphdr* ipHeader = nullptr;
            struct tcphdr* tcpResp = nullptr;

            for (int i = 0; i < MAX_RETRIES; i++) {
                if (sendto(fdSock, &tcpHeader, sizeof(struct tcphdr), 0, (struct sockaddr*)&dstAddr, sizeof(dstAddr)) == -1) {
                    close(fdSock);
                    close(epollFd);
                    throw std::runtime_error("Could not send packet!");
                }

                int timeout = scanParams.getTimeout();
                auto startTime = std::chrono::steady_clock::now();

                while (timeout > 0) {
                    int ready = epoll_wait(epollFd, events, MAX_EVENTS, timeout);
                    auto now = std::chrono::steady_clock::now();
                    int delta = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
                    timeout -= delta;
                    startTime = now;

                    if (ready == -1) {
                        std::cerr << "epoll_wait failed!\n";
                        break;
                    } else if (ready == 0) {
                        break; // Timeout
                    }

                    char buffer[MAX_BUFFER_SIZE];
                    struct sockaddr_in recvAddr;
                    socklen_t recvAddrLen = sizeof(recvAddr);
                    int received = recvfrom(fdSock, buffer, sizeof(buffer), 0, (struct sockaddr*)&recvAddr, &recvAddrLen);
                    if (received == -1) continue;

                    ipHeader = (struct iphdr*)buffer;
                    tcpResp = (struct tcphdr*)(buffer + (ipHeader->ihl * 4));

                    if (recvAddr.sin_addr.s_addr == dstAddr.sin_addr.s_addr && ntohs(tcpResp->th_sport) == port) {
                        notFiltered = true;
                        break;
                    }
                }

                if (notFiltered) break;
            }

           
            if (!notFiltered) {
                std::cout << dstIpv4 << " " << port << " " << "tcp filtered" << std::endl;
            } else if (tcpResp && (tcpResp->th_flags & TH_SYN) && (tcpResp->th_flags & TH_ACK)) {
                std::cout << dstIpv4 << " " << port << " " <<"tcp open" << std::endl;
            } else if (tcpResp && (tcpResp->th_flags & TH_RST)) {
                std::cout << dstIpv4 << " " << port << " " << "tcp closed" << std::endl;
            } 
            
        }
    }

    this->closeSocket(fdSock);
    this->closeEpoll(epollFd);
}

//_______________________________________________________________________________________________________________________________
void TcpIpv6Scanner::scan() {
    int srcPort = 50000;
    int fdSock = this->createSocket(AF_INET6, IPPROTO_TCP);
    int epollFd = this->createEpoll();

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = fdSock;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fdSock, &ev) == -1) {
        close(fdSock);
        close(epollFd);
        throw std::runtime_error("Could not add socket to epoll!");
    }

    std::cout << "Interface: " << scanParams.getInterfaceIpv6() << std::endl;

    for (std::string dstIpv6 : scanParams.getIp6AddrDest()) {
        for (int port : scanParams.getTcpPorts()) {
            struct tcphdr tcpHeader;
            memset(&tcpHeader, 0, sizeof(tcphdr));
            tcpHeader.th_sport = htons(srcPort);
            tcpHeader.th_dport = htons(port);
            tcpHeader.th_flags = TH_SYN;
            tcpHeader.th_seq = htonl(rand());
            tcpHeader.th_win = htons(65535);
            tcpHeader.th_off = 5;
            tcpHeader.th_ack = 0;
            tcpHeader.th_urp = 0;
            tcpHeader.th_sum = 0;

            if (srcPort < 60000) srcPort++;
            else srcPort = 50000;

            struct checkSumPseudoHdrIpv6 {
                struct in6_addr src;
                struct in6_addr dst;
                uint32_t length;
                uint8_t zero[3];
                uint8_t next_header;
            };

            struct checkSumPseudoHdrIpv6 pseudoHdr;
            memset(&pseudoHdr, 0, sizeof(pseudoHdr));
            if (inet_pton(AF_INET6, scanParams.getInterfaceIpv6().c_str(), &pseudoHdr.src) != 1) {
                // TODO: Handle error
                continue;
            }
            if (inet_pton(AF_INET6, dstIpv6.c_str(), &pseudoHdr.dst) != 1) {
                //TODO: 
                continue;
            }
            pseudoHdr.length = htonl(sizeof(struct tcphdr));
            pseudoHdr.next_header = IPPROTO_TCP;

            size_t datagramLength = sizeof(struct tcphdr) + sizeof(struct checkSumPseudoHdrIpv6);
            std::vector<char> datagram(datagramLength);
            memcpy(datagram.data(), &pseudoHdr, sizeof(struct checkSumPseudoHdrIpv6));
            memcpy(datagram.data() + sizeof(struct checkSumPseudoHdrIpv6), &tcpHeader, sizeof(struct tcphdr));
            tcpHeader.th_sum = this->calculateChecksum(datagram.data(), datagramLength);

            struct sockaddr_in6 dstAddr;
            memset(&dstAddr, 0, sizeof(dstAddr));
            dstAddr.sin6_family = AF_INET6;
            dstAddr.sin6_port = htons(0);
            if (inet_pton(AF_INET6, dstIpv6.c_str(), &dstAddr.sin6_addr) != 1) {
                //perror("inet_pton (sendto addr) failed"); TODO: Handle error
                continue;
            }
            
            

            bool notFiltered = false;
            struct tcphdr* tcpResp = nullptr;

            for (int i = 0; i < MAX_RETRIES; i++) {
                if (sendto(fdSock, (struct tchphdr*) &tcpHeader, sizeof(struct tcphdr), 0, (struct sockaddr*)&dstAddr, sizeof(dstAddr)) == -1) {
                    //perror("sendto failed"); TODO: Handle error
                    std::cerr << "errno: " << errno << std::endl;
                    continue;
                }

                int timeout = scanParams.getTimeout();
                auto startTime = std::chrono::steady_clock::now();

                while (timeout > 0) {
                    int ready = epoll_wait(epollFd, events, MAX_EVENTS, timeout);
                    auto now = std::chrono::steady_clock::now();
                    int delta = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
                    timeout -= delta;
                    startTime = now;

                    if (ready == -1) {
                        //TODO: Handle error
                        break;
                    } else if (ready == 0) {
                        break; 
                    }

                    char buffer[MAX_BUFFER_SIZE];
                    struct sockaddr_in6 recvAddr;
                    socklen_t recvAddrLen = sizeof(recvAddr);
                    int received = recvfrom(fdSock, buffer, sizeof(buffer), 0, (struct sockaddr*)&recvAddr, &recvAddrLen);
                    if (received == -1) continue;
                    
                    tcpResp = (struct tcphdr*)(buffer); 

                    if (memcmp(&recvAddr.sin6_addr, &dstAddr.sin6_addr, sizeof(in6_addr)) == 0 &&
                        ntohs(tcpResp->th_sport) == port) {
                        notFiltered = true;
                        break;
                    }
                }

                if (notFiltered) break;
            }

            if (!notFiltered) {
                std::cout << dstIpv6 << " " << port << " " << "tcp filtered" << std::endl;
            } else if (tcpResp && (tcpResp->th_flags & TH_SYN) && (tcpResp->th_flags & TH_ACK)) {
                std::cout << dstIpv6 << " " << port << " " << "tcp open" << std::endl;
            } else if (tcpResp && (tcpResp->th_flags & TH_RST)) {
                std::cout << dstIpv6 << " " << port << " " << "tcp closed" << std::endl;
            }
        }
    }

    this->closeSocket(fdSock);
    this->closeEpoll(epollFd);
}

