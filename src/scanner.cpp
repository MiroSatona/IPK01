/**
 * @file scanner.cpp
 * @name Martin Zůbek, x253206
 * @date 25.3. 2025
 * @brief Implementation of classes for scanning ports and methods for checksum calculation, creating socket and epoll instance, closing socket and epoll instance.
 */
#include "scanner.hpp"
#include "pseudo_headers.hpp"
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
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

// Constructor of scanners

Scanner::Scanner(const ScannerParams& scanParams) : scanParams(scanParams) {}
TcpIpv4Scanner::TcpIpv4Scanner(const ScannerParams& params): Scanner(params) {}
TcpIpv6Scanner::TcpIpv6Scanner(const ScannerParams& params): Scanner(params) {}
UdpIpv4Scanner::UdpIpv4Scanner(const ScannerParams& params): Scanner(params) {}
UdpIpv6Scanner::UdpIpv6Scanner(const ScannerParams& params): Scanner(params) {}

// Method for calculating checksum

unsigned short Scanner::calculateChecksum(const char* pdu, size_t dataLen) {
    // Checksum
    unsigned long checksum = 0;
    // Offset
    size_t offset = 0;
    // Calculate checksum
    while (offset < dataLen-1){
        checksum += *(unsigned short *)&pdu[offset];
        // 16 bits -> 2 bytes
        offset += 2;
    }
    // If data length is odd, add last byte
    if (dataLen%2) checksum += (unsigned char) pdu[offset];
    // Add carry
    while (checksum >> 16) checksum = (checksum & 0xFFFF) + (checksum >> 16);
    // Return checksum
    return (unsigned short) ~checksum;
}

// Method for creating socket and bind socket, wich socket is independent on IP version and protocol

int Scanner::createSocket(int ipvType, int protocol) {
    // Create socket
    int fdSock = socket(ipvType, SOCK_RAW, protocol);
    if (fdSock == -1) return -1;
    // Bind socket to interface
    if(setsockopt(fdSock, SOL_SOCKET, SO_BINDTODEVICE, scanParams.getInterfaceName().c_str(), scanParams.getInterfaceName().size()) == -1){
        close(fdSock);
        return -1;
    }

    return fdSock;
}

// Method for creating epoll instance

int Scanner::createEpoll() {
    int epollFd = epoll_create1(0);
    return epollFd;
}

// Method for closing socket

void Scanner::closeSocket(int fdSock) {
    close(fdSock);
}

// Method for closing epoll instance

void Scanner::closeEpoll(int epollFd) {
    close(epollFd);
}


// Methods for scanning ports -> TCP IPv4, TCP IPv6, UDP IPv4, UDP IPv6

void TcpIpv4Scanner::scan() {
    // Source port
    int srcPort = DEFAULT_SOURCE_PORT;
    // Create and bind socket to interface
    int fdSock = this->createSocket(AF_INET, IPPROTO_TCP);
    if (fdSock == -1) throw std::runtime_error("Could not create or bind socket!");
    
    // Create epoll instance for timeout handling
    int epollFd = this->createEpoll();
    if(epollFd == -1) throw std::runtime_error("Could not create epoll instance!");
    
    // Add socket to epoll
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = fdSock;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fdSock, &ev) == -1) {
        this->closeSocket(fdSock);
        this->closeEpoll(epollFd);
        throw std::runtime_error("Could not add socket to epoll!");
    }

    // For each destination IP address and port
    for (std::string dstIpv4 : scanParams.getIp4AddrDest()) {
        for (int port : scanParams.getTcpPorts()) {

            // Create TCP header
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

            
            // Create pseudo header for checksum calculation
            struct checkSumPseudoHdrIpv4 pseudoHdr;
            memset(&pseudoHdr, 0, sizeof(struct checkSumPseudoHdrIpv4));
            if(inet_pton(AF_INET, scanParams.getInterfaceIpv4().c_str(), &pseudoHdr.srcAddr) != 1){
                this->closeSocket(fdSock);
                this->closeEpoll(epollFd);
                throw std::runtime_error("Inet_pton failed!");
            }
            if(inet_pton(AF_INET, dstIpv4.c_str(), &pseudoHdr.dstAddr) != 1){
                this->closeSocket(fdSock);
                this->closeEpoll(epollFd);
                throw std::runtime_error("Inet_pton failed!");
            }
            pseudoHdr.protocol = IPPROTO_TCP;
            pseudoHdr.zero = 0;
            pseudoHdr.protocolLength = htons(sizeof(struct tcphdr));

            // Create segment for checksum calculation
            size_t segmentLength = sizeof(struct tcphdr) + sizeof(struct checkSumPseudoHdrIpv4);
            std::vector<char> segment(segmentLength);
            // Copy pseudo header and TCP header to segment
            memcpy(segment.data(), &pseudoHdr, sizeof(struct checkSumPseudoHdrIpv4));
            memcpy(segment.data() + sizeof(struct checkSumPseudoHdrIpv4), &tcpHeader, sizeof(struct tcphdr));
            // Calculate checksum
            tcpHeader.th_sum = this->calculateChecksum(segment.data(), segmentLength);

            // Create socket destination address for sending
            struct sockaddr_in sockDstAddr;
            memset(&sockDstAddr, 0, sizeof(sockDstAddr));
            sockDstAddr.sin_family = AF_INET;
            sockDstAddr.sin_port = htons(port);
            sockDstAddr.sin_addr.s_addr = inet_addr(dstIpv4.c_str());
            socklen_t sockDstAddrLen = sizeof(sockDstAddr);
            // Flag for filtred
            bool notFiltered = false;
            // Pointers for received packet
            struct iphdr* ipHeader = nullptr;
            struct tcphdr* tcpRecive = nullptr;

            // In tcp when timeout is reached, we try to send packet again
            for (int i = 0; i < MAX_RETRIES; i++) {
                // Send packet
                if (sendto(fdSock, (struct tcphdr*)&tcpHeader, sizeof(struct tcphdr), 0, (struct sockaddr*)&sockDstAddr, sockDstAddrLen) == -1) {
                    this->closeSocket(fdSock);
                    this->closeEpoll(epollFd);
                    throw std::runtime_error("Could not send packet!");
                }
                // Start timeout
                int timeout = scanParams.getTimeout();
                auto startTime = std::chrono::steady_clock::now();

                // Wait for response
                while (timeout > 0) {
                    // Wait for event
                    int epollState = epoll_wait(epollFd, events, MAX_EVENTS, timeout);
                    // Save time of event
                    auto now = std::chrono::steady_clock::now();
                    // Calculate time delta
                    int delta = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
                    // Decrease spend time from timeout
                    timeout -= delta;
                    // Set new start time
                    startTime = now;

                    // Check if epoll_wait failed
                    if (epollState == -1) {
                        this->closeSocket(fdSock);
                        this->closeEpoll(epollFd);
                        throw std::runtime_error("Epoll_wait failed!");
                    // Check timeout reached
                    } else if (epollState == 0) {
                        break;
                    }

                    // Buffer for received packet
                    char buffer[MAX_BUFFER_SIZE];
                    // Receive socket address
                    struct sockaddr_in socketRecvAddr;
                    socklen_t sockRecvAddrLen = sizeof(socketRecvAddr);
                    if(recvfrom(fdSock, buffer, sizeof(buffer), 0, (struct sockaddr*)&socketRecvAddr, &sockRecvAddrLen) == -1){
                        this->closeSocket(fdSock);
                        this->closeEpoll(epollFd);
                        throw std::runtime_error("Cannot receive packet!");
                    }
                    
                    // Parse received packet
                    ipHeader = (struct iphdr*)buffer;
                    tcpRecive = (struct tcphdr*)(buffer + (ipHeader->ihl * 4));
                    // Check validity of received packet
                    bool dstAddrMatch = socketRecvAddr.sin_addr.s_addr == sockDstAddr.sin_addr.s_addr;
                    bool srcAddrMatch = ipHeader->daddr == inet_addr(scanParams.getInterfaceIpv4().c_str());
                    bool portMatch = ntohs(tcpRecive->th_sport) == port;
                    bool dstPortMatch = ntohs(tcpRecive->th_dport) == srcPort;
                    
                    // If right packet was received, break
                    if (srcAddrMatch && dstAddrMatch && portMatch && dstPortMatch) {
                        notFiltered = true;
                        break;
                    }
                }
                // If packet was received, break
                if (notFiltered) break;
            }

            // Print result
            if (!notFiltered) {
                std::cout << dstIpv4 << " " << port << " " << "tcp filtered" << std::endl;
            } else if (tcpRecive && (tcpRecive->th_flags & TH_SYN) && (tcpRecive->th_flags & TH_ACK)) {
                std::cout << dstIpv4 << " " << port << " " <<"tcp open" << std::endl;
            } else if (tcpRecive && (tcpRecive->th_flags & TH_RST)) {
                std::cout << dstIpv4 << " " << port << " " << "tcp closed" << std::endl;
            }

            // Increase source port
            if (srcPort < MAX_SOURCE_PORT) srcPort++;
            else srcPort = DEFAULT_SOURCE_PORT;
        }
    }
    // Free descriptors
    this->closeSocket(fdSock);
    this->closeEpoll(epollFd);
}


void TcpIpv6Scanner::scan() {
    // Source port
    int srcPort = DEFAULT_SOURCE_PORT;
    // Create and bind socket to interface
    int fdSock = this->createSocket(AF_INET6, IPPROTO_TCP);
    if (fdSock == -1) throw std::runtime_error("Could not create or bind socket!");
    // Create epoll instance for timeout handling
    int epollFd = this->createEpoll();

    // Add socket to epoll
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = fdSock;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fdSock, &ev) == -1) {
        close(fdSock);
        close(epollFd);
        throw std::runtime_error("Could not add socket to epoll!");
    }

    // For each destination IP address and port
    for (std::string dstIpv6 : scanParams.getIp6AddrDest()) {
        for (int port : scanParams.getTcpPorts()) {
            // Create TCP header
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

            // Create pseudo header for checksum calculation
            struct checkSumPseudoHdrIpv6 pseudoHdr;
            memset(&pseudoHdr, 0, sizeof(pseudoHdr));
            if (inet_pton(AF_INET6, scanParams.getInterfaceIpv6().c_str(), &pseudoHdr.src) != 1) {
                this->closeSocket(fdSock);
                this->closeEpoll(epollFd);
                throw std::runtime_error("Inet_pton failed!");
            }
            if (inet_pton(AF_INET6, dstIpv6.c_str(), &pseudoHdr.dst) != 1) {
                this->closeSocket(fdSock);
                this->closeEpoll(epollFd);
                throw std::runtime_error("Inet_pton failed!");
            }
            pseudoHdr.length = htonl(sizeof(struct tcphdr));
            pseudoHdr.next_header = IPPROTO_TCP;

            // Create segment for checksum calculation
            size_t segmentLenght = sizeof(struct tcphdr) + sizeof(struct checkSumPseudoHdrIpv6);
            std::vector<char> segment(segmentLenght);
            memcpy(segment.data(), &pseudoHdr, sizeof(struct checkSumPseudoHdrIpv6));
            memcpy(segment.data() + sizeof(struct checkSumPseudoHdrIpv6), &tcpHeader, sizeof(struct tcphdr));
            tcpHeader.th_sum = this->calculateChecksum(segment.data(), segmentLenght);

            // Create socket destination address for sending
            struct sockaddr_in6 sockDstAddr;
            memset(&sockDstAddr, 0, sizeof(sockDstAddr));
            sockDstAddr.sin6_family = AF_INET6;
            sockDstAddr.sin6_port = htons(0);
            if (inet_pton(AF_INET6, dstIpv6.c_str(), &sockDstAddr.sin6_addr) != 1) {
                this->closeSocket(fdSock);
                this->closeEpoll(epollFd);
                throw std::runtime_error("Inet_pton failed!");
            }
            
            
            // Flag for filtred
            bool notFiltered = false;
            // Pointers for received packet
            struct tcphdr* tcpRecive = nullptr;

            // In tcp when timeout is reached, we try to send packet again
            for (int i = 0; i < MAX_RETRIES; i++) {
                // Send packet
                if (sendto(fdSock, (struct tchphdr*) &tcpHeader, sizeof(struct tcphdr), 0, (struct sockaddr*)&sockDstAddr, sizeof(sockDstAddr)) == -1) {
                    this->closeSocket(fdSock);
                    this->closeEpoll(epollFd);
                    throw std::runtime_error("Could not send packet!");
                }
               // Start timeout
               int timeout = scanParams.getTimeout();
               auto startTime = std::chrono::steady_clock::now();

               // Wait for response
               while (timeout > 0) {
                    // Wait for event
                    int epollState = epoll_wait(epollFd, events, MAX_EVENTS, timeout);
                    // Save time of event
                    auto now = std::chrono::steady_clock::now();
                    // Calculate time delta
                    int delta = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
                    // Decrease spend time from timeout
                    timeout -= delta;
                    // Set new start time
                    startTime = now;

                    // Check if epoll_wait failed
                    if (epollState == -1) {
                        this->closeSocket(fdSock);
                        this->closeEpoll(epollFd);
                        throw std::runtime_error("Epoll_wait failed!");
                    // Check timeout reached
                    } else if (epollState == 0) {
                        break;
                    }

                    // Buffer for received packet
                    char buffer[MAX_BUFFER_SIZE];
                    // Receive socket address
                    struct sockaddr_in6 recvAddr;
                    socklen_t recvAddrLen = sizeof(recvAddr);
                    if(recvfrom(fdSock, buffer, sizeof(buffer), 0, (struct sockaddr*)&recvAddr, &recvAddrLen) == -1){ 
                        this->closeSocket(fdSock);
                        this->closeEpoll(epollFd);
                        throw std::runtime_error("Cannot receive packet!");
                    }
                    
                    // Parse received packet
                    tcpRecive = (struct tcphdr*)buffer;
                    // Check validity of received packet
                    bool dstAddrMatch = memcmp(&recvAddr.sin6_addr, &sockDstAddr.sin6_addr, sizeof(in6_addr)) == 0;
                    bool portMatch = ntohs(tcpRecive->th_sport) == port;
                    bool dstPortMatch = ntohs(tcpRecive->th_dport) == srcPort;
                                    

                    // If right packet was received, break
                    if (dstAddrMatch && portMatch && dstPortMatch) {    
                        notFiltered = true;
                        break;
                    }
                }
                // If packet was received, break
                if (notFiltered) break;
            }
            // Print result
            if (!notFiltered) {
                std::cout << dstIpv6 << " " << port << " " << "tcp filtered" << std::endl;
            } else if (tcpRecive && (tcpRecive->th_flags & TH_SYN) && (tcpRecive->th_flags & TH_ACK)) {
                std::cout << dstIpv6 << " " << port << " " << "tcp open" << std::endl;
            } else if (tcpRecive && (tcpRecive->th_flags & TH_RST)) {
                std::cout << dstIpv6 << " " << port << " " << "tcp closed" << std::endl;
            }
            // Increase source port
            if (srcPort < MAX_SOURCE_PORT) srcPort++;
            else srcPort = DEFAULT_SOURCE_PORT;

        }
    }
    // Free descriptors
    this->closeSocket(fdSock);
    this->closeEpoll(epollFd);
}

void UdpIpv4Scanner::scan() {
    // Source port
    int srcPort = DEFAULT_SOURCE_PORT;
    // Create and bind socket to interface
    int fdSock = this->createSocket(AF_INET, IPPROTO_UDP);
    if(fdSock == -1) throw std::runtime_error("Could not create or bind socket!");
    // Create and bind ICMP socket
    int icmp = this->createSocket(AF_INET, IPPROTO_ICMP);
    if (icmp == -1) {
        this->closeSocket(fdSock);
        throw std::runtime_error("Could not create or bind ICMP socket!");
    }
    // Create epoll instance for timeout handling
    int epollFd = this->createEpoll();
    if(epollFd == -1) {
        this->closeSocket(fdSock);
        this->closeSocket(icmp);
        throw std::runtime_error("Could not create epoll instance!");
    }
    // Add ICMP socket to epoll
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = fdSock;
    // Add ICMP socket to epoll
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, icmp, &ev) == -1) {
        this->closeSocket(fdSock);
        this->closeEpoll(epollFd);
        this->closeSocket(icmp);
        throw std::runtime_error("Could not add socket to epoll!");
    }
    // For each destination IP address and port
    for (std::string dstIpv4 : scanParams.getIp4AddrDest()) {
        for (int port : scanParams.getUdpPorts()) {
            // Create UDP header
            struct udphdr udpHeader;
            memset(&udpHeader, 0, sizeof(udphdr));
            udpHeader.source = htons(srcPort);
            udpHeader.dest = htons(port);
            udpHeader.len = htons(sizeof(struct udphdr));
            
            // Create pseudo header for checksum calculation
            struct checkSumPseudoHdrIpv4 pseudoHdr;
            memset(&pseudoHdr, 0, sizeof(struct checkSumPseudoHdrIpv4));
            pseudoHdr.srcAddr = inet_addr(scanParams.getInterfaceIpv4().c_str());
            pseudoHdr.dstAddr = inet_addr(dstIpv4.c_str());
            pseudoHdr.protocol = IPPROTO_UDP;
            pseudoHdr.zero = 0;
            pseudoHdr.protocolLength = htons(sizeof(struct udphdr));

            // Create datageam for checksum calculation
            size_t datagramLength = sizeof(struct udphdr) + sizeof(struct checkSumPseudoHdrIpv4);
            std::vector<char> datagram(datagramLength);
            memcpy(datagram.data(), &pseudoHdr, sizeof(struct checkSumPseudoHdrIpv4));
            memcpy(datagram.data() + sizeof(struct checkSumPseudoHdrIpv4), &udpHeader, sizeof(struct udphdr));
            udpHeader.check = this->calculateChecksum(datagram.data(), datagramLength);

            // Create socket destination address for sending
            struct sockaddr_in dstAddr;
            memset(&dstAddr, 0, sizeof(dstAddr));
            dstAddr.sin_family = AF_INET;
            dstAddr.sin_port = htons(port);
            dstAddr.sin_addr.s_addr = inet_addr(dstIpv4.c_str());
            // Flag for get ICMP packet
            bool getIcmp = false;

            // Send packet
            if (sendto(fdSock, (struct udphdr*) &udpHeader, sizeof(struct udphdr), 0, (struct sockaddr*)&dstAddr, sizeof(dstAddr)) == -1) {
                this->closeSocket(fdSock);
                this->closeEpoll(epollFd);
                this->closeSocket(icmp);
                throw std::runtime_error("Could not send packet!");
                
            }

            // Start timeout
            int timeout = scanParams.getTimeout();
            auto startTime = std::chrono::steady_clock::now();
            
            // Wait for response
            while(!getIcmp && timeout > 0){
                // Wait for event
                int epollState = epoll_wait(epollFd, events, MAX_EVENTS, timeout);
                // Save time of event
                auto now = std::chrono::steady_clock::now();
                // Calculate time delta
                int delta = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
                // Decrease spend time from timeout
                timeout -= delta;
                // Set new start time
                startTime = now;

                // Check if epoll_wait failed
                if (epollState == -1) {
                    this->closeSocket(fdSock);
                    this->closeEpoll(epollFd);
                    this->closeSocket(icmp);
                    throw std::runtime_error("Epoll_wait failed!");
                // Check timeout reached
                } else if (epollState == 0) {
                    break;
                }
                
                // Buffer for received packet
                char buffer[MAX_BUFFER_SIZE];
                int received = recvfrom(icmp, buffer, sizeof(buffer), 0, nullptr, nullptr);
                if (received == -1){
                    this->closeSocket(fdSock);
                    this->closeEpoll(epollFd);
                    this->closeSocket(icmp);
                    throw std::runtime_error("Cannot receive packet!");
                }

                // Parse received packet
                struct icmphdr* icmpHeader = (struct icmphdr*)(buffer + sizeof(struct iphdr));
                struct iphdr* ipHeader = (struct iphdr*)(buffer);
                unsigned char* innerIpStart = (unsigned char*)icmpHeader + sizeof(struct icmphdr);
                struct iphdr* innerIp = (struct iphdr*)innerIpStart;
                struct udphdr* innerUdp = (struct udphdr*)(innerIpStart + innerIp->ihl * 4);
                char srcIp[INET_ADDRSTRLEN], dstIp[INET_ADDRSTRLEN];
                if(inet_ntop(AF_INET, &ipHeader->saddr, dstIp, sizeof(srcIp)) == nullptr){
                    this->closeSocket(fdSock);
                    this->closeEpoll(epollFd);
                    this->closeSocket(icmp);
                    throw std::runtime_error("Inet_ntop failed!");
                }
                if(inet_ntop(AF_INET, &ipHeader->daddr, srcIp, sizeof(dstIp)) == nullptr){
                    this->closeSocket(fdSock);
                    this->closeEpoll(epollFd);
                    this->closeSocket(icmp);
                    throw std::runtime_error("Inet_ntop failed!");
                }

                // Check validity of received packet
                bool matchAddr = dstIpv4 == std::string(dstIp) && scanParams.getInterfaceIpv4() == std::string(srcIp);
                bool matchPort = ntohs(innerUdp->dest) == port && ntohs(innerUdp->source) == srcPort;
                bool matchIcmp = icmpHeader->type == ICMP_UNREACH_PORT && icmpHeader->code == ICMP_UNREACH_PORT;

                // If right packet was received and has right ICMP type then set prot like closed
                if(matchAddr && matchPort && matchIcmp){
                    getIcmp = true;
                    std::cout << dstIpv4 << " " << port << " " << "udp closed" << std::endl;
                    break;
                }

            }

            // If packet was not received, set port like open
            if(!getIcmp){
                std::cout << dstIpv4 << " " << port << " " << "udp open" << std::endl;
            }
            // Increase source port
            if (srcPort < MAX_SOURCE_PORT) srcPort++;
            else srcPort = DEFAULT_SOURCE_PORT;
            
        }
    }
    // Free descriptors
    this->closeSocket(fdSock);
    this->closeEpoll(epollFd);
    this->closeSocket(icmp);
}

void UdpIpv6Scanner::scan() {
    int srcPort = DEFAULT_SOURCE_PORT;
    // Create and bind socket to interface
    int fdSock = this->createSocket(AF_INET6, IPPROTO_UDP);
    if(fdSock == -1) throw std::runtime_error("Could not create or bind socket!");
    // Create and bind ICMP socket
    int icmp = this->createSocket(AF_INET6, IPPROTO_ICMPV6);
    if (icmp == -1) {
        this->closeSocket(fdSock);
        throw std::runtime_error("Could not create or bind ICMP socket!");
    }
    // Create epoll instance for timeout handling
    int epollFd = this->createEpoll();
    if(epollFd == -1) {
        this->closeSocket(fdSock);
        this->closeSocket(icmp);
        throw std::runtime_error("Could not create epoll instance!");
    }
    // Add ICMP socket to epoll
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = fdSock;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, icmp, &ev) == -1) {
        this->closeSocket(fdSock);
        this->closeEpoll(epollFd);
        this->closeSocket(icmp);
        throw std::runtime_error("Could not add socket to epoll!");
    }
    // For each destination IP address and port
    for (std::string dstIpv6 : scanParams.getIp6AddrDest()) {
        for (int port : scanParams.getUdpPorts()) {
            // Create UDP header
            struct udphdr udpHeader;
            memset(&udpHeader, 0, sizeof(udphdr));
            udpHeader.source = htons(srcPort);
            udpHeader.dest = htons(port);
            udpHeader.len = htons(sizeof(struct udphdr));
            
            // Create pseudo header for checksum calculation
            struct checkSumPseudoHdrIpv6 pseudoHdr;
            memset(&pseudoHdr, 0, sizeof(pseudoHdr));
            if (inet_pton(AF_INET6, scanParams.getInterfaceIpv6().c_str(), &pseudoHdr.src) != 1) {
                this->closeSocket(fdSock);
                this->closeEpoll(epollFd);
                this->closeSocket(icmp);
                throw std::runtime_error("Inet_pton failed!");
            }
            if (inet_pton(AF_INET6, dstIpv6.c_str(), &pseudoHdr.dst) != 1) {
                this->closeSocket(fdSock);
                this->closeEpoll(epollFd);
                this->closeSocket(icmp);
                throw std::runtime_error("Inet_pton failed!");
            }
            pseudoHdr.length = htonl(sizeof(struct udphdr));
            pseudoHdr.next_header = IPPROTO_UDP;

            // Create datageam for checksum calculation
            size_t datagramLength = sizeof(struct udphdr) + sizeof(struct checkSumPseudoHdrIpv6);
            std::vector<char> datagram(datagramLength);
            memcpy(datagram.data(), &pseudoHdr, sizeof(struct checkSumPseudoHdrIpv6));
            memcpy(datagram.data() + sizeof(struct checkSumPseudoHdrIpv6), &udpHeader, sizeof(struct udphdr));
            udpHeader.check = this->calculateChecksum(datagram.data(), datagramLength);

            // Create socket destination address for sending
            struct sockaddr_in6 dstAddr;
            memset(&dstAddr, 0, sizeof(dstAddr));
            dstAddr.sin6_family = AF_INET6;
            //dstAddr.sin6_port = htons(port);
            if (inet_pton(AF_INET6, dstIpv6.c_str(), &dstAddr.sin6_addr) != 1) {
                this->closeSocket(fdSock);
                this->closeEpoll(epollFd);
                this->closeSocket(icmp);
                throw std::runtime_error("Inet_pton failed!");
            }

            // Flag for get ICMP packet
            bool getIcmp = false;
            // Send packet
            if (sendto(fdSock, (struct udphdr*) &udpHeader, sizeof(struct udphdr), 0, (struct sockaddr*)&dstAddr, sizeof(dstAddr)) == -1) {
                close(fdSock);
                close(epollFd);
                close(icmp);
                throw std::runtime_error("Could not send packet!");
                
            }

            // Start timeout
            int timeout = scanParams.getTimeout();
            auto startTime = std::chrono::steady_clock::now();
            
            while (!getIcmp && timeout > 0) {
                // Wait for event
                int epollState = epoll_wait(epollFd, events, MAX_EVENTS, timeout);
                // Save time of event
                auto now = std::chrono::steady_clock::now();
                // Calculate time delta
                int delta = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
                // Decrease spend time from timeout
                timeout -= delta;
                // Set new start time
                startTime = now;
            
                // Check if epoll_wait failed
                if (epollState == -1) {
                    this->closeSocket(fdSock);
                    this->closeEpoll(epollFd);
                    throw std::runtime_error("Epoll_wait failed!");
                // Check timeout reached
                } else if (epollState == 0) {
                    break;
                }
                
                // Buffer for received packet
                char buffer[MAX_BUFFER_SIZE];
                // Receive packet
                int received = recvfrom(icmp, buffer, sizeof(buffer), 0, nullptr, nullptr);
                if (received == -1){
                    this->closeSocket(fdSock);
                    this->closeEpoll(epollFd);
                    this->closeSocket(icmp);
                    throw std::runtime_error("Cannot receive packet!");
                }
                
                // Parse received packet
                uint8_t icmpType = buffer[0];
                uint8_t icmpCode = buffer[1];
            
                unsigned char* innerData = (unsigned char*)(buffer + 8); 
                struct in6_addr* origSrcIp = (struct in6_addr*)(innerData + 8);  
                struct in6_addr* origDstIp = (struct in6_addr*)(innerData + 24); 
            
                struct udphdr* innerUdp = (struct udphdr*)(innerData + 40); 
                uint16_t udpSrcPort = ntohs(innerUdp->source);
                uint16_t udpDstPort = ntohs(innerUdp->dest);
            
                char srcAddrStr[INET6_ADDRSTRLEN], dstAddrStr[INET6_ADDRSTRLEN];
                if(inet_ntop(AF_INET6, origSrcIp, srcAddrStr, sizeof(srcAddrStr)) == nullptr){
                    this->closeSocket(fdSock);
                    this->closeEpoll(epollFd);
                    this->closeSocket(icmp);
                    throw std::runtime_error("Inet_ntop failed!");
                }
                if(inet_ntop(AF_INET6, origDstIp, dstAddrStr, sizeof(dstAddrStr)) == nullptr){
                    this->closeSocket(fdSock);
                    this->closeEpoll(epollFd);
                    this->closeSocket(icmp);
                    throw std::runtime_error("Inet_ntop failed!");
                }
                
                // Check validity of received packet
                bool matchPorts = (udpSrcPort == srcPort && udpDstPort == port);
                bool matchIcmp = (icmpType == ICMP6_DST_UNREACH && icmpCode == ICMP6_DST_UNREACH_NOPORT);
                bool matchIps = (scanParams.getInterfaceIpv6() == std::string(srcAddrStr) && dstIpv6 == std::string(dstAddrStr));
                
                // If right packet was received and has right ICMP type then set port like closed
                if (matchPorts && matchIcmp && matchIps) {
                    getIcmp = true;
                    std::cout << dstIpv6 << " " << port << " udp closed" << std::endl;
                }
            }
            
            // If packet was not received, set port like open
            if(!getIcmp){
                std::cout << dstIpv6 << " " << port << " " << "udp open" << std::endl;
            }
            // Increase source port
            if (srcPort < MAX_SOURCE_PORT) srcPort++;
            else srcPort = DEFAULT_SOURCE_PORT;
            
        }
    }
    // Free descriptors
    this->closeSocket(fdSock);
    this->closeEpoll(epollFd);
    this->closeSocket(icmp);
}