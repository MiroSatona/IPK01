/**
 * @file scanner.hpp
 * @name Martin Zůbek, x253206
 * @date 25.3. 2025
 * @brief Library for scanner of ports
 */

#ifndef SCANNER_HPP
#define SCANNER_HPP // SCANNER_HPP

#include <iostream>
#include "scanner_params.hpp"

// Constants for max retrie of send packet on tcp protocol
#define MAX_RETRIES 2
// Constants for max recive buffer size
#define MAX_BUFFER_SIZE 4096
// Constants for max events in epoll
#define MAX_EVENTS 1024
// Constants for default source port
#define DEFAULT_SOURCE_PORT 50000
// Constants for max source port
#define MAX_SOURCE_PORT 60000

/**
 * @brief Class for scanning ports
 * 
 * Parent class/Interface for classes TcpIpv4Scanner, TcpIpv6Scanner, UdpIpv4Scanner, UdpIpv6Scanner.
 * This class is responsible for creating scan ports.
 */
class Scanner{
    public:
        /**
         * @brief Construct a new Scanner object
         * 
         * @param scanParams - object of ScanParams with scan parameters
         */
        Scanner(const ScannerParams &scanParams);
        /**
         * @brief Method for scanning ports
         * 
         * Only virtual method for scanning, will be implemented in child classes.
         */
        virtual void scan() = 0;
    protected:
        /**
         * @brief Method for calculating checksum
         * 
         * @param pdu - pointer to data
         * @param dataLen - length of data
         * @return checksum
         */
        unsigned short calculateChecksum(const char* pdu, size_t dataLen);
        /**
         * @brief Method for creating socket and bind socket to interface
         * 
         * @param ipvType - type of IP protocol
         * @param protocol - type of protocol
         * @return file descriptor of socket, -1 if error
         */
        int createSocket(int ipvType, int protocol);
        /**
         * @brief Method for creating epoll instance
         * 
         * @return file descriptor of epoll instance, -1 if error
         */
        int createEpoll();
        /**
         * @brief Method for closing socket
         * 
         * @param fdSock - file descriptor of socket for close
         */
        void closeSocket(int fdSock);
        /**
         * @brief Method for closing epoll instance
         * 
         * @param epollFd - file descriptor of epoll instance for close
         */
        void closeEpoll(int epollFd);
        // Object of ScannerParams with scan parameters
        ScannerParams scanParams;
};

/**
 * @brief Class for scanning TCP ports with IPv4
 * 
 * Child class of Scanner for scanning TCP ports with IPv4.
 */
class TcpIpv4Scanner : public Scanner {
    public:
        /**
         * @brief Construct a new TcpIpv4Scanner object
         * 
         * @param params - object of ScanParams with scan parameters
         */
        TcpIpv4Scanner(const ScannerParams& params);
        /**
         * @brief Method for scanning TCP ports with IPv4
         * 
         * Meethod will create and bind socket to interface and create epoll instance for timeout handling.
         * For each destination IP address and port will create TCP header, pseudo header for checksum calculation and segment for checksum calculation.
         * Will send part of segment(tcp header, cause ip header will be added by kernel) and wait for response.
         * If response is received, will check validity of response. If response is valid, port will be marked as open or closed, it is indepeneed on response ([SYN, ACK] or RST)
         * If timout is reached without response, part of segment will be send again.
         * If valid response is not received after MAX_RETRIES, port will be marked as filtered.
         * 
         * @throw std::runtime_error if was detected interanl error of other function or system call or error with hadnling communication
         */
        void scan() override;
};

/**
 * @brief Class for scanning TCP ports with IPv6
 * 
 * Child class of Scanner for scanning TCP ports with IPv6.
 */
class TcpIpv6Scanner : public Scanner {
    public:
        /**
         * @brief Construct a new TcpIpv6Scanner object
         * 
         * @param params - object of ScanParams with scan parameters
         */
        TcpIpv6Scanner(const ScannerParams& params);
        /**
         * @brief Method for scanning TCP ports with IPv6
         * 
         * Meethod will create and bind socket to interface and create epoll instance for timeout handling.
         * For each destination IP address and port will create TCP header, pseudo header for checksum calculation and segment for checksum calculation.
         * Will send part of segment(tcp header, cause ip header will be added by kernel) and wait for response.
         * If response is received, will check validity of response. If response is valid, port will be marked as open or closed, it is indepeneed on response ([SYN, ACK] or RST).
         * If timout is reached without response, part of segment will be send again.
         * If valid response is not received after MAX_RETRIES, port will be marked as filtered.
         * 
         * @throw std::runtime_error if was detected interanl error of other function or system call or error with hadnling communication
         */
        void scan() override;
};

/**
 * @brief Class for scanning UDP ports with IPv4
 * 
 * Child class of Scanner for scanning UDP ports with IPv4.
 */
class UdpIpv4Scanner : public Scanner {
    public:
        /**
         * @brief Construct a new UdpIpv4Scanner object
         * 
         * @param params - object of ScanParams with scan parameters
         */
        UdpIpv4Scanner(const ScannerParams& params);
        /**
         * @brief Method for scanning UDP ports with IPv4
         * 
         * Meethod will create and bind socket to interface and create epoll instance for timeout handling.
         * For each destination IP address and port will create UDP header, pseudo header for checksum calculation and datagram for checksum calculation.
         * Will send part of datagram(udp header, cause ip header will be added by kernel) and wait for response.
         * If response is received, then is chacked validity of response.
         * If response response is valid, and has right type of ICMP, then port will be marked as close, otherwise will be marked as open.
         * 
         * @throw std::runtime_error if was detected interanl error of other function or system call or error with hadnling communication
         */
        void scan() override;
};

/**
 * @brief Class for scanning UDP ports with IPv6
 * 
 * Child class of Scanner for scanning UDP ports with IPv6.
 */
class UdpIpv6Scanner : public Scanner {
    public:
        /**
         * @brief Construct a new UdpIpv6Scanner object
         * 
         * @param params - object of ScanParams with scan parameters
         */
        UdpIpv6Scanner(const ScannerParams& params);
         /**
         * @brief Method for scanning UDP ports with IPv6
         * 
         * Meethod will create and bind socket to interface and create epoll instance for timeout handling.
         * For each destination IP address and port will create UDP header, pseudo header for checksum calculation and datagram for checksum calculation.
         * Will send part of datagram(udp header, cause ip header will be added by kernel) and wait for response.
         * If response is received, then is chacked validity of response.
         * If response response is valid, and has right type of ICMP, then port will be marked as close, otherwise will be marked as open.
         * 
         * @throw std::runtime_error if was detected interanl error of other function or system call or error with hadnling communication
         */
        void scan() override;
};

#endif // SCANNER_HPP
