/**
 * @file pseudo_headers.hpp
 * @name Martin Zůbek, x253206
 * @date 25.3. 2025
 * @brief Library for creating pseudo headers for checksum calculation 
 */

#ifndef PSEUDO_HEADERS_HPP
#define PSEUDO_HEADERS_HPP // PSEUDO_HEADERS_HPP

#include <cstdint>
#include <netinet/in.h>

/**
 * @brief Struct for creating pseudo header for checksum calculation for IPv4
 */
struct checkSumPseudoHdrIpv4 {
    // Source address
    uint32_t srcAddr;
    // Destination address
    uint32_t dstAddr;
    // Zero field
    uint8_t zero;
    // Protocol number
    uint8_t protocol;
    // Length of the protocol header
    uint16_t protocolLength;
};

/**
 * @brief Struct for creating pseudo header for checksum calculation for IPv6
 */
struct checkSumPseudoHdrIpv6 {
    // Source address
    struct in6_addr src;
    // Destination address
    struct in6_addr dst;
    // Length of the protocol header
    uint32_t length;
    // Zero field
    uint8_t zero[3];
    // Next header -> protocol number
    uint8_t next_header;
};

#endif // PSEUDO_HEADERS_HPP