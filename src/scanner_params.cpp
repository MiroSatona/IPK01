/**
 * @file scanner_params.cpp
 * @author Martin Zůbek, x253206
 * @date 25.3. 2025
 * @brief Implementation file for the ScannerParams class
 */

#include "scanner_params.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>
#include <regex>
#include <ifaddrs.h>
#include <cstring>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>

// Constructor of the class ScannerParams

ScannerParams::ScannerParams(std::string parsedInterface, std::string parseDomain, std::string parseTcpPorts, std::string parsedUdpPorts, std::string parseTimeout){
    // Initialize all attributes to default values and call the setters
    this->interfaceName = parsedInterface;
    this->interfaceIpv4 = "";
    this->interfaceIpv6 = "";
    this->ip4AddrDest = {};
    this->ip6AddrDest = {};
    this->timeout = DEFAULT_TIMEOUT;
    this->tcpPorts = {};
    this->udpPorts = {};

    this->setAddrsDest(parseDomain);
    this->setTimeout(parseTimeout);
    this->setPorts(parseTcpPorts, parsedUdpPorts);
    this->setInterfaceIpv();
}

// Getters of the class ScannerParams

std::string ScannerParams::getInterfaceName(){
    return this->interfaceName;
}

std::unordered_set<std::string> ScannerParams::getIp4AddrDest(){
    return this->ip4AddrDest;
}

std::unordered_set<std::string> ScannerParams::getIp6AddrDest(){
    return this->ip6AddrDest;
}

int ScannerParams::getTimeout(){
    return this->timeout;
}

std::vector<int> ScannerParams::getTcpPorts(){
    return this->tcpPorts;
}

std::vector<int> ScannerParams::getUdpPorts(){
    return this->udpPorts;
}

std::string ScannerParams::getInterfaceIpv4(){
    return this->interfaceIpv4;
}

std::string ScannerParams::getInterfaceIpv6(){
    return this->interfaceIpv6;
}

// Method for converting the ports

std::vector<int> ScannerParams::convertPorts(std::string convertPorts){

    // If the ports are empty, return empty vector
    if (convertPorts.empty()) return {};
    // Regular expressions for type of input of ports
    std::regex port("^(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4})$");
    std::regex ports("^(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4})(?:,(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4}))*$");
    std::regex portsRange("^(?:(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4}))-(?:(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4}))$");

    // Declaration of the result vector
    std::vector<int> result = {};
    
    // CASE 1: If the input is only one port
    if (std::regex_match(convertPorts, port)){
        result.push_back(std::stoi(convertPorts));
    }
    // CASE 2: If the input is more ports separated by comma -> 80,443
    else if (std::regex_match(convertPorts, ports)) {
        // Create the stream of characters
        std::istringstream charactersStream(convertPorts);
        std::string character;
        
        // Split the actual stream by comma and convert the characters to integers
        while (std::getline(charactersStream, character, ',')) {
            result.push_back(std::stoi(character));
        }

        // Check if the ports are unique
        for (size_t i = 0; i < result.size(); i++) {
            for (size_t j = i + 1; j < result.size(); j++) {
                if (result[i] == result[j]) result={};
            }
        }
    }
    // CASE 3: If the input is interval of ports -> 80-443 
    else if (std::regex_match(convertPorts, portsRange)) {
        // Find the index of the dash
        size_t dashIndex = convertPorts.find('-');
        // By the index of the dash, split the interval for found the begin and the end of the interval
        int intervalBegin = std::stoi(convertPorts.substr(0, dashIndex));
        int intervalEnd = std::stoi(convertPorts.substr(dashIndex + 1));
        // Save prots from the interval to the result vector
        while(intervalBegin <= intervalEnd){
            result.push_back(intervalBegin);
            intervalBegin++;
        }
    }

    return result;
}

// Setter for set the ports

void ScannerParams::setPorts(std::string parsedTcpPorts, std::string parsedUdpPorts){
    // Convert inputed ports to the vector of integers
    this->tcpPorts = this->convertPorts(parsedTcpPorts);
    this->udpPorts = this->convertPorts(parsedUdpPorts);

    // If ports were pasted and the conversion return empty vector, then the ports are invalid
    if((!parsedTcpPorts.empty() && this->tcpPorts.empty()) || (!parsedUdpPorts.empty() && this->udpPorts.empty())){
        throw std::invalid_argument("");
    }
}

// Setter for set ipv4 and ipv6 address of the interface

void ScannerParams::setInterfaceIpv(){
    // If the interface name is empty, then was not pasted and the interface was not found
    if (this->interfaceName.empty()) throw std::invalid_argument("");
    
    // Get the list of interfaces
    struct ifaddrs *listInterfaces;
    if (getifaddrs(&listInterfaces) == -1) throw std::runtime_error("Getifaddrs failed!");
        
    // Iterate over the list of interfaces and find the interface by the name
    for (struct ifaddrs *interface = listInterfaces; interface != nullptr; interface = interface->ifa_next) {
        // Found the active interface with right name
        if (interface->ifa_flags & IFF_UP && interface->ifa_name == this->interfaceName && interface->ifa_addr != nullptr) {
            // Ipv4 
            if (interface->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)(interface->ifa_addr);
                char ipv[INET_ADDRSTRLEN];
                if(inet_ntop(interface->ifa_addr->sa_family, &(ipv4->sin_addr), ipv, INET_ADDRSTRLEN) == nullptr) throw std::runtime_error("Inet_ntop failed!");
                this->interfaceIpv4 = std::string(ipv);
            // Ipv6
            } else if (interface->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)(interface->ifa_addr);
                char ipv[INET6_ADDRSTRLEN];
                if(inet_ntop(interface->ifa_addr->sa_family, &(ipv6->sin6_addr), ipv, INET6_ADDRSTRLEN) == nullptr) throw std::runtime_error("Inet_ntop failed!");
                this->interfaceIpv6 = std::string(ipv);
            }
        // If both ipv4 and ipv6 were found, then break the loop
        if(!this->interfaceIpv4.empty() && !this->interfaceIpv6.empty()) break;
        }

    }
    // Free the list of interfaces
    freeifaddrs(listInterfaces);
    // If the interface was not found, then inputed interface was invalid or not active -> invalid argument
    if (this->interfaceIpv4.empty() && this->interfaceIpv6.empty()) throw std::invalid_argument("");
}

// Setter for set the destination address of domain

void ScannerParams::setAddrsDest(std::string domain){
    
    // If the domain is empty, then was not pasted and the domain is invalid
    if (domain.empty()) throw std::invalid_argument("");
    
    // Get the list of addresses by the domain
    struct addrinfo hints, *listOfAddrInfo;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    int retVal = getaddrinfo(domain.c_str(), nullptr, &hints, &listOfAddrInfo);
    
    // Check the return value of getaddrinfo -> NONAME <=> invalid domain name or internal error
    if(retVal == EAI_NONAME) throw std::invalid_argument("");
    else if(retVal || listOfAddrInfo == nullptr) throw std::runtime_error("Internal error of getaddrinfo!");

    // Iterate over the list of addresses and find the ipv4 and ipv6 addresses
    void* addr = nullptr;
    for (struct addrinfo* element = listOfAddrInfo; element != nullptr; element = element->ai_next) {
        // Ipv4
        if (element->ai_family == AF_INET) {
            sockaddr_in* ipv4 = (sockaddr_in*)(element->ai_addr);
            addr = &(ipv4->sin_addr);
            char ipv[INET_ADDRSTRLEN];
            inet_ntop(element->ai_family, addr, ipv, INET_ADDRSTRLEN);
            this->ip4AddrDest.insert(std::string(ipv));

        // Ipv6
        } else if(element->ai_family == AF_INET6){
            sockaddr_in6* ipv6 = (sockaddr_in6*)(element->ai_addr);
            addr = &(ipv6->sin6_addr);
            char ipv[INET6_ADDRSTRLEN];
            inet_ntop(element->ai_family, addr, ipv, INET6_ADDRSTRLEN);
            this->ip6AddrDest.insert(std::string(ipv));
        }
    }

    // Free the list of addresses
    freeaddrinfo(listOfAddrInfo);
    // If the addresses were not found, then the domain is invalid -> invalid argument
    if(this->ip4AddrDest.empty() && this->ip6AddrDest.empty()) throw std::invalid_argument("");
}

// Setter for set the timeout

void ScannerParams::setTimeout(std::string parsedTimeout){
    // If the timeout was not pasted, use the default 
    if (parsedTimeout.empty()){
        this->timeout = DEFAULT_TIMEOUT;
        return;
    }
    // Regular expression for the timeout
    std::regex timeReg("^[1-9][0-9]*$");
    // Check if the pasted timeout is valid, if yes, then set the timeout
    if(std::regex_match(parsedTimeout, timeReg)) this->timeout = std::stoi(parsedTimeout);
    else throw std::invalid_argument("");
    
}