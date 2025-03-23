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





ScannerParams::ScannerParams(std::string parsedInterface, std::string parseDomain, std::string parseTcpPorts, std::string parsedUdpPorts, std::string parseTimeout){
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


std::vector<int> ScannerParams::convertPorts(std::string convertPorts){

    if (convertPorts.empty()) return {};
    std::regex port("^(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4})$");
    std::regex ports("^(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4})(?:,(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4}))*$");
    std::regex portsRange("^(?:(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4}))-(?:(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4}))$");

    std::vector<int> result = {};
    
    if (std::regex_match(convertPorts, port)){
        result.push_back(std::stoi(convertPorts));
    }
    else if (std::regex_match(convertPorts, ports)) {
        std::istringstream charactersStream(convertPorts);
        std::string character;
        
        while (std::getline(charactersStream, character, ',')) {
            result.push_back(std::stoi(character));
        }

        for (size_t i = 0; i < result.size(); i++) {
            for (size_t j = i + 1; j < result.size(); j++) {
                if (result[i] == result[j]) result={};
            }
        }
    } 
    else if (std::regex_match(convertPorts, portsRange)) {
        size_t dashIndex = convertPorts.find('-');
        int intervalBegin = std::stoi(convertPorts.substr(0, dashIndex));
        int intervalEnd = std::stoi(convertPorts.substr(dashIndex + 1));
        while(intervalBegin <= intervalEnd){
            result.push_back(intervalBegin);
            intervalBegin++;
        }
    }
    return result;
}

void ScannerParams::setPorts(std::string parsedTcpPorts, std::string parsedUdpPorts){
    this->tcpPorts = this->convertPorts(parsedTcpPorts);
    this->udpPorts = this->convertPorts(parsedUdpPorts);

    if((!parsedTcpPorts.empty() && this->tcpPorts.empty()) || (!parsedUdpPorts.empty() && this->udpPorts.empty())){
        
        throw std::invalid_argument("Invalid ports were pasted!\n");
    }
}

void ScannerParams::setInterfaceIpv(){
    if (this->interfaceName.empty()){
        throw std::invalid_argument("Interface was not pasted!\n");
        return;
    }
        
    struct ifaddrs *listInterfaces, *interface;

    if (getifaddrs(&listInterfaces) == -1) {
        throw std::runtime_error("Error: Getifaddrs failed!\n");
        return;
    }

    for (interface = listInterfaces; interface != nullptr; interface = interface->ifa_next) {
        if (interface->ifa_flags & IFF_UP && interface->ifa_name == this->interfaceName && interface->ifa_addr != nullptr) {
            if (interface->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)(interface->ifa_addr);
                char ipv[INET_ADDRSTRLEN];
                inet_ntop(interface->ifa_addr->sa_family, &(ipv4->sin_addr), ipv, INET_ADDRSTRLEN);
                this->interfaceIpv4 = std::string(ipv);
                break;
            } else if (interface->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)(interface->ifa_addr);
                char ipv[INET6_ADDRSTRLEN];
                inet_ntop(interface->ifa_addr->sa_family, &(ipv6->sin6_addr), ipv, INET6_ADDRSTRLEN);
                this->interfaceIpv6 = std::string(ipv);
            break;
            }
        if(!this->interfaceIpv4.empty() && !this->interfaceIpv6.empty()) break;
        }

    }

    freeifaddrs(listInterfaces); 
    if (this->interfaceIpv4.empty() && this->interfaceIpv6.empty()) throw std::invalid_argument("Interface was not found!\n");
}

void ScannerParams::setAddrsDest(std::string domain){
    
    struct addrinfo hints, *listOfAddrInfo;
    memset(&hints, 0, sizeof(hints));
    
   

    int retVal = getaddrinfo(domain.c_str(), nullptr, &hints, &listOfAddrInfo);
    
    if(retVal == EAI_NONAME) throw std::invalid_argument("Invalid domain name was pasted!");
    else if(retVal || listOfAddrInfo == nullptr) throw std::invalid_argument("Internal error of getaddrinfo!");


   

        void* addr = nullptr;
        for (struct addrinfo* element = listOfAddrInfo; element != nullptr; element = element->ai_next) {
    
            if (element->ai_family == AF_INET) {
                sockaddr_in* ipv4 = (sockaddr_in*)(element->ai_addr);
                addr = &(ipv4->sin_addr);
                char ipv[INET_ADDRSTRLEN];
                inet_ntop(element->ai_family, addr, ipv, INET_ADDRSTRLEN);
                this->ip4AddrDest.insert(std::string(ipv));

            } else if(element->ai_family == AF_INET6){
                sockaddr_in6* ipv6 = (sockaddr_in6*)(element->ai_addr);
                addr = &(ipv6->sin6_addr);
                char ipv[INET6_ADDRSTRLEN];
                inet_ntop(element->ai_family, addr, ipv, INET6_ADDRSTRLEN);
                this->ip6AddrDest.insert(std::string(ipv));
            }
        }

    freeaddrinfo(listOfAddrInfo);
    if(this->ip4AddrDest.empty() && this->ip6AddrDest.empty()) throw std::invalid_argument("Invalid domain name was pasted!");
}



void ScannerParams::setTimeout(std::string parsedTimeout){
    if (parsedTimeout.empty()){
        this->timeout = DEFAULT_TIMEOUT;
        return;
    }

    std::regex timeReg("^[1-9][0-9]*$");

    if(std::regex_match(parsedTimeout, timeReg)) this->timeout = std::stoi(parsedTimeout);
    else throw std::invalid_argument("Invalid timeout was pasted!\n");
    
}