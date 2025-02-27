#include "arguments.hpp"
#include <regex>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <cstring>
#include <net/if.h>

Arguments::Arguments(std::string interface, std::string domain, std::string tcpPorts, std::string udpPorts, std::string timeout, bool parsedTcp, bool parsedUdp, TYPE_SCAN typeScan)
    : interface(interface), domain(domain){
    if(typeScan == INTERACES_ONLY){
        this->valid = true;
        return;
    }
    this->timeout = DEFAULT_TIMEOUT;
    this->valid = false;
    this->tcpPorts = this->convertPorts(tcpPorts);
    this->udpPorts = this->convertPorts(udpPorts);
    this->valid = true;
    this ->valid = this->validateInterface() && this->validateDomain() && this->validatePorts(parsedTcp, parsedUdp) && this->validateTimeout(timeout); 
}

std::string Arguments::getInterface(){ 
    return this->interface; 
}

std::string Arguments::getDomain(){ 
    return this->domain; 
}

std::vector<int> Arguments::getPotsTcp(){ 
    return this->tcpPorts;
}

std::vector<int> Arguments::getPotsUdp(){ 
    return this->udpPorts; 
}

int Arguments::getTimeout(){ 
    return this->timeout; 
}

bool Arguments::isValid(){ 
    return this->valid; 
}

std::string Arguments::getDomainName(){ 
    return this->domainName; 
}

std::vector<int> Arguments::convertPorts(std::string convertPorts){
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

bool Arguments::validateInterface(){

    if (this->interface.empty()) return false;
        
    
    struct ifaddrs *listIntefaces;
    
    if (getifaddrs(&listIntefaces) == -1) {
        
        return false;
    }
    bool found = false;
    for (struct ifaddrs *interface = listIntefaces; interface != nullptr; interface = interface->ifa_next) {
        if (interface->ifa_name && this->interface == interface->ifa_name && (interface->ifa_flags & IFF_UP)){
            found = true;
            break;
        }
    }

    freeifaddrs(listIntefaces);
    return found;
}

bool Arguments::validateDomain(){
    setTypeDomain();
    if(this->domainType == INVALID) return false;

    switch (this->domainType){
        case DOMAIN:
            struct addrinfo hints, *domainInfoResult;

            memset(&hints, 0, sizeof(hints));

            hints.ai_family = AF_UNSPEC;

            if(!getaddrinfo(this->domainName.c_str(), nullptr, &hints, &domainInfoResult)) {

                void* addr = nullptr;
            
                for (struct addrinfo* element = domainInfoResult; element != nullptr; element = element->ai_next) {
            
                    if (element->ai_family == AF_INET) {
                        this->domainType = IPV4;
            
                        sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(element->ai_addr);
                        addr = &(ipv4->sin_addr);
                        char ipv[INET_ADDRSTRLEN];
                        inet_ntop(element->ai_family, addr, ipv, INET_ADDRSTRLEN);
                        this->domain = std::string(ipv);
                        break;
    
                    } else if(element->ai_family == AF_INET6){
                        this->domainType = IPV6;
                        sockaddr_in6* ipv6 = reinterpret_cast<sockaddr_in6*>(element->ai_addr);
                        addr = &(ipv6->sin6_addr);
                        char ipv[INET6_ADDRSTRLEN];
                        inet_ntop(element->ai_family, addr, ipv, INET6_ADDRSTRLEN);
                        this->domain = std::string(ipv);
                    }
    
                }

                freeaddrinfo(domainInfoResult);
                return true;
    
            } else {
    
                return false;
    
            }
    
            break;
    default:


        return true;
        break;
    }
}


void Arguments::setTypeDomain(){

    if (this->domain.empty()) this->domainType = INVALID;
    std::regex ipv4Reg("^((25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)$");
    std::regex ipv6Reg("^((?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?::[0-9A-Fa-f]{1,4}){1,7}|:)$");
    this->domainType = INVALID;

    if(std::regex_match(domain, ipv4Reg)){
        this->domainType = IPV4;
        this->domainName = "";
    }
    else if(std::regex_match(domain, ipv6Reg)){
        this->domainType = IPV6;
        this->domainName = "";
    
    }
    else {
       
        this->domainType = DOMAIN;
        this->domainName = domain;
        this->domain = "";
    
    }
}



bool Arguments::validatePorts(bool tcp, bool udp){
    return (!this->tcpPorts.empty() == tcp) && (!this->udpPorts.empty() == udp) && (!this->tcpPorts.empty() || !this->udpPorts.empty());
}

bool Arguments::validateTimeout(std::string time){
    if (time.empty()) return true;
    std::regex timeReg("^[1-9][0-9]*$");
    if(std::regex_match(time, timeReg)) this->timeout = std::stoi(time);
    else this->timeout = 0;
    return this->timeout > 0;
}