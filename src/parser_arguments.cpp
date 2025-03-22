#include "arguments.hpp"
#include <regex>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <cstring>
#include <net/if.h>
#include <unordered_set>

Arguments::Arguments(std::string interface, std::string domain, std::string tcpPorts, std::string udpPorts, std::string timeout, bool parsedTcp, bool parsedUdp, TYPE_SCAN typeScan)
    : interface(interface), domainName(domain){
    if(typeScan == INTERACES_ONLY)return;


    this->timeout = DEFAULT_TIMEOUT;
    this->tcpPorts = this->convertPorts(tcpPorts);
    this->udpPorts = this->convertPorts(udpPorts);
    this->validateInterface();
    this->setTypeDomain(); 
    this->validateDomain(); 
    this->validatePorts(parsedTcp, parsedUdp); 
    this->validateTimeout(timeout); 
}

std::string Arguments::getInterface(){ 
    return this->interface; 
}

std::unordered_set<std::string> Arguments::getIp4Addr(){ 
    return this->ip4Addr; 
}

std::unordered_set<std::string> Arguments::getIp6Addr(){ 
    return this->ip6Addr; 
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
std::string Arguments::getDomainName(){ 
    return this->domainName; 
}

std::string Arguments::getSrcIpv4(){ 
    return this->srcIpv4; 
}

std::string Arguments::getSrcIpv6(){ 
    return this->srcIpv6; 
}

std::vector<int> Arguments::convertPorts(std::string convertPorts){
    std::regex port("^(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4})$");
    std::regex ports("^(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4})(?:,(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4}))*$");
    std::regex portsRange("^(?:(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4}))-(?:(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]?\\d{1,4}))$");

    std::vector<int> result = {};
    bool possDuplicate = false;
    if (std::regex_match(convertPorts, port)){
        result.push_back(std::stoi(convertPorts));
    }
    else if (std::regex_match(convertPorts, ports)) {
        std::istringstream charactersStream(convertPorts);
        std::string character;
        
        while (std::getline(charactersStream, character, ',')) {
            result.push_back(std::stoi(character));
            possDuplicate = true;
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


    for (size_t i = 0; i < result.size() && possDuplicate; i++) {
        for (size_t j = i + 1; j < result.size(); j++) {
            if (result[i] == result[j]) throw std::invalid_argument("Port was pasted more than once!");
        }
    }


    return result;
}

void Arguments::validateInterface(){

    if (this->interface.empty()){
        throw std::invalid_argument("Interface was not pasted!");
        return;
    }
        
    struct ifaddrs *listInterfaces, *interface;
    if (getifaddrs(&listInterfaces) == -1) {
        perror("getifaddrs failed");
        return;
    }

    bool found = false;
    for (interface = listInterfaces; interface != nullptr; interface = interface->ifa_next) {
        if (interface->ifa_addr == nullptr) continue;
        if (interface->ifa_flags & IFF_UP && interface->ifa_name == this->interface) {
            if (interface->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(interface->ifa_addr);
                char ipv[INET_ADDRSTRLEN];
                inet_ntop(interface->ifa_addr->sa_family, &(ipv4->sin_addr), ipv, INET_ADDRSTRLEN);
                this->srcIpv4 = std::string(ipv);
                found = true;
                break;
            } else if (interface->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *ipv6 = reinterpret_cast<struct sockaddr_in6 *>(interface->ifa_addr);
                char ipv[INET6_ADDRSTRLEN];
                inet_ntop(interface->ifa_addr->sa_family, &(ipv6->sin6_addr), ipv, INET6_ADDRSTRLEN);
                this->srcIpv6 = std::string(ipv);

                found = true;
            break;
            }
        if(!this->srcIpv4.empty() && !this->srcIpv6.empty()) break;
        
        }

    }

    freeifaddrs(listInterfaces); // Free allocated memory

    if (!found) {
        std::cerr << "Error: Interface ' not found or has no IP address." << std::endl;
    }
    return;
}

void Arguments::validateDomain(){
   
    struct addrinfo hints, *listOfAddrInfo;
    memset(&hints, 0, sizeof(hints));
    
    switch (this->domainType){
    case INVALID:
        throw::std::invalid_argument("Invalid domain was pasted!");
        break;
    case IPV4:
        hints.ai_family = AF_INET;
        break;
    case IPV6:
        hints.ai_family = AF_INET6;
        break;   
    case DOMAIN:
        hints.ai_family = AF_UNSPEC;
        break;
    }

    int retVal = getaddrinfo(this->domainName.c_str(), nullptr, &hints, &listOfAddrInfo);
    
    if(retVal == EAI_NONAME) throw std::invalid_argument("Invalid domain name was pasted!");
    else if(retVal || listOfAddrInfo == nullptr) throw std::invalid_argument("Internal error of getaddrinfo!");


    switch (this->domainType){
        case DOMAIN:{ 

        void* addr = nullptr;
        for (struct addrinfo* element = listOfAddrInfo; element != nullptr; element = element->ai_next) {
    
            if (element->ai_family == AF_INET) {
                sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(element->ai_addr);
                addr = &(ipv4->sin_addr);
                char ipv[INET_ADDRSTRLEN];
                inet_ntop(element->ai_family, addr, ipv, INET_ADDRSTRLEN);
                this->ip4Addr.insert(std::string(ipv));

            } else if(element->ai_family == AF_INET6){
                sockaddr_in6* ipv6 = reinterpret_cast<sockaddr_in6*>(element->ai_addr);
                addr = &(ipv6->sin6_addr);
                char ipv[INET6_ADDRSTRLEN];
                inet_ntop(element->ai_family, addr, ipv, INET6_ADDRSTRLEN);
                this->ip6Addr.insert(std::string(ipv));
            }

        }
        break;
    }
    default:{ 
        char hostname[NI_MAXHOST];
        int retValName = getnameinfo(listOfAddrInfo->ai_addr, listOfAddrInfo->ai_addrlen, hostname, NI_MAXHOST, nullptr, 0, NI_NAMEREQD);
        
        if(retValName == EAI_NONAME) {
            freeaddrinfo(listOfAddrInfo);
            throw std::invalid_argument("Invalid domain address was pasted!");
        }
        else if(retValName){
            freeaddrinfo(listOfAddrInfo);
            throw std::invalid_argument("Internal error of getnameinfo!");
        }
        this->domainName = std::string(hostname);
        break;
        }
    }
    freeaddrinfo(listOfAddrInfo);
    return;
}



void Arguments::setTypeDomain(){

    if (this->domainName.empty()) this->domainType = INVALID;
    std::regex ipv4Reg("^((25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)$");
    std::regex ipv6Reg("^((?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?::[0-9A-Fa-f]{1,4}){1,7}|:)$");
    this->domainType = INVALID;

    if(std::regex_match(domainName, ipv4Reg)){
        this->domainType = IPV4;
        this->ip4Addr.insert(domainName);
        
    }
    else if(std::regex_match(domainName, ipv6Reg)){
        this->domainType = IPV6;
        this->ip6Addr.insert(domainName);
        
    }
    else {
        this->domainType = DOMAIN;
    }
}



void Arguments::validatePorts(bool tcp, bool udp){

    bool tcpEmpty = this->tcpPorts.empty();
    bool udpEmpty = this->udpPorts.empty();
    bool invalidPortsSyntax = (tcpEmpty && tcp) || (udpEmpty && udp);
    bool notPorts = !tcp && !udp;
    
    if (invalidPortsSyntax) throw std::invalid_argument("Invalid input of ports!");
    else if (notPorts) throw std::invalid_argument("Invalid input of ports!");
    else return;
}

void Arguments::validateTimeout(std::string time){
    if (time.empty()) return;
    std::regex timeReg("^[1-9][0-9]*$");
    if(std::regex_match(time, timeReg)) this->timeout = std::stoi(time);
    else throw std::invalid_argument("Invalid timeout was pasted!");

    return;
}