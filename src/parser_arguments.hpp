#ifndef ARGUMENTS_HPP 
#define ARGUMENTS_HPP // ARGUMENTS_HPP

#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>

// Default timeout
#define DEFAULT_TIMEOUT 5000


// Enum for set if scanner will print interfaces only or scan
enum TYPE_SCAN{
    INTERACES_ONLY,
    DEFUALT_SCAN
};

// Type of pasted domain
enum IPV_TYPE{
    IPV4,
    IPV6,
    DOMAIN,
    INVALID,
};


/**
 * @class Arguments
 * @brief Class for save and validate arguments.
 * 
 * 
 * Public methods of class are use for get arguments after validation.
 * Private methods and variables of class for validate arguments and save them.
 */
class Arguments{
    public:
        

        Arguments(std::string interface, std::string domain, std::string tcpPorts, std::string udpPorts, std::string timeout, bool parsedTcp, bool parsedUdp, TYPE_SCAN typeScan);  

        std::string getDomainName();
        std::string getInterface();
        std::string getDomain();
        std::vector<int> getPotsTcp();
        std::vector<int> getPotsUdp(); 
        IPV_TYPE getDomainType();
        int getTimeout();
        std::unordered_set<std::string> getIp4Addr();
        std::unordered_set<std::string> getIp6Addr();
        std::string getSrcIpv4();
        std::string getSrcIpv6();

    private:

       
        std::string interface;
        IPV_TYPE domainType;
        std::unordered_set<std::string> ip4Addr;
        std::unordered_set<std::string> ip6Addr;
        std::string domainName;
        int timeout;
        std::vector<int> tcpPorts;
        std::vector<int>  udpPorts;
        std::string srcIpv4;
        std::string srcIpv6;
      
        // Private methods for validate arguments or convert them
        std::vector<int> convertPorts(std::string ports);   
        void validateInterface();
        void validateDomain();
        void  validatePorts(bool tcp, bool udp);
        void validateTimeout(std::string time);
        void setTypeDomain();
        

};


#endif // ARGUMENTS_HPP