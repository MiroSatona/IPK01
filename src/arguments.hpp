#ifndef ARGUMENTS_HPP 
#define ARGUMENTS_HPP // ARGUMENTS_HPP

#include <iostream>
#include <string>
#include <vector>


#define DEFAULT_TIMEOUT 5000

enum TYPE_SCAN{
    INTERACES_ONLY,
    DEFUALT_SCAN
};

enum IPV_TYPE{
    IPV4,
    IPV6,
    DOMAIN,
    INVALID
};



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
        bool isValid();
       

    private:

        bool valid;
        std::string interface;
        IPV_TYPE domainType;
        std::string domain;
        std::string domainName;
        int timeout;
        std::vector<int> tcpPorts;
        std::vector<int>  udpPorts;
      
        
        std::vector<int> convertPorts(std::string ports);   
        bool validateInterface();
        bool validateDomain();
        bool validatePorts(bool tcp, bool udp);
        bool validateTimeout(std::string time);
        void setTypeDomain();
        

};


#endif // ARGUMENTS_HPP