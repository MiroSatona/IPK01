#ifndef SCANN_PARAMS_HPP
#define SCANN_PARAMS_HPP // SCANN_PARAMS_HPP

#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>

#define DEFAULT_TIMEOUT 5000
class ScannerParams{

    public:
        ScannerParams() = default;
        ScannerParams(std::string parsedInterface, std::string parseDomain, std::string parseTcpPorts, std::string parsedUdpPorts, std::string parseTimeout);

        std::string getInterfaceName();
        std::unordered_set<std::string> getIp4AddrDest();
        std::unordered_set<std::string> getIp6AddrDest();
        int getTimeout();
        std::vector<int> getTcpPorts();
        std::vector<int> getUdpPorts();
        std::string getInterfaceIpv4();
        std::string getInterfaceIpv6();
        
    private:

        void setAddrsDest(std::string domain);
        void setTimeout(std::string parsedTimeout);
        void setPorts(std::string parsedTcpPorts, std::string parsedUdpPorts);
        void setInterfaceIpv();
        std::vector<int> convertPorts(std::string convertPorts);

        std::string interfaceName;
        std::unordered_set<std::string> ip4AddrDest;
        std::unordered_set<std::string> ip6AddrDest;
        int timeout;
        std::vector<int> tcpPorts;
        std::vector<int>  udpPorts;
        std::string interfaceIpv4;
        std::string interfaceIpv6;

};


#endif // SCANN_PARAMS_HPP

