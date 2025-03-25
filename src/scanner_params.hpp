/**
 * @file scanner_params.hpp
 * @author Martin Zůbek, x253206
 * @date 25.3. 2025
 * @brief Header file for the ScannerParams class, which is used for parsing the input arguments, and storting them for the scanner.
 */

#ifndef SCANN_PARAMS_HPP
#define SCANN_PARAMS_HPP // SCANN_PARAMS_HPP

#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>

// Default timeout for the scanner
#define DEFAULT_TIMEOUT 5000

/**
 * @class ScannerParams
 * @brief Class for parsing the input arguments
 * 
 * This class is used for parsing the input arguments, and storing them for the scanner.
 * This class is and aggregated to class ParseArguments and composed to the class Scanner.
 *  */
class ScannerParams{

    public:
        /**
         * @brief Default constructor of the class ScannerParams
         * 
         * Default constructor of the class ScannerParams, initializes all attributes to default values.
         */
        ScannerParams() = default;
        /**
         * @brief Constructor of the class ScannerParams
         * 
         * Constructor of the class ScannerParams, initializes all attributes to values parsed from the input arguments.
         * 
         * @param parsedInterface - name of the interface
         * @param parseDomain - domain name
         * @param parseTcpPorts - TCP ports
         * @param parsedUdpPorts - UDP ports
         * @param parseTimeout - timeout
         * 
         */
        ScannerParams(std::string parsedInterface, std::string parseDomain, std::string parseTcpPorts, std::string parsedUdpPorts, std::string parseTimeout);

        /**
         * @brief Getter of the name of the interface
         * 
         * Method for getting the name of the interface
         * 
         * @return name of the interface
         */
        std::string getInterfaceName();
        /**
         * @brief Getter of the set of IPv4 addresses
         * 
         * Method for getting the set of IPv4 addresses
         * 
         * @return set of IPv4 addresses
         */
        std::unordered_set<std::string> getIp4AddrDest();
        /**
         * @brief Getter of the set of IPv6 addresses
         * 
         * Method for getting the set of IPv6 addresses
         * 
         * @return set of IPv6 addresses
         */
        std::unordered_set<std::string> getIp6AddrDest();
        /**
         * @brief Getter of the timeout
         * 
         * Method for getting the timeout
         * 
         * @return timeout
         */
        int getTimeout();
        /**
         * @brief Getter of the vector of TCP ports
         * 
         * Method for getting the vector of TCP ports
         * 
         * @return vector of TCP ports
         */
        std::vector<int> getTcpPorts();
        /**
         * @brief Getter of the vector of UDP ports
         * 
         * Method for getting the vector of UDP ports
         * 
         * @return vector of UDP ports
         */
        std::vector<int> getUdpPorts();
        /**
         * @brief Getter of the IPv4 address of the interface
         * 
         * Method for getting the IPv4 address of the interface
         * 
         * @return IPv4 address of the interface
         */
        std::string getInterfaceIpv4();
        /**
         * @brief Getter of the IPv6 address of the interface
         * 
         * Method for getting the IPv6 address of the interface
         * 
         * @return IPv6 address of the interface
         */
        std::string getInterfaceIpv6();
        
    private:
        /**
         * @brief Setter of the destination addresses
         * 
         * Method for setting the destination addresses -> vector of IPv4 and IPv6 addresses
         * 
         * @param domain - domain name for resolved
         * 
         * @throws std::invalid_argument if the domain name is invalid
         * @throws std::runtime_error if the internal error of getaddrinfo or inet_ntop
         */
        void setAddrsDest(std::string domain);
        /**
         * @brief Setter of the timeout
         * 
         * Method for setting the timeout
         * 
         * @param parsedTimeout - parsed timeout from the inputed arguments
         * 
         * @throws std::invalid_argument if the timeout is invalid
         */
        void setTimeout(std::string parsedTimeout);
        /**
         * @brief Setter of the ports
         * 
         * Method for setting the ports -> vector of TCP and UDP ports
         * 
         * @param parsedTcpPorts - converted TCP ports from the inputed arguments
         * @param parsedUdpPorts - converted UDP ports from the inputed arguments
         * 
         * @throws std::invalid_argument if the ports are invalid
         */
        void setPorts(std::string parsedTcpPorts, std::string parsedUdpPorts);
        /**
         * @brief Setter of the interface IPv4 and IPv6 addresses
         * 
         * Method for setting the interface IPv4 and IPv6 addresses -> interfaceIpv4 and interfaceIpv6
         * 
         * @throws std::invalid_argument if the interface is invalid
         * @throws std::runtime_error if the internal error of getifaddrs
         */
        void setInterfaceIpv();
        /**
         * @brief Method for converting the ports
         * 
         * Method for converting the ports from the inputed arguments
         * 
         * @param convertPorts - ports from the inputed arguments
         * 
         * @return vector of converted ports, if the ports are invalid, return empty vector
         */
        std::vector<int> convertPorts(std::string convertPorts);

        // Attributes of the class
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

