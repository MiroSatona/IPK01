#ifndef PARSE_ARGUMENTS_HPP
#define PARSE_ARGUMENTS_HPP // PARSE_ARGUMENTS_HPP

#include <iostream>
#include <string>
#include "scanner_params.hpp"

class ParseArguments{
    public:

        ParseArguments(int argCount, char*  args[]);
        bool isHelpOnly();
        bool isInterfaceOnly();

        std::string getParsedInterface();
        std::string getParsedDomain();
        std::string getParsedTcpPorts();
        std::string getParsedUdpPorts();
        std::string getTimeout();
        ScannerParams getScanParams();

        
    private:
        std::string parsedInterface;
        std::string parsedDomain;
        std::string parsedTcpPorts;
        std::string parsedUdpPorts;
        std::string timeout;
        ScannerParams scanParams;

        bool helpOnly;
        bool interfaceOnly;

        void parse(int argCount, char*  args[]);
};


#endif // PARSE_ARGUMENTS_HPP