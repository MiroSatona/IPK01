#include "parser_arguments.hpp"
#include <iostream>
#include <string>


ParseArguments::ParseArguments(int argCount, char* args[]){
    this->helpOnly = false;
    this->interfaceOnly = false;
    this->parsedInterface = "";
    this->parsedDomain = "";
    this->parsedTcpPorts = "";
    this->parsedUdpPorts = "";
    this->timeout = "";
    this->parse(argCount, args);
    this->scanParams = ScannerParams(this->parsedInterface, this->parsedDomain, this->parsedTcpPorts, this->parsedUdpPorts, this->timeout);

}


bool ParseArguments::isHelpOnly(){
    return this->helpOnly;
}

bool ParseArguments::isInterfaceOnly(){
    return this->interfaceOnly;
}

std::string ParseArguments::getParsedInterface(){
    return this->parsedInterface;
}

std::string ParseArguments::getParsedDomain(){
    return this->parsedDomain;
}

std::string ParseArguments::getParsedTcpPorts(){
    return this->parsedTcpPorts;
}

std::string ParseArguments::getParsedUdpPorts(){
    return this->parsedUdpPorts;
}

std::string ParseArguments::getTimeout(){
    return this->timeout;
}

ScannerParams ParseArguments::getScanParams(){
    return this->scanParams;
}

void ParseArguments::parse(int argCount, char* args[]){

    if ((argCount == 2 && (std::string(args[1]) == "-h" || std::string(args[1]) == "--help"))){
        this->helpOnly = true;
        return;
    }

    if(argCount == 1 || (argCount == 2 && (std::string(args[1]) == "-i" || std::string(args[1]) == "--interface"))){
        this->interfaceOnly = true;
        return;
    }

    int index = 1;
    while (index < argCount) {
        std::string arg = args[index];
        if ((arg == "-i" || arg == "--interface") && index + 1 < argCount && this->parsedInterface.empty()) {
            this->parsedInterface = args[index + 1];
            index += 2;
        }
        else if ((arg == "-u" || arg == "--pu") && this->parsedUdpPorts.empty() && index + 1 < argCount && !this->parsedUdpPorts.empty()) {
            this->parsedUdpPorts = args[index + 1];
            index += 2;
        }
        else if ((arg == "-t" || arg == "--pt") && this->parsedTcpPorts.empty() && index + 1 < argCount && !this->parsedTcpPorts.empty()) {
            this->parsedTcpPorts = args[index + 1];
            index += 2;
        }
        else if ((arg == "-w" || arg == "--wait") && this->timeout.empty() && index + 1 < argCount && !this->timeout.empty()) {
            this->timeout = args[index + 1];
            index += 2;
        }
        else if (this->parsedDomain.empty()) {
            this->parsedDomain = arg;
            index++;
        }
        else{
            throw std::invalid_argument("Invalid arguments were pasted!\n");
            return;
        }
    }
    return;
}