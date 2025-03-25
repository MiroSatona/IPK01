/**
 * @file parser_arguments.cpp
 * @name Martin Zůbek, x253206
 * @date 25.3. 2025
 * @brief Implementation of methods for class ParseArguments for parsing arguments
 * 
 */

#include "parser_arguments.hpp"
#include <iostream>
#include <string>

// Constructor
ParseArguments::ParseArguments(int argCount, char* args[]){
    // Initialize attributes of the class for default values
    this->helpOnly = false;
    this->interfaceOnly = false;
    this->parsedInterface = "";
    this->parsedDomain = "";
    this->parsedTcpPorts = "";
    this->parsedUdpPorts = "";
    this->timeout = "";
    // Call method for parsing arguments
    this->parse(argCount, args);
    // If help or interface flag is set, dont create object of ScannerParams
    if(!this->helpOnly && !this->interfaceOnly){
        this->scanParams = ScannerParams(this->parsedInterface, this->parsedDomain, this->parsedTcpPorts, this->parsedUdpPorts, this->timeout);
    }
}

// Getters of the class

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

// Method for parsing arguments

void ParseArguments::parse(int argCount, char*  args[]){
    // If there is only one argument and it is help flag, set helpOnly flag
    if ((argCount == 2 && (std::string(args[1]) == "-h" || std::string(args[1]) == "--help"))){
        this->helpOnly = true;
        return;
    }
    // If there is only one argument and it is interface flag, set interfaceOnly flag
    if(argCount == 1 || (argCount == 2 && (std::string(args[1]) == "-i" || std::string(args[1]) == "--interface"))){
        this->interfaceOnly = true;
        return;
    }

    int index = 1;
    // Parse arguments, by empty() swas detected duplicity and uncorect combination of arguments
    while (index < argCount) {
        std::string arg = args[index];
        if ((arg == "-i" || arg == "--interface") && index + 1 < argCount && this->parsedInterface.empty()) { 
            this->parsedInterface = args[index + 1];
            index += 2;
        }
        else if ((arg == "-u" || arg == "--pu") && this->parsedUdpPorts.empty() && index + 1 < argCount) { 
            this->parsedUdpPorts = args[index + 1];
            index += 2;
        }
        else if ((arg == "-t" || arg == "--pt") && this->parsedTcpPorts.empty() && index + 1 < argCount) { 
            this->parsedTcpPorts = args[index + 1];
            index += 2;
        }
        else if ((arg == "-w" || arg == "--wait") && this->timeout.empty() && index + 1 < argCount) {
            this->timeout = args[index + 1];
            index += 2;
        }
        else if (this->parsedDomain.empty()) {
            this->parsedDomain = arg;
            index++;
        }
        else{
            throw std::invalid_argument("");
            return;
        }
    }
    return;
}