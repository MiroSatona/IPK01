/**
 * @file parser_arguments.hpp
 * @author Martin Zůbek, x253206
 * @date 25.3. 2025
 * @brief Header file for class for parsing arguments
 * 
 */

#ifndef PARSE_ARGUMENTS_HPP
#define PARSE_ARGUMENTS_HPP // PARSE_ARGUMENTS_HPP

#include <iostream>
#include <string>
#include "scanner_params.hpp"

/**
 * @brief Class for parsing arguments
 * 
 * This class is used for parsing arguments from command line.
 */
class ParseArguments{
    public:
        /**
         * @brief Construct of ParseArguments
         *
         * This constructor initializes the object and parses the arguments.
         * 
         * @param argCount Number of arguments
         * @param args Array of arguments from command line
         * 
         */
        ParseArguments(int argCount, char*  args[]);
        /**
         * @brief Method for checking if program will only print help
         * 
         * This method returns true if program will only print help.
         * 
         * @return true if program will only print help, false otherwise
         */
        bool isHelpOnly();
        /**
         * @brief Method for checking if program will only print interface
         * 
         * This method returns true if program will only print interface.
         * 
         * @return true if program will only print interface, false otherwise
         */
        bool isInterfaceOnly();
        /**
         * @brief Getter of parsed interface
         * 
         * This method returns parsed interface.
         * 
         * @return parsed interface
         */
        std::string getParsedInterface();
        /**
         * @brief Getter of parsed domain
         * 
         * This method returns parsed domain.
         * 
         * @return parsed domain
         */
        std::string getParsedDomain();
        /**
         * @brief Getter of parsed TCP ports
         * 
         * This method returns parsed TCP ports.
         * 
         * @return parsed TCP ports
         */
        std::string getParsedTcpPorts();
        /**
         * @brief Getter of parsed UDP ports
         * 
         * This method returns parsed UDP ports.
         * 
         * @return parsed UDP ports
         */
        std::string getParsedUdpPorts();
        /**
         * @brief Getter of timeout
         * 
         * This method returns timeout.
         * 
         * @return parsed timeout
         */
        std::string getTimeout();
        /**
         * @brief Getter of scan parameters
         * 
         * This method returns scan parameters.
         * 
         * @return object of ScannerParams
         */
        ScannerParams getScanParams();

    private:
        // Attributes of the class
        std::string parsedInterface;
        std::string parsedDomain;
        std::string parsedTcpPorts;
        std::string parsedUdpPorts;
        std::string timeout;
        // Object of ScannerParams
        ScannerParams scanParams;
        // Flags for help and interface
        bool helpOnly;
        bool interfaceOnly;
        /**
         * @brief Method for parsing arguments
         * 
         * This method parses arguments from command line.
         * 
         * @param argCount Number of arguments
         * @param args Array of arguments from command line
         * 
         */
        void parse(int argCount, char*  args[]);
};


#endif // PARSE_ARGUMENTS_HPP