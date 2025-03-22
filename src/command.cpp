/**
* @file command.cpp
* @author Martin Zůbek, x253206
* @brief Implementation file for the Command pattern
*/

#include "command.hpp"
#include <iostream>
#include <string>
#include <ifaddrs.h>
#include <net/if.h>
#include <unordered_set>

// Performs the help command
void HelpCommand::performExecute() {
    // Help message
    std::string helpMessage =
        "Usage: ./ipk-l4-scan [OPTIONS] [hostname | ip-address]\n"
        "\n"
        "This program scans TCP/UDP ports (IPv4/IPv6) and reports their states.\n"
        "\n"
        "OPTIONS:\n"
        "  -h, --help                Show this help message and exit. Cannot be combined with any other argument.\n"
        "  -i, --interface <iface>   Specify network interface.\n"
        "  -t, --pt <port-range>     Scan TCP ports.\n"
        "  -u, --pu <port-range>     Scan UDP ports.\n"
        "  -w, --wait <ms>           Set timeout in milliseconds.\n"
        "\n"
        "BEHAVIOR:\n"
        "  - If no scanning options are passed, a list of active interfaces will be printed.\n"
        "  - If only -i or --interface is passed without an argument, a list of active interfaces will be printed.\n"
        "  - The --help or -h option cannot be combined with any other argument and must be used alone.\n"
        "  - Ports can be specified as:\n"
        "      - a single port (e.g. 80)\n"
        "      - a range (e.g. 80-100)\n"
        "      - a comma-separated list (e.g. 80,443)\n"
        "    Note: These formats cannot be combined.\n";

    // Print help message
    std::cout << helpMessage << std::endl;
}

// Preforms the interface command
void InterfaceCommand::performExecute(){
    // Prepare list of active interfaces
    struct ifaddrs *listInterfaces;
    // Set of active interfaces
    std::unordered_set<std::string> interfaces;
    // Get list of active interfaces
    if (getifaddrs(&listInterfaces) == -1) {
        throw std::runtime_error("getifaddrs failed!");
    }
    
    // Iterate over list of interfaces and save active interfaces
    for (struct ifaddrs *interface = listInterfaces; interface != nullptr; interface = interface->ifa_next) {
        if ((interface->ifa_flags & IFF_UP) && interface->ifa_addr != nullptr) {
            interfaces.insert(std::string(interface->ifa_name));
        }
    }
    // Print active interfaces or message if no active interfaces were found
    if(interfaces.empty()){
        std::cout << "No ative interfaces found!" << std::endl;
    }
    else{
        std::cout << "List of active interfaces: " << std::endl;
        for (std::string intf : interfaces) {
            std::cout << intf << std::endl;
        }
    }
    // Free allocated memory
    freeifaddrs(listInterfaces);
}
