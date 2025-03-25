/**
 * @file main.cpp
 * @name: Martin Zůbek, x253206
 * @date 25.3. 2025
 * @brief Main file for the IPK project 1 [OMEGA] 
 */

#include <iostream>
#include "parser_arguments.hpp"
#include "command.hpp"
#include "scanner_params.hpp"
#include "scanner.hpp"
#include "return_values.hpp"

int main(int argc, char *argv[]){

   try{ 
      // Parse arguments
      ParseArguments args(argc, argv);

      // Check if only help was requested
      if(args.isHelpOnly()){
         HelpCommand helpCommand;
         helpCommand.performExecute();
         return 0;
      }

      // Check if only interfaces were requested
      if(args.isInterfaceOnly()){
         InterfaceCommand interfaceCommand;
         interfaceCommand.performExecute();
         return 0;
      }

      // Get scan parameters
      ScannerParams scanParams = args.getScanParams();

      // Set what to scan and scan
      if (!scanParams.getTcpPorts().empty() && !scanParams.getIp4AddrDest().empty()){
         TcpIpv4Scanner tcpIpv4(scanParams);
         tcpIpv4.scan();
      }
      
      if (!scanParams.getTcpPorts().empty() && !scanParams.getIp6AddrDest().empty()){
         TcpIpv6Scanner tcpIpv6(scanParams);
         tcpIpv6.scan();
      }
      
      if (!scanParams.getUdpPorts().empty() && !scanParams.getIp4AddrDest().empty()){
         UdpIpv4Scanner udpIpv4(scanParams);
         udpIpv4.scan();
      }

      if (!scanParams.getUdpPorts().empty() && !scanParams.getIp6AddrDest().empty()){
         UdpIpv6Scanner udpIpv6(scanParams);
         udpIpv6.scan();
      }
   
   }
   // Catch error of invlaid input
   catch (const std::invalid_argument&) {
   std::cerr << "Error: Invalid input was pasted!" << std::endl;
   return INVALID_ARGUMENTS;
   // Catch internal error of program
   }catch (const std::runtime_error& e) {
   std::cerr << "Error: " << e.what() << std::endl;
   return INTERNAL_ERROR;
   }


   return SUCCESS;
}
