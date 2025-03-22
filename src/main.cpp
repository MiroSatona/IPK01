#include <iostream>
#include "parser_arguments.hpp"
#include "command.hpp"
#include "scanner_params.hpp"

int main(int argc, char *argv[])
{
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

      

   }
   catch(std::exception &e){
      std::cerr << "Error: " << e.what() << std::endl;
      return 1;
   }
    
   return 0;
}
