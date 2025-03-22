/**
 * @file command.hpp
 * @author Martin Zůbek, x253206
 * @brief Header file for the Command pattern
 */


#ifndef COMMAND_HPP 
#define COMMAND_HPP // COMMAND_HPP

/**
 * @class Command
 * @brief Abstract class for the Command pattern
 *  
 * This class is an abstract class for the Command pattern. It has one method that will be overridden by the derived classes.
 */
class Command{
    public:
        /**
         * @brief Preforms the command
         * 
         * This method is pure virtual and will be overridden by the derived classes.
         */
        virtual void performExecute() = 0;
        

};

/**
 * @class HelpCommand
 * @brief Class for the help command
 * 
 * This class is derived from the Command class. It overrides the performExecute method and prints the help message.
 */
class HelpCommand: public Command{
    public:
        /**
         * @brief Preforms the help command
         * 
         * This method prints the help message. 
         */
        void performExecute() override; 
};
/**
 * @class InterfaceCommand
 * @brief Class for the interface command
 * 
 * This class is derived from the Command class. It overrides the performExecute method and prints the interfaces.
 */
class InterfaceCommand: public Command{
    public:
        /**
         * @brief Preforms the interface command
         * 
         * This method prints the active interfaces.
         */
        void performExecute() override; // Preforms the interface command
};


#endif // COMMAND_HPP