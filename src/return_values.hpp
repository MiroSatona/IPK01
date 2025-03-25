/**
 * @file return_values.hpp
 * @author Martin Zůbek, x253206
 * @date 25.3. 2025
 * @brief Header file for the return values of program
 */


#ifndef RETURN_VALUES_HPP
#define RETURN_VALUES_HPP // RETURN_VALUES_HPP

/**
 * @brief Enum for return values of the program
 * 
 * This enum is used to return values of the program.
 */
enum retVal{
    SUCCESS = 0,
    INVALID_ARGUMENTS = 1,
    INTERNAL_ERROR = 99
};

#endif // RETURN_VALUES_HPP
