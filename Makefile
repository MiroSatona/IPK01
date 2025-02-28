# Makefile for IPK Project

# Author: Martin Zůbek
# Login: x253206
# Date: 20.2. 2025

# Compiler and flags
CPP = g++
FLAGS = -std=c++20 -Wall -Wextra -Wpedantic

# Directories
SRC_DIR = src

# Program
PROG = ipk-l4-scan

# Source files
SRC = $(wildcard $(SRC_DIR)/*.cpp)
OBJ = $(SRC:.cpp=.o) 

# Compile 
$(PROG): $(OBJ)
	@$(CPP) $(FLAGS) -o $(PROG) $(OBJ)

%.o: %.cpp
	@$(CPP) $(FLAGS) -c $< -o $@

# Run program
run:
	@./$(PROG)

# Run tests for parse invalid input
run_test_parse:
	@cd tests/parse && chmod +x parse.sh && ./parse.sh 

# Clean objects and program
clean:
	@rm -f $(PROG) $(OBJ)

.PHONY: clean run