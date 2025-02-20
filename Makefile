# Makefile for IPK Project

# Author: Martin Zůbek
# Login: x253206
# Date: 20.2. 2025

# Compiler and flags
CPP = g++
FLAGS = -std=c++20 -Wall -Wextra -Wpedantic

# Directories
SRC_DIR = src
OBJ_DIR = obj

# Program
PROG = ipk-l4-scan

# Source files
SRC = $(wildcard $(SRC_DIR)/*.cpp)
OBJ = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRC))

# Compile 
$(PROG): $(OBJ)
	@$(CPP) $(FLAGS) -o $(PROG) $(OBJ)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	@$(CPP) $(FLAGS) -c $< -o $@

# Objects directory
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)
	
# Run program
run:
	@./$(PROG)
# Clean objects and program
clean:
	@rm -rf $(PROG) $(OBJ_DIR)

.PHONY: clean run