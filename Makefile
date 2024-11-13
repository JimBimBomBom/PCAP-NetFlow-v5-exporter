# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -Wall -Wextra -pedantic -std=c++11
CXXLIBS = -lpcap

# Name of the output executable
TARGET = p2nprobe

# Source file
SRC = ./p2nprobe.cpp

# Object file (generated from the source)
OBJ = $(SRC:.cpp=.o)

# The default target
all: $(TARGET)

# Rule to build the executable
$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) -v $(OBJ) $(CXXLIBS)

# Rule to compile the source into object file
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up generated files
clean:
	rm -f $(OBJ) $(TARGET)

# Phony targets (they are not actual files)
.PHONY: all clean
