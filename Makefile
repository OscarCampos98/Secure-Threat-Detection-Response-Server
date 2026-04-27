# Compiler 
CXX = g++

# Compiler flags:
# -std=c++17  -> use modern C++
# -Wall       -> show common warnings
# -Wextra     -> show extra warnings
# -pthread    -> required later for thread-per-client support

CXXFLAGS = -std=c++17 -Wall -Wextra -pthread

# Output binary name
TARGET = threat_server

# Source files
SRCS = src/main.cpp src/server.cpp src/parser.cpp src/threat_engine.cpp

# Default build target 
all:
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET)

# Remove compiler binary 
clean:
	rm -f $(TARGET)