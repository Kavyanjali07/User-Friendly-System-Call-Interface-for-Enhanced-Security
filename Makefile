# Compiler
CXX = g++

# Compiler Flags
CXXFLAGS = -Wall -Wextra -std=c++17 -lssl -lcrypto

# Source Files
SRCS = src/auth_module.cpp src/log_manager.cpp src/syscall_handler.cpp src/users.cpp

# Header Files
HEADERS = include/auth_module.h include/log_manager.h include/syscall_handler.h include/users.h

# Output Executable
TARGET = secure_syscall

# Build the executable
all: $(TARGET)

$(TARGET): $(SRCS) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET)

# Clean command
clean:
	rm -f $(TARGET)
