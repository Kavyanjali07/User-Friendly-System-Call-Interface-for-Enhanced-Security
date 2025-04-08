# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Iinclude
LDFLAGS = -lssl -lcrypto

# Directories
SRC_DIR = src
BUILD_DIR = build
INCLUDE_DIR = include

# Source and Object files
SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SOURCES))

# Output binary
TARGET = secure_auth

# Default rule
all: $(BUILD_DIR) $(TARGET)

# Linking final binary
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

# Compiling source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Create build dir if not exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean
clean:
	rm -rf $(BUILD_DIR) $(TARGET)
