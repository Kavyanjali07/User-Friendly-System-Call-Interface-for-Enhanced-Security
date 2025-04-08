#include "../include/syscall_handler.h"
#include "../include/log_manager.h"
#include "../include/auth_module.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <string>

bool isAdmin(const std::string& username) {
    return getUserRole(username) == "Admin";
}

bool isValidCommand(const std::string& command, const std::string& role) {
    // Extract base command (first word before any space)
    std::string baseCommand = command;
    size_t spacePos = command.find(' ');
    if (spacePos != std::string::npos) {
        baseCommand = command.substr(0, spacePos);
    }
    
    // Commands available for regular users
    std::vector<std::string> userCommands = {"ls", "pwd", "cat", "echo"};
    
    // Commands available only for admins
    std::vector<std::string> adminCommands = {"kill", "shutdown", "uptime", "ifconfig", "netstat", "ps", "top", "reboot", 
                          "apt", "apt-get", "systemctl", "service", "mount", "umount", "fdisk",
                          "whoami", "useradd", "usermod", "userdel", "groupadd", "passwd"};
    
    // Check if the command is allowed based on user role
    if (role == "Admin") {
        return (std::find(userCommands.begin(), userCommands.end(), baseCommand) != userCommands.end() ||
                std::find(adminCommands.begin(), adminCommands.end(), baseCommand) != adminCommands.end());
    } else {
        return std::find(userCommands.begin(), userCommands.end(), baseCommand) != userCommands.end();
    }
}

// Updated secureSystemCall function with better command validation
void secureSystemCall(const std::string& username, const std::string& commandInput) {
    std::string role = getUserRole(username);
    
    // Extract base command (first word before any space)
    std::string baseCommand = commandInput;
    size_t spacePos = commandInput.find(' ');
    if (spacePos != std::string::npos) {
        baseCommand = commandInput.substr(0, spacePos);
    }
    
    // Commands available for regular users
    std::vector<std::string> userCommands = {"ls", "pwd", "cat", "echo"};
    
    // Commands available only for admins
    std::vector<std::string> adminCommands = {"kill", "shutdown", "uptime", "ifconfig", "netstat", "ps", "top", "reboot", 
                          "apt", "apt-get", "systemctl", "service", "mount", "umount", "fdisk",
                          "whoami", "useradd", "usermod", "userdel", "groupadd", "passwd"};
    
    // Check if the command is allowed based on user role
    bool isAllowed = false;
    if (role == "Admin") {
        isAllowed = (std::find(userCommands.begin(), userCommands.end(), baseCommand) != userCommands.end() ||
                    std::find(adminCommands.begin(), adminCommands.end(), baseCommand) != adminCommands.end());
    } else {
        isAllowed = std::find(userCommands.begin(), userCommands.end(), baseCommand) != userCommands.end();
    }
    
    if (!isAllowed) {
        std::cout << "Invalid or unauthorized command. Access denied.\n";
        logSystemCall(username, "Unauthorized attempt: " + commandInput);
        return;
    }
    
    // Build safe command execution
    std::string safeCommand;
    if (baseCommand == "ls") {
        // Handle ls command with potential arguments
        safeCommand = "ls ";
        if (spacePos != std::string::npos) {
            std::string args = commandInput.substr(spacePos + 1);
            // Only allow specific safe arguments
            if (args == "-l" || args == "-a" || args == "-la" || args == "-al") {
                safeCommand += args;
            }
        }
    } 
    else if (baseCommand == "cat") {
        // Handle cat with basic path validation
        safeCommand = "cat ";
        if (spacePos != std::string::npos) {
            std::string filePath = commandInput.substr(spacePos + 1);
            // Prevent path traversal by excluding '..'
            if (filePath.find("..") == std::string::npos) {
                safeCommand += filePath;
            } else {
                std::cout << "Invalid path. Directory traversal not allowed.\n";
                logSystemCall(username, "Security violation: " + commandInput);
                return;
            }
        }
    }
    else if (baseCommand == "echo") {
        // Echo is relatively safe
        safeCommand = commandInput;
    }
    else if (baseCommand == "pwd") {
        // pwd doesn't take dangerous arguments
        safeCommand = "pwd";
    }
    else if (role == "Admin") {
        // For admin commands, just use as-is but with validation already done
        safeCommand = commandInput;
    }
    
    // Execute the safe command
    std::system(safeCommand.c_str());
    logSystemCall(username, "Executed: " + commandInput);
}
