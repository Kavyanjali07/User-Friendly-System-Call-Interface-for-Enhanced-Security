#include "syscall_handler.h"
#include "auth_module.h"
#include "log_manager.h"
#include <iostream>

using namespace std;

bool isAdmin(const std::string& username) {
    return getUserRole(username) == "Admin";
}

void secureSystemCall(const std::string& username, const std::string& command) {
    std::vector<std::string> adminOnlyCommands = {"shutdown", "reboot"};

    if (std::find(adminOnlyCommands.begin(), adminOnlyCommands.end(), command) != adminOnlyCommands.end()) {
        if (!isAdmin(username)) {
            logSystemCall(username, "Unauthorized admin command attempt: " + command);
            std::cout << "Error: You do not have permission to execute this command!" << std::endl;
            return;
        }
    }
    system(command.c_str());
    logSystemCall(username, "Executed command: " + command);
}

// Function to authenticate user
bool authenticateUser(const string& username, const string& password) {
    return isValidUser(username, password);
}

bool isValidCommand(const std::string& command) {
    // Define allowed commands
    std::vector<std::string> allowedCommands = {"ls", "pwd", "whoami", "uptime"};
    return std::find(allowedCommands.begin(), allowedCommands.end(), command) != allowedCommands.end();
}

void secureSystemCall(const std::string& username, const std::string& command) {
    if (!isValidCommand(command)) {
        logSystemCall(username, "Unauthorized command attempt: " + command);
        std::cout << "Error: Command not allowed!" << std::endl;
        return;
    }
    system(command.c_str());
    logSystemCall(username, "Executed command: " + command);
}

}
