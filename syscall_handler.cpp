#include "syscall_handler.h"
#include "log_manager.h"
#include "auth_module.h"
#include <iostream>
#include <algorithm>
#include <cstdlib>

bool isAdmin(const std::string& username) {
    return getUserRole(username) == "Admin";
}

bool isValidCommand(const std::string& command) {
    std::vector<std::string> allowedCommands = {"ls", "pwd", "whoami", "uptime", "date"};
    return std::find(allowedCommands.begin(), allowedCommands.end(), command) != allowedCommands.end();
}

void secureSystemCall(const std::string& username, const std::string& command) {
    std::vector<std::string> adminOnlyCommands = {"shutdown", "reboot"};

    if (std::find(adminOnlyCommands.begin(), adminOnlyCommands.end(), command) != adminOnlyCommands.end()) {
        if (!isAdmin(username)) {
            logEvent(username, "Unauthorized admin command attempt: " + command);
            std::cout << "Permission denied: You are not an Admin." << std::endl;
            return;
        }
    }

    if (!isValidCommand(command)) {
        logEvent(username, "Invalid command attempt: " + command);
        std::cout << "Error: Command not allowed." << std::endl;
        return;
    }

    logEvent(username, "Executed: " + command);
    system(command.c_str());
}
