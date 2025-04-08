#include "../include/syscall_handler.h"
#include "../include/log_manager.h"
#include "../include/auth_module.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <cstdlib>

bool isAdmin(const std::string& username) {
    return getUserRole(username) == "Admin";
}

bool isValidCommand(const std::string& command) {
    std::vector<std::string> allowed = {"ls", "whoami", "uptime", "pwd"};
    return std::find(allowed.begin(), allowed.end(), command) != allowed.end();
}

void secureSystemCall(const std::string& username, const std::string& command) {
    if (!isValidCommand(command)) {
        std::cout << "Invalid or unauthorized command.\n";
        logSystemCall(username, "Unauthorized attempt: " + command);
        return;
    }
    std::system(command.c_str());
    logSystemCall(username, "Executed: " + command);
}
