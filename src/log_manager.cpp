#include "../include/log_manager.h"
#include <fstream>
#include <iostream>

void logSystemCall(const std::string& username, const std::string& command) {
    std::ofstream log("logs/system_logs.txt", std::ios::app);
    log << "[SYSCALL] User: " << username << ", Command: " << command << "\n";
}

void viewLogs() {
    std::ifstream log("logs/system_logs.txt");
    std::string line;
    while (std::getline(log, line)) {
        std::cout << line << "\n";
    }
}
