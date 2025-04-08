#include "log_manager.h"
#include <fstream>
#include <ctime>
#include <iostream>

void logEvent(const std::string& username, const std::string& action) {
    std::ofstream logfile("logs/system_logs.txt", std::ios::app);
    if (!logfile) {
        std::cerr << "Failed to open log file!" << std::endl;
        return;
    }

    time_t now = time(0);
    char* dt = ctime(&now);
    dt[strcspn(dt, "\n")] = '\0'; // remove newline

    logfile << "[" << dt << "] "
            << "[" << username << "] "
            << action << std::endl;

    logfile.close();
}

