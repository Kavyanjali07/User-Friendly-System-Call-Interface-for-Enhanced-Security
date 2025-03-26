#include <ctime>  // Add this for time functions
void displayLogs() {
    std::ifstream logFile("syscall_log.txt");
    if (!logFile) {
        std::cerr << "Error: Unable to open log file!" << std::endl;
        return;
    }

    std::string line;
    std::cout << "==== System Call Logs ====" << std::endl;
    while (std::getline(logFile, line)) {
        std::cout << line << std::endl;
    }
    logFile.close();
}

void logEvent(const std::string& username, const std::string& event) {
    std::ofstream logFile("syscall_log.txt", std::ios::app);
    if (!logFile) {
        std::cerr << "Error: Unable to open log file!" << std::endl;
        return;
    }

    // Get current time
    time_t now = time(0);
    char* dt = ctime(&now);  // Convert time to string format

    // Remove newline character from time string
    dt[strlen(dt) - 1] = '\0';

    logFile << "[" << dt << "] " << username << " - " << event << std::endl;
    logFile.close();
}
