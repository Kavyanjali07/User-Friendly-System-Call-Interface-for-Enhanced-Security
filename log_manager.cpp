#include "log_manager.h"
#include <iostream>
#include <fstream>

using namespace std;

const string LOG_FILE = "auth_log.txt";

// Function to log events
void logEvent(const string& eventType, const string& details) {
    ofstream logFile(LOG_FILE, ios::app);
    if (logFile.is_open()) {
        logFile << "[" << eventType << "] " << details << endl;
        logFile.close();
    } else {
        cerr << "⚠ Error opening log file!\n";
    }
}

// Function to display logs
void displayLogs() {
    ifstream logFile(LOG_FILE);
    if (!logFile) {
        cerr << "⚠ No logs found!\n";
        return;
    }

    string line;
    cout << "📜 System Logs:\n";
    while (getline(logFile, line)) {
        cout << line << endl;
    }
    logFile.close();
}
