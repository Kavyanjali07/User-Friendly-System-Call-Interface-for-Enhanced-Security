#include "syscall_handler.h"
#include "auth_module.h"
#include "log_manager.h"
#include <iostream>

using namespace std;

// Function to authenticate user
bool authenticateUser(const string& username, const string& password) {
    return isValidUser(username, password);
}

// Function to execute a secure system call
void secureSystemCall(const string& username, const string& command) {
    if (users.find(username) != users.end()) { 
        cout << "🔒 Executing secure command: " << command << endl;
        logEvent("SYSCALL", username + " executed command: " + command);
    } else {
        cout << "⛔ Unauthorized user! Cannot execute command.\n";
        logEvent("SYSCALL", username + " attempted unauthorized access!");
    }
}
