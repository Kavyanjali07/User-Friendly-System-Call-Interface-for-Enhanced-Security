#include "auth_module.h"
#include "log_manager.h"  // For logging authentication attempts
#include <iostream>
#include <unordered_map>
using namespace std;


// Simulated user database
unordered_map<string, string> users = {
    {"admin", "admin123"},
    {"user1", "user123"},
    {"Kavya", "Kavya123"},
    {"Sargun", "Sargun123"},
    {"Akshita", "Akshita123"}
};

// Function to validate user login
bool isValidUser(const string& username, const string& password) {
    if (users.find(username) != users.end() && users[username] == password) {
        logAuthentication(username, "Login Successful");
        return true;
    }
    logAuthentication(username, "Login Failed");
    return false;
}

// Function to log authentication attempts
void logAuthentication(const string& username, const string& status) {
    logEvent("AUTH", username + " - " + status);
}
