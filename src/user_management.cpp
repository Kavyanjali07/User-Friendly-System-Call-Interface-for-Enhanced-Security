#include "../include/user_management.h"
#include "../include/auth_module.h"
#include "../include/log_manager.h"
#include <fstream>

UserManager::UserManager() : loggedIn(false) {}

bool UserManager::login(const std::string& username, const std::string& password) {
    if (isValidUser(username, password)) {
        currentUser = username;
        currentRole = getUserRole(username);
        loggedIn = true;
        logAuthentication(username, "Success");
        return true;
    }
    logAuthentication(username, "Failure");
    return false;
}

bool UserManager::addUser(const std::string& username, const std::string& password, const std::string& role) {
    std::ofstream file("users/user_data.txt", std::ios::app);
    file << username << " " << hashPassword(password, username) << " " << role << "\n";
    return true;
}

std::string UserManager::getCurrentUser() { return currentUser; }
std::string UserManager::getCurrentRole() { return currentRole; }
bool UserManager::isLoggedIn() { return loggedIn; }

