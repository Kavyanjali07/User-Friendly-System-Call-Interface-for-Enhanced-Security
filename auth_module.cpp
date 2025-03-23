#include "auth_module.h"
#include "users.h"
#include <iostream>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

// Function to hash password using SHA-256
std::string hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.length(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Function to validate user credentials
bool isValidUser(const std::string& username, const std::string& password) {
    if (users.find(username) != users.end()) {
        return users.at(username) == hashPassword(password);
    }
    return false;
}

// Function to get user role
std::string getUserRole(const std::string& username) {
    if (roles.find(username) != roles.end()) {
        return roles.at(username);
    }
    return "Unknown";
}
