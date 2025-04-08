#include "../include/auth_module.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <openssl/sha.h>

std::string hashPassword(const std::string& password, const std::string& salt) {
    std::string input = password + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << (int)hash[i];
    return oss.str();
}

bool isValidUser(const std::string& username, const std::string& password) {
    std::ifstream file("users/user_data.txt");
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string uname, hashedPwd, role;
        if (iss >> uname >> hashedPwd >> role) {
            if (uname == username) {
                return hashedPwd == hashPassword(password, username);
            }
        }
    }
    return false;
}

std::string getUserRole(const std::string& username) {
    std::ifstream file("users/user_data.txt");
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string uname, pwd, role;
        if (iss >> uname >> pwd >> role) {
            if (uname == username) {
                return role;
            }
        }
    }
    return "User";
}

void logAuthentication(const std::string& username, const std::string& status) {
    std::ofstream logFile("logs/system_logs.txt", std::ios::app);
    logFile << "[AUTH] User: " << username << ", Status: " << status << "\n";
}
