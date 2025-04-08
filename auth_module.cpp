#include "auth_module.h"
#include <fstream>
#include <sstream>
#include <random>
#include <iostream>
#include <openssl/sha.h>

std::string generateSalt() {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string salt;
    std::default_random_engine rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    for (int i = 0; i < 16; ++i) {
        salt += charset[dist(rng)];
    }
    return salt;
}

std::string hashPassword(const std::string& password, const std::string& salt) {
    std::string input = password + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input.c_str(), input.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << (int)hash[i];
    return ss.str();
}

bool verify2FACode(const std::string& code) {
    return code == "123456"; // Replace with dynamic 2FA logic in real-world usage
}

bool isValidUser(const std::string& username, const std::string& password) {
    std::ifstream file("users/user_data.txt");
    if (!file) return false;

    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string user, hash, salt, role;
        std::getline(ss, user, ',');
        std::getline(ss, hash, ',');
        std::getline(ss, salt, ',');
        std::getline(ss, role, ',');

        if (user == username && hash == hashPassword(password, salt)) {
            return true;
        }
    }
    return false;
}

std::string getUserRole(const std::string& username) {
    std::ifstream file("users/user_data.txt");
    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string user, hash, salt, role;
        std::getline(ss, user, ',');
        std::getline(ss, hash, ',');
        std::getline(ss, salt, ',');
        std::getline(ss, role, ',');

        if (user == username) return role;
    }
    return "User";
}

