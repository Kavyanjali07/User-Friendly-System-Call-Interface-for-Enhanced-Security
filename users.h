#ifndef USERS_H
#define USERS_H

#include <unordered_map>
#include <string>

// Store usernames and their SHA-256 hashed passwords
const std::unordered_map<std::string, std::string> users = {
    {"Kavya", "0d107d09f5bbe40cade3de5c71e9e9b7"},   // Password: Kavya123
    {"Sargun", "e99a18c428cb38d5f260853678922e03"}, // Password: Sargun123
    {"Akshita", "4ef99ff929e7b4c7e9d17f24b0383a37"} // Password: Akshita123
};

// Store user roles (Admin/User)
const std::unordered_map<std::string, std::string> roles = {
    {"Kavya", "Admin"},
    {"Sargun", "User"},
    {"Akshita", "User"}
};

#endif // USERS_H
