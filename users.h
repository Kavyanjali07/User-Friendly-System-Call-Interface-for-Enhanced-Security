#ifndef USERS_H
#define USERS_H

#include <unordered_map>
#include <string>

// Hardcoded users (In future, we can load this from a secure database)
std::unordered_map<std::string, std::string> users = {
    {"admin", "admin123"},
    {"user1", "password1"},
    {"user2", "password2"}
};

#endif
