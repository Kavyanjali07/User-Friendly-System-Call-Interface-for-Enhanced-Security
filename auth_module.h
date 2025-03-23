#ifndef AUTH_MODULE_H
#define AUTH_MODULE_H

#include <string>

bool isValidUser(const std::string& username, const std::string& password);
std::string hashPassword(const std::string& password);
std::string getUserRole(const std::string& username);

#endif // AUTH_MODULE_H

