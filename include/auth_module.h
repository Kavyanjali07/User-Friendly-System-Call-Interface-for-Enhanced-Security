#ifndef AUTH_MODULE_H
#define AUTH_MODULE_H

#include <string>

std::string hashPassword(const std::string& password, const std::string& salt);
bool isValidUser(const std::string& username, const std::string& password);
std::string getUserRole(const std::string& username);
void logAuthentication(const std::string& username, const std::string& status);

#endif
