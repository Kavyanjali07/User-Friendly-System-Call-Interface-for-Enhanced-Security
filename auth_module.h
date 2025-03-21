#ifndef AUTH_MODULE_H
#define AUTH_MODULE_H

#include <iostream>
#include <unordered_map>
#include <string>

using namespace std;

// ✅ Declare the users map as an external variable
extern unordered_map<string, string> users;

// ✅ Function declarations
bool isValidUser(const string& username, const string& password);
void logAuthentication(const string& username, const string& status);

#endif // AUTH_MODULE_H
