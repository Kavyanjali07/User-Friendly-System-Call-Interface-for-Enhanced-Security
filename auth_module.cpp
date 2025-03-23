#include "auth_module.h"
#include "users.h"
#include <iostream>

bool isValidUser(const std::string& username, const std::string& password) {
    return (users.find(username) != users.end() && users[username] == password);
}

int main() {
    std::string username, password;
    std::cout << "Enter Username: ";
    std::cin >> username;
    std::cout << "Enter Password: ";
    std::cin >> password;

    if (isValidUser(username, password)) {
        std::cout << "Login successful!\n";
    } else {
        std::cout << "Invalid credentials!\n";
    }
}
