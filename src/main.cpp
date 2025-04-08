#include "../include/user_management.h"
#include "../include/log_manager.h"
#include "../include/syscall_handler.h"
#include <iostream>

int main() {
    UserManager um;
    int choice;

    std::cout << "1. Login\n2. Register\nChoice: ";
    std::cin >> choice;

    std::string username, password, role;
    if (choice == 1) {
        std::cout << "Username: "; std::cin >> username;
        std::cout << "Password: "; std::cin >> password;

        if (!um.login(username, password)) {
            std::cout << "Login failed.\n";
            return 1;
        }
    } else if (choice == 2) {
        std::cout << "New Username: "; std::cin >> username;
        std::cout << "New Password: "; std::cin >> password;
        std::cout << "Role (Admin/User): "; std::cin >> role;
        um.addUser(username, password, role);
        std::cout << "Registration complete.\n";
        return 0;
    }

    while (true) {
        std::cout << "\n1. View Logs\n2. Run Command\n3. Exit\nChoice: ";
        std::cin >> choice;

        if (choice == 1) viewLogs();
        else if (choice == 2) {
            std::string cmd;
            std::cout << "Enter command: ";
            std::cin >> cmd;
            secureSystemCall(um.getCurrentUser(), cmd);
        } else break;
    }

    return 0;
}
