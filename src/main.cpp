#include "../include/user_management.h"
#include "../include/log_manager.h"
#include "../include/syscall_handler.h"
#include <iostream>

int main(int argc, char* argv[]) {
    UserManager um;

    // If arguments passed, treat it as GUI interaction
    if (argc > 1) {
        std::string action = argv[1];

        if (action == "login" && argc == 4) {
            std::string username = argv[2];
            std::string password = argv[3];
            if (um.login(username, password)) {
                std::cout << "Login successful\n";
            } else {
                std::cout << "Login failed\n";
            }
            return 0;
        }

        else if (action == "register" && argc == 5) {
            std::string username = argv[2];
            std::string password = argv[3];
            std::string role = argv[4];
            if (um.addUser(username, password, role)) {
                std::cout << "User added successfully\n";
            } else {
                std::cout << "User registration failed\n";
            }
            return 0;
        }

        else if (action == "view_logs") {
            viewLogs();
            return 0;
        }

        else if (action == "run_cmd" && argc == 4) {
            std::string username = argv[2];
            std::string command = argv[3];
            secureSystemCall(username, command);
            return 0;
        }

        else {
            std::cerr << "Invalid arguments provided.\n";
            return 1;
        }
    }

    // Otherwise use CLI interface
    int choice;
    std::cout << "1. Login\n2. Register\nChoice: ";
    std::cin >> choice;

    std::string username, password, role;

    if (choice == 1) {
        std::cout << "Username: ";
        std::cin >> username;
        std::cout << "Password: ";
        std::cin >> password;

        if (!um.login(username, password)) {
            std::cout << "Login failed.\n";
            return 1;
        }
    }

    else if (choice == 2) {
        std::cout << "New Username: ";
        std::cin >> username;
        std::cout << "New Password: ";
        std::cin >> password;
        std::cout << "Role (Admin/User): ";
        std::cin >> role;

        if (um.addUser(username, password, role)) {
            std::cout << "Registration complete.\n";
        } else {
            std::cout << "Registration failed.\n";
        }
        return 0;
    }

    while (true) {
        std::cout << "\n1. View Logs\n2. Run Command\n3. Exit\nChoice: ";
        std::cin >> choice;

        if (choice == 1) {
            viewLogs();
        } else if (choice == 2) {
            std::string command;
            std::cout << "Enter command: ";
            std::cin >> command;
            secureSystemCall(um.getCurrentUser(), command);
        } else {
            break;
        }
    }

    return 0;
}
