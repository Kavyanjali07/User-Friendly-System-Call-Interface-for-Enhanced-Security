#include "auth_module.h"
#include "log_manager.h"
#include "user_management.h"
#include "syscall_handler.h"

#include <iostream>
#include <string>

using namespace std;

int main() {
    UserManager userManager;
    int choice;
    
    while (true) {
        cout << "\n--- Secure System Call Interface ---" << endl;
        cout << "1. Register New User" << endl;
        cout << "2. Login" << endl;
        cout << "3. Exit" << endl;
        cout << "Enter your choice: ";
        cin >> choice;

        if (choice == 1) {
            string newUser, newPass, newRole;
            cout << "Enter new username: ";
            cin >> newUser;
            cout << "Enter new password: ";
            cin >> newPass;
            cout << "Enter role (Admin/User): ";
            cin >> newRole;

            if (userManager.addUser(newUser, newPass, newRole)) {
                cout << "User added successfully!" << endl;
            } else {
                cout << "User could not be added." << endl;
            }
        } else if (choice == 2) {
            string uname, pass;
            cout << "Enter username: ";
            cin >> uname;
            cout << "Enter password: ";
            cin >> pass;

            if (userManager.login(uname, pass)) {
                cout << "\nWelcome, " << uname << " (" << userManager.getCurrentRole() << ")" << endl;
                while (true) {
                    cout << "\n--- Menu ---" << endl;
                    cout << "1. Execute Secure System Call" << endl;
                    cout << "2. View Logs" << endl;
                    cout << "3. Logout" << endl;
                    cout << "Enter your choice: ";
                    cin >> choice;

                    if (choice == 1) {
                        string command;
                        cout << "Enter command to execute: ";
                        cin.ignore(); // flush newline
                        getline(cin, command);
                        secureSystemCall(uname, command, userManager.getCurrentRole());
                    } else if (choice == 2) {
                        if (userManager.getCurrentRole() == "Admin") {
                            showLogs();
                        } else {
                            cout << "Access denied. Admins only." << endl;
                        }
                    } else if (choice == 3) {
                        userManager.logout();
                        break;
                    } else {
                        cout << "Invalid choice." << endl;
                    }
                }
            } else {
                cout << "Authentication failed!" << endl;
            }
        } else if (choice == 3) {
            break;
        } else {
            cout << "Invalid option. Try again." << endl;
        }
    }

    return 0;
}
