#include <iostream>
#include "auth_module.h"
#include "syscall_handler.h"
#include "log_manager.h"

using namespace std;

int main() {
    int choice;
    cout << "1️⃣ Login\n2️⃣ View Logs\n3️⃣ Execute Secure System Call\nEnter choice: ";
    cin >> choice;

    if (choice == 1) {
        string username, password;
        cout << "Enter username: ";
        cin >> username;
        cout << "Enter password: ";
        cin >> password;

        if (authenticateUser(username, password)) {
            cout << "✅ Access Granted!\n";
        } else {
            cout << "❌ Access Denied! Invalid credentials.\n";
        }
    } 
    else if (choice == 2) {
        displayLogs();
    } 
    else if (choice == 3) {
        string username, command;
        cout << "Enter username: ";
        cin >> username;
        cout << "Enter command: ";
        cin.ignore();
        getline(cin, command);
        secureSystemCall(username, command);
    } 
    else {
        cout << "Invalid choice.\n";
    }

    return 0;
}
