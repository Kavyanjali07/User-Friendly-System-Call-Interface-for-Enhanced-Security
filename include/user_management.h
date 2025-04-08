#ifndef USER_MANAGEMENT_H
#define USER_MANAGEMENT_H

#include <string>
#include <vector>

class UserManager {
private:
    std::string currentUser;
    std::string currentRole;
    bool loggedIn;

public:
    UserManager();

    bool login(const std::string& username, const std::string& password);
    bool addUser(const std::string& username, const std::string& password, const std::string& role);
    std::string getCurrentUser();
    std::string getCurrentRole();
    bool isLoggedIn();
};

#endif

