## USER-FRIENDLY SECURE SYSTEM CALL INTERFACE

### PROJECT OVERVIEW
This project offers a secure system call interface with added safety features. It makes sure that only verified users can run system commands and keeps a detailed log of access.

### PROJECT ARCHITECTURE  
The project is built around three main parts:
- **Authentication Module** – Manages user logins.
- **Logging Module** – Handles event logging.
- **System Call Handler** – Oversees the safe execution of system commands.

Each part works on its own but comes together to create a complete security setup.

#### FOLDER STRUCTURE
```
SecureSysCallProject/
│-- src/
│   │-- auth_module.cpp
│   │-- log_manager.cpp
│   │-- syscall_handler.cpp
│-- include/
│   │-- auth_module.h
│   │-- log_manager.h
│   │-- syscall_handler.h
│-- logs/
│   │-- auth_log.txt
│   │-- syscall_log.txt
│-- users/
│   │-- users.h
│-- README.md
│-- Makefile
```
---

## OVERVIEW OF MODULES  

### 1. AUTHENTICATION MODULE (`auth_module.cpp &amp; auth_module.h`)  
**Purpose**:  
The Authentication Module checks if users are who they say they are before giving them access to the system. It makes sure credentials are safe and keeps track of both successful and failed login attempts.

**Core Functionalities**:  
- Keeps a list of authorized users (`users.h`).  
- Uses SHA-256 to hash passwords for added security.  
- Confirms user credentials against what’s stored.  

**Files**:
- `auth_module.cpp`: This file has the logic for authentication.
- `auth_module.h`: This one defines the functions that handle authentication.
- `users.h`: This file keeps the user credentials.

**Key Functions**:
- `bool isValidUser(const std::string&amp; username, const std::string&amp; password)`: Checks if the username and password are correct.
- `std::string hashPassword(const std::string&amp; password)`: Takes a password and hashes it using the SHA-256 method.
- `void logAuthentication(const std::string&amp; username, const std::string&amp; status)`: Keeps track of login attempts.
- `std::string getUserRole(const std::string&amp; username)`: Gets the role of the user, like if they are an Admin or a regular User.

---

### **2. Logging Module (`log_manager.cpp &amp; log_manager.h`)**
**Purpose**:
The Logging Module is all about keeping track of every authentication attempt and system call. This way, we have a solid record for security reviews later on.

**Core Features**:
- It records login attempts including the time they happened.
- Logs all system calls that are executed to keep an eye on security.
- Lets you pull up and view logs whenever needed.
- Records errors so we know what went wrong.
- The logs are kept in `auth_log.txt` and `syscall_log.txt`.

**Files**:
- `log_manager.cpp`: This file implements the logging processes.
- `log_manager.h`: This defines the logging functions.
- `auth_log.txt`: This keeps a record of authentication logs.
- `syscall_log.txt`: This holds information on all system calls made.

**Key Functions**:
- `void logEvent(const std::string&amp; username, const std::string&amp; event)`: Logs what system calls are executed.
- `void logError(const std::string&amp; errorMessage)`: Logs any errors that happen in the system.
- `void displayLogs()`: Shows all authentication attempts and system command logs.

---

### **3. Secure System Call Handler (`syscall_handler.cpp &amp; syscall_handler.h`)**
**Purpose**:
This module makes sure that only users who have passed the authentication can execute system commands safely.

**Core Features**:
- It checks if the user is authenticated before letting them run any system calls.
- Executes commands in a safe manner.
- Logs each command that is run.
- Makes sure access is based on user roles.
- Stops unauthorized commands from running.

**Files**:
- `syscall_handler.cpp`: Takes care of executing system calls securely.
- `syscall_handler.h`: Defines the functions for managing system calls.
- `syscall_log.txt`: This file logs all executed commands.

**Key Functions**:
- `void secureSystemCall(const std::string&amp; username, const std::string&amp; command)`: This function executes system commands securely.
- `bool isAuthorizedUser(const std::string&amp; username)`: Checks if the user is allowed to execute commands.
- `void logSystemCall(const std::string&amp; username, const std::string&amp; command)`: Keeps a log for security purposes.

---

## **How the Modules Work Together**
1. **Authentication**: Users enter their credentials. If everything checks out, they get in.
2. **Logging**: All attempts to log in and execute system commands are recorded.
3. **Secure Execution**: Only authenticated users can safely run commands.

This structure makes sure everything is secure, easy to maintain, and ready for future improvements.

---
## **Revisions**
- **Authentication Module**
1) Set up a basic authentication system.
2) Improved security by adding password hashing.
3) Enhanced password hashing with the SHA-256 method.

- **Log Manager Module**
1) Added timestamps to the logs.
2) Added a feature to view the logs for system calls.

- **Secure System Call Handler**
1) Implemented input checks for system calls.
2) Added role-based permissions for command execution.
3) Refined the logging for system calls.

## **Installation &amp; Setup Guide**
Here's how to get everything set up in **Kali Linux**:

### **1. Clone the Repository**

Start by running these commands in your terminal:

```sh
mkdir SecureSysCallProject
cd SecureSysCallProject
git clone &lt;repository-url&gt;
cd &lt;repository-folder&gt;
```

### **2. Install Required Dependencies**  
Make sure you have OpenSSL installed for hashing passwords:
```sh
sudo apt update
sudo apt install libssl-dev
```

### **3. Compile the Project**  
Next, compile the project with this command:
```sh
g++ -o secure_syscall src/*.cpp -Iinclude -lssl -lcrypto
```

### **4. Run the Program**  
Finally, execute the program like this:
```sh
./secure_syscall
```
