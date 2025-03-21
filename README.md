## 🔹 **Secure System Call Interface - Detailed README**

### 📖 **Project Overview**  
This project provides a **secure system call interface** with enhanced security mechanisms. It ensures that only **authenticated users** can execute system commands, while maintaining a detailed **log of authentication attempts and executed commands**. The system is designed with a **modular approach**, making it secure, maintainable, and extensible.

### 🏗 **Project Structure**  
The project consists of three main modules:
- **Authentication Module** → Handles user authentication.
- **Logging Module** → Manages event logging.
- **System Call Handler** → Controls secure execution of system commands.

Each module is designed independently but interacts to form a complete security system.

#### 📂 **Folder Structure**
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

## 🔹 **Modules Overview**  
### 📌 **1. Authentication Module (`auth_module.cpp & auth_module.h`)**  
📂 **Purpose**:  
The **Authentication Module** is responsible for verifying users before granting access to the system. It securely validates credentials and logs both successful and failed authentication attempts.

📜 **Core Functionalities**:  
✅ Maintains a list of **authorized users** (`users.h`).  
✅ Hashes passwords using **SHA-256 encryption** for security.  
✅ Checks **user credentials** against stored data.  
✅ Logs authentication attempts (success & failure) in **auth_log.txt**.  
✅ Implements **role-based access control** (Admin/User).  

📂 **Files**:  
- `auth_module.cpp` → Implements authentication logic.  
- `auth_module.h` → Defines functions for authentication.  
- `users.h` → Stores user credentials.

📜 **Key Functions**:
- `bool isValidUser(const std::string& username, const std::string& password)` → Validates username and password.
- `std::string hashPassword(const std::string& password)` → Hashes the password using SHA-256.
- `void logAuthentication(const std::string& username, const std::string& status)` → Logs authentication attempts.
- `std::string getUserRole(const std::string& username)` → Retrieves user role (Admin/User).

---

### 📌 **2. Logging Module (`log_manager.cpp & log_manager.h`)**  
📂 **Purpose**:  
The **Logging Module** records all authentication attempts and system calls. This ensures a proper audit trail for security analysis.

📜 **Core Functionalities**:  
✅ Records login attempts with timestamps.  
✅ Logs all executed system calls for security monitoring.  
✅ Allows retrieval and display of logs for analysis.  
✅ Implements **error logging** to track failures.  
✅ Stores logs in **auth_log.txt** & **syscall_log.txt**.  

📂 **Files**:  
- `log_manager.cpp` → Implements log recording and retrieval.  
- `log_manager.h` → Defines logging functions.  
- `auth_log.txt` → Stores authentication logs.  
- `syscall_log.txt` → Stores executed system call logs.

📜 **Key Functions**:
- `void logEvent(const std::string& username, const std::string& event)` → Logs system call executions.
- `void logError(const std::string& errorMessage)` → Logs system errors.
- `void displayLogs()` → Displays authentication and system call logs.

---

### 📌 **3. Secure System Call Handler (`syscall_handler.cpp & syscall_handler.h`)**  
📂 **Purpose**:  
The **System Call Handler Module** ensures that only authenticated users can execute system commands securely.

📜 **Core Functionalities**:  
✅ Verifies **authentication** before allowing system calls.  
✅ Executes commands in a **secure environment**.  
✅ Logs each executed system command.  
✅ Enforces **privilege-based access control**.  
✅ Prevents **unauthorized execution of critical commands**.  

📂 **Files**:  
- `syscall_handler.cpp` → Implements secure system call execution.  
- `syscall_handler.h` → Defines functions for handling system calls.  
- `syscall_log.txt` → Stores details of executed commands.

📜 **Key Functions**:
- `void secureSystemCall(const std::string& username, const std::string& command)` → Executes system commands securely.
- `bool isAuthorizedUser(const std::string& username)` → Checks if the user is authorized.
- `void logSystemCall(const std::string& username, const std::string& command)` → Logs system calls for security tracking.

---

## 🛠 **How the Modules Work Together**  
1️⃣ **Authentication**: Users provide credentials. If valid, they are granted access.  
2️⃣ **Logging**: Each authentication attempt and system call execution is logged.  
3️⃣ **Secure Execution**: Authenticated users execute commands securely.

This modular structure ensures **security, maintainability, and extensibility** for future upgrades.

---

## 📌 **Installation & Setup Guide**  
Follow these steps to set up the project in **Kali Linux**:

### 🔹 **1. Clone the Repository**  
```sh
mkdir SecureSysCallProject
cd SecureSysCallProject
git clone <repository-url>
cd <repository-folder>
```

### 🔹 **2. Install Required Dependencies**  
Ensure that OpenSSL is installed for password hashing:
```sh
sudo apt update
sudo apt install libssl-dev
```

### 🔹 **3. Compile the Project**  
```sh
g++ -o secure_syscall src/*.cpp -Iinclude -lssl -lcrypto
```

### 🔹 **4. Run the Program**  
```sh
./secure_syscall
```

---

## 🏆 **Future Enhancements**  
- Implement **two-factor authentication (2FA)** for added security.  
- Integrate a **graphical user interface (GUI)** for ease of use.  
- Add **remote logging capabilities** for centralized monitoring.  
- Improve **role-based access control** with finer granularity.  
- Implement **encryption** for log files to prevent tampering.

---

