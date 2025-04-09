**USER-FRIENDLY SECURE SYSTEM CALL INTERFACE**

**PROJECT OVERVIEW**  
This project focuses on creating a safe system call interface with enhanced security features. It ensures that only users who are verified can run system commands and it maintains a detailed record of who accessed what. 

**Key Features**

- Dual Interface - Command-line and graphical interfaces for flexible user interaction
- Strong Authentication - Username/password verification with optional two-factor authentication
- Extensive Logging - Comprehensive audit trails for all authentication attempts and system calls
- Role-Based Access Control - User permissions based on assigned roles
- Secure System Call Execution - Protected command execution with input validation
- User-Friendly GUI - Intuitive graphical interface for easier system interaction

**PROJECT ARCHITECTURE**  
The whole project is divided into three main pieces:

1. **Authentication Module** – This takes care of user logins and verifies their identities. 
2. **Logging Module** – This keeps track of everything that happens, like login attempts and commands run. 
3. **System Call Handler** – This makes sure that system commands are executed safely only by authorized users.
4. **GUI Interfac**e - Provides graphical access to all system features

These components work together to create a cohesive security framework while maintaining ease of use.

**FOLDER STRUCTURE**  
Here’s how the files are organized in the project:
```
SecureSysCallProject/
│-- src/
│   │-- auth_module.cpp
│   │-- log_manager.cpp
│   │-- syscall_handler.cpp
│   │-- gui/
│       │-- main.py
│       │-- auth_screen.py
│       │-- dashboard.py
│       │-- system_call_panel.py
│-- include/
│   │-- auth_module.h
│   │-- log_manager.h
│   │-- syscall_handler.h
│-- logs/
│   │-- auth_log.txt
│   │-- syscall_log.txt
│-- users/
│   │-- users.h
│-- static/
│   │-- icons/
│   │-- styles/
│-- README.md
│-- Makefile
│-- requirements.txt
```

**OVERVIEW OF MODULES**  

1. **AUTHENTICATION MODULE (auth_module.cpp &amp; auth_module.h)**  
   **Purpose:**  
   The Authentication Module checks the identity of users before they can access the system. Its job is to keep credentials safe and log both successful and failed login attempts.

   **Core Functionalities:**  
   - Maintains a list of users who are allowed access (found in users.h).  
   - Uses SHA-256 to securely hash passwords.  
   - Confirms user credentials against the stored information.  

   **Files:**  
   - **auth_module.cpp:** Contains the code that handles user login processes.  
   - **auth_module.h:** Lists the functions for user authentication tasks.  
   - **users.h:** Holds user credentials in a secure manner.  

   **Key Functions:**  
   - `bool isValidUser(const std::string&amp; username, const std::string&amp; password)`: Checks if the provided username and password are correct.  
   - `std::string hashPassword(const std::string&amp; password)`: Hashes the given password with SHA-256 for security.  
   - `void logAuthentication(const std::string&amp; username, const std::string&amp; status)`: Logs the outcome of login attempts.  
   - `std::string getUserRole(const std::string&amp; username)`: Identifies the role of the user, indicating whether they are an Admin or just a regular User.  

2. **LOGGING MODULE (log_manager.cpp &amp; log_manager.h)**  
   **Purpose:**  
   The Logging Module is responsible for tracking every authentication attempt and any system calls that are made. This helps create a clear record for security reviews later.

   **Core Features:**  
   - Records when users try to log in, including the times of attempts.  
   - Logs every system call that is executed for monitoring purposes.  
   - Allows retrieval of logs whenever necessary.  
   - Tracks errors to identify what went wrong.  

   **Files:**  
   - **log_manager.cpp:** Implements the logging functionality.  
   - **log_manager.h:** Defines the logging-related functions.  
   - **auth_log.txt:** Holds records of all authentication attempts.  
   - **syscall_log.txt:** Contains records of all system calls made.  

   **Key Functions:**  
   - `void logEvent(const std::string&amp; username, const std::string&amp; event)`: Logs what system calls are executed.  
   - `void logError(const std::string&amp; errorMessage)`: Records any errors that the system encounters.  
   - `void displayLogs()`: Shows all logs of login attempts and executed commands.  

3. **SECURE SYSTEM CALL HANDLER (syscall_handler.cpp &amp; syscall_handler.h)**  
   **Purpose:**  
   This module ensures that only authenticated users can safely execute system commands.

   **Core Features:**  
   - Verifies if the user is authenticated before allowing them to run system calls.  
   - Executes commands in a safe way to prevent misuse.  
   - Logs every command that's executed for security monitoring.  
   - Ensures that permission to access features is based on the user's role.  
   - Blocks unauthorized commands from going through.  

   **Files:**  
   - **syscall_handler.cpp:** Responsible for securely executing system calls.  
   - **syscall_handler.h:** Lists functions related to managing system calls.  
   - **syscall_log.txt:** Stores logs of all commands that were executed.  

   **Key Functions:**  
   - `void secureSystemCall(const std::string&amp; username, const std::string&amp; command)`: Handles the secure execution of commands.  
   - `bool isAuthorizedUser(const std::string&amp; username)`: Checks if the user is permitted to carry out the commands.  
   - `void logSystemCall(const std::string&amp; username, const std::string&amp; command)`: Keeps a security log of executed commands.  

4. **GUI Interface**
**Purpose**
 Provides user-friendly graphical access to all system features

**Key Features:**

- Intuitive login screen with 2FA support
- Dashboard for system monitoring
- Command execution panel with history
- Real-time log viewer
- User management interface (admin only)

**Key Components:**

- auth_screen.py - Handles login and 2FA verification
- dashboard.py - Main user interface after authentication
- system_call_panel.py - Interface for executing system calls
- log_viewer.py - Visual interface for reviewing system logs

**Workflow**

- Authentication: Users provide credentials via CLI or GUI
- Verification: System validates credentials and optional 2FA
- Authorization: System checks user permissions for requested actions
- Execution: Commands are sanitized and executed securely
- Logging: All activities are recorded for audit purposes

** Functionality Summary**
Each part works as intended:

- Login & Registration via CLI and GUI

- Role-Based Access Control

- 2FA in GUI

- Command Execution with Restrictions

- Logs Viewable via GUI + Export to File

- Dashboard showing last commands & activity 


**REVISIONS**  
- **Authentication Module:**  
  - Set up basic authentication.  
  - Added a layer of security by hashing passwords.  
  - Enhanced security further with SHA-256 hashing.  

- **Log Manager Module:**  
  - Introduced timestamps for all logged events.  
  - Implemented a feature to view logs for system calls.  

- **Secure System Call Handler:**  
  - Added checks for receiving input before executing calls.  
  - Introduced role-based permissions for running commands.  
  - Improved logging for system calls to enhance tracking.  

**Installation & Setup Guide**

Prerequisites

- C++ compiler (g++ recommended)
- OpenSSL development libraries
- Python 3.8+ (for GUI interface)
- Git (for repository cloning)

**Step 1:** Install System Dependencies
bash# Update package lists
sudo apt update

# Install C++ dependencies
sudo apt install g++ libssl-dev make -y

# Install Python dependencies (for GUI)
sudo apt install python3 python3-pip python3-venv -y

**Step 2:** Clone the Repository
bash mkdir SecureSysCallProject
cd SecureSysCallProject
git clone git@github.com:Kavyanjali07/User-Friendly-System-Call-Interface-for-Enhanced-Security.git
cd User-Friendly-System-Call-Interface-for-Enhanced-Security

**Step 3:** Set Up Python Environment (for GUI)
bash# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
Step 4: Compile the Project
bash# Compile C++ components
make

🖥️ Usage Instructions
Command-Line Interface
bash# Run the CLI application
./secure_syscall

# Follow the prompts to log in and execute commands
Graphical User Interface
bash# Ensure virtual environment is activated
source venv/bin/activate

# Start the GUI application
python src/gui/main.py

**Security Best Practices**

- Regularly update user passwords
- Enable two-factor authentication for all users
- Review logs periodically for unauthorized access attempts
- Limit system commands based on least privilege principle
- Keep all dependencies updated to patch security vulnerabilities

** Recent Updates**

- Added graphical user interface for improved usability
- Implemented two-factor authentication for enhanced security
- Added command sanitization to prevent injection attacks
- Improved logging with rotation and tamper-evident features
- Enhanced role-based permissions system

**Contributors**

- Kavyanjali Vashishtha
- Sargun Dhingra
- Akshita


