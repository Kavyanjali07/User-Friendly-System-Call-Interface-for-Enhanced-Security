**USER-FRIENDLY SECURE SYSTEM CALL INTERFACE**

**PROJECT OVERVIEW**  
This project focuses on creating a safe system call interface with enhanced security features. It ensures that only users who are verified can run system commands and it maintains a detailed record of who accessed what. 

**PROJECT ARCHITECTURE**  
The whole project is divided into three main pieces:

1. **Authentication Module** – This takes care of user logins and verifies their identities. 
2. **Logging Module** – This keeps track of everything that happens, like login attempts and commands run. 
3. **System Call Handler** – This makes sure that system commands are executed safely only by authorized users.

These parts might function independently, but when put together, they form a solid security setup.

**FOLDER STRUCTURE**  
Here’s how the files are organized in the project:

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

**HOW THE MODULES WORK TOGETHER**  
1. **Authentication:** Users type in their credentials. If everything matches, they gain access.  
2. **Logging:** Every attempt to log in and execute commands gets logged.  
3. **Secure Execution:** Only those who have been authenticated get to run commands safely.  

This whole structure makes sure everything stays secure, is easy to manage, and can be upgraded in the future.

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

**INSTALLATION &amp; SETUP GUIDE**  
If you want to set this up on Kali Linux, follow these steps:
1. **Install git if not installed**
  If installed check - 
	git --version
  
  If not installed
	sudo apt update
	 sudo apt install git -y

2. **Clone the Repository**  
   First, run these commands in the terminal:  
   ```
   mkdir SecureSysCallProject  
   cd SecureSysCallProject  
   git clone git@github.com:your-username/repository-name.git  
   cd repository-name

   ```

2. **Install Required Dependencies**  
   Make sure you have OpenSSL installed to hash those passwords:  
   ```
   sudo apt update  
   sudo apt install libssl-dev  
   ```

3. **Compile the Project**  
   Then compile the project using this command:  
   ```
   g++ -o secure_syscall src/*.cpp -Iinclude -lssl -lcrypto  
   ```

4. **Run the Program**  
   Lastly, you can run the program like this:  
   ```
   ./secure_auth
  
   ```  

With that, you should have everything set up!
