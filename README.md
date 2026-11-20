# User-Friendly System Call Interface for Enhanced Security

A small C++ and Python project exploring a controlled interface for running a limited set of system commands, with basic user records and audit logging.

> **Security status: educational prototype only. Do not use this project to protect a real system or execute commands for untrusted users.** The current implementation has important authentication and command-execution limitations described below.

## Project overview

The project separates a few core concerns:

- Authentication helpers for checking user records
- A command allowlist for a small set of commands
- Logging of command attempts and execution events
- A graphical interface implemented in Python/Tkinter

## Current implementation

### Authentication

The C++ authentication module reads user records from `users/user_data.txt` and compares a stored digest against a SHA-256 digest of the password concatenated with the username.

This is **not suitable password storage**:
- SHA-256 is a fast general-purpose hash, not a password-hashing function.
- The username is used as a predictable, non-random salt.
- There is no configurable work factor.

For a real application, use a password-hashing scheme such as Argon2id, scrypt, or bcrypt with a unique random salt per password. Do not reuse existing credentials from this prototype.

### Command handling

The current command handler contains a small allowlist:

- `ls`
- `whoami`
- `uptime`
- `pwd`

It rejects commands that do not exactly match an allowed string and records the attempt. Allowed commands are executed through `std::system`.

**Important limitation:** the command handler does not itself verify the caller's password or enforce the user's role before execution. A role helper exists, but the current command execution path does not use it as an authorization check. A command allowlist combined with `std::system` is not a robust security boundary.

A safer redesign would use direct process execution with fixed executable paths and argument arrays, enforce authorization inside the privileged operation, and avoid shell interpretation entirely.

### Logging

The current logging module appends authentication and command events to `logs/system_logs.txt`. This is a basic local audit trail, not tamper-resistant logging.

## Repository layout

The project is organised around:

- `src/auth_module.cpp` — user-record lookup and password comparison
- `src/syscall_handler.cpp` — command allowlist and execution
- `src/log_manager.cpp` — basic event logging
- `include/` — C++ declarations
- `src/gui/` — Python/Tkinter interface
- `Makefile` — C++ build commands
- `requirements.txt` — Python dependencies, if present in the checkout

## Build

On a Debian-based Linux system, install a C++ compiler, Make, and OpenSSL development headers:

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

Build the C++ components:

```bash
make
```

Clean generated build files:

```bash
make clean
```

The GUI is implemented separately in Python. Check the files under `src/gui/` for its entry point and Python dependencies before running it.

## Known limitations and next steps

Before this project could be considered a security control, it needs substantial changes:

1. Replace the fast SHA-256 password digest with Argon2id, scrypt, or bcrypt and unique random salts.
2. Enforce authentication and authorization inside the command execution boundary.
3. Replace `std::system` with safe process execution that does not invoke a shell.
4. Separate privileged operations from the GUI and apply least privilege.
5. Validate user records, roles, file permissions, and log access.
6. Add automated tests for authentication, authorization, invalid input, and command execution.
7. Document the actual GUI workflow and supported runtime environment.

## Author

**Kavyanjali**

- [GitHub](https://github.com/Kavyanjali07)
- [LinkedIn](https://www.linkedin.com/in/kavyanjali07)
