#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import qrcode
import pyotp
import hashlib
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QStackedWidget, QComboBox, 
                            QTextEdit, QDialog, QTabWidget, QGridLayout, QMessageBox,
                            QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog)
from PyQt5.QtGui import QPixmap, QIcon, QFont, QColor, QPalette
from PyQt5.QtCore import Qt, QTimer, QDateTime

# Constants
TOTP_SECRET_FILE = "users/totp_secrets.txt"
LOG_FILE = "logs/system_logs.txt"
# List of commands that regular users are allowed to run
USER_ALLOWED_COMMANDS = ["ls", "uptime", "echo", "pwd", "touch", "cat"]

class TwoFactorSetupDialog(QDialog):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.secret = pyotp.random_base32()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("2FA Setup")
        self.setFixedSize(400, 500)
        
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("Two-Factor Authentication Setup")
        header_label.setFont(QFont("Arial", 14, QFont.Bold))
        header_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(header_label)
        
        # Instructions
        instructions = QLabel("Scan the QR code with your authenticator app")
        instructions.setAlignment(Qt.AlignCenter)
        layout.addWidget(instructions)
        
        # QR Code
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(self.secret).provisioning_uri(
            name=self.username, issuer_name="SecureAccessSystem")
        qr_img = qrcode.make(totp_uri)
        
        # Save QR code to temporary file and load as QPixmap
        temp_qr_path = "temp_qr.png"
        qr_img.save(temp_qr_path)
        self.qr_label.setPixmap(QPixmap(temp_qr_path).scaled(200, 200, Qt.KeepAspectRatio))
        os.remove(temp_qr_path)  # Remove temporary file
        
        layout.addWidget(self.qr_label)
        
        # Secret key
        secret_layout = QHBoxLayout()
        secret_label = QLabel("Secret Key:")
        self.secret_value = QLineEdit(self.secret)
        self.secret_value.setReadOnly(True)
        secret_layout.addWidget(secret_label)
        secret_layout.addWidget(self.secret_value)
        layout.addLayout(secret_layout)
        
        # Verification
        verify_label = QLabel("Enter code from your authenticator app to verify:")
        layout.addWidget(verify_label)
        
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("6-digit code")
        layout.addWidget(self.code_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.verify_button = QPushButton("Verify & Enable 2FA")
        self.cancel_button = QPushButton("Cancel")
        
        self.verify_button.clicked.connect(self.verify_code)
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.verify_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def verify_code(self):
        totp = pyotp.TOTP(self.secret)
        # Fixed the verification issue by using more lenient verification
        # This allows for time drift between server and client
        if totp.verify(self.code_input.text(), valid_window=1):
            # Save TOTP secret
            os.makedirs(os.path.dirname(TOTP_SECRET_FILE), exist_ok=True)
            with open(TOTP_SECRET_FILE, "a") as f:
                f.write(f"{self.username} {self.secret}\n")
            
            QMessageBox.information(self, "Success", "2FA has been successfully enabled!")
            self.accept()
        else:
            QMessageBox.warning(self, "Verification Failed", "The code is incorrect. Please try again.")

class TwoFactorVerifyDialog(QDialog):
    def __init__(self, username, secret):
        super().__init__()
        self.username = username
        self.secret = secret
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("2FA Verification")
        self.setFixedSize(300, 200)
        
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("Two-Factor Authentication")
        header_label.setFont(QFont("Arial", 14, QFont.Bold))
        header_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(header_label)
        
        # Instructions
        instructions = QLabel("Enter the code from your authenticator app:")
        instructions.setAlignment(Qt.AlignCenter)
        layout.addWidget(instructions)
        
        # Code input
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("6-digit code")
        layout.addWidget(self.code_input)
        
        # Timer label for TOTP time remaining
        self.timer_label = QLabel("Time remaining: 30s")
        self.timer_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.timer_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.verify_button = QPushButton("Verify")
        self.cancel_button = QPushButton("Cancel")
        
        self.verify_button.clicked.connect(self.verify_code)
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.verify_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Timer for updating remaining time
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_timer)
        self.timer.start(1000)  # Update every second
        
    def update_timer(self):
        totp = pyotp.TOTP(self.secret)
        remaining = 30 - (int(time.time()) % 30)
        self.timer_label.setText(f"Time remaining: {remaining}s")
        
    def verify_code(self):
        totp = pyotp.TOTP(self.secret)
        # Fixed the verification issue by using more lenient verification
        # This allows for time drift between server and client
        if totp.verify(self.code_input.text(), valid_window=1):
            self.accept()
        else:
            QMessageBox.warning(self, "Verification Failed", "The code is incorrect. Please try again.")

class LoginWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Secure Access System")
        header.setAlignment(Qt.AlignCenter)
        header.setFont(QFont("Arial", 18, QFont.Bold))
        layout.addWidget(header)
        
        # Login form
        form_layout = QGridLayout()
        
        username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        
        password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.Password)
        
        form_layout.addWidget(username_label, 0, 0)
        form_layout.addWidget(self.username_input, 0, 1)
        form_layout.addWidget(password_label, 1, 0)
        form_layout.addWidget(self.password_input, 1, 1)
        
        layout.addLayout(form_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        
        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.show_register)
        
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.register_button)
        
        layout.addLayout(button_layout)
        
        # Status message
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        
    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not username or not password:
            self.status_label.setText("Please enter both username and password")
            return
            
        # Call the backend login function using subprocess
        result = subprocess.run(
            ["./main", "login", username, password],
            capture_output=True,
            text=True
        )
        
        if "Login successful" in result.stdout:
            # Check if user has 2FA enabled
            if os.path.exists(TOTP_SECRET_FILE):
                with open(TOTP_SECRET_FILE, "r") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 2 and parts[0] == username:
                            secret = parts[1]
                            # Verify 2FA
                            verify_dialog = TwoFactorVerifyDialog(username, secret)
                            if verify_dialog.exec_() != QDialog.Accepted:
                                self.status_label.setText("2FA verification failed")
                                return
                            break
            
            # Get user role
            user_role = self.get_user_role(username)
            
            # Log successful login with timestamp
            self.log_with_timestamp(f"[AUTH] User: {username}, Status: Success, Role: {user_role}")
            
            # Switch to main application
            self.parent.username = username
            self.parent.user_role = user_role
            self.parent.show_main_window()
        else:
            self.status_label.setText("Login failed. Please check your credentials.")
            # Log failed login attempt with timestamp
            self.log_with_timestamp(f"[AUTH] User: {username}, Status: Failure, Reason: Invalid credentials")
    
    def get_user_role(self, username):
        # Check user_data.txt for the user's role
        if os.path.exists("users/user_data.txt"):
            with open("users/user_data.txt", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0] == username:
                        return parts[2]
        return "User"  # Default to User if not found
    
    def show_register(self):
        self.parent.stacked_widget.setCurrentIndex(1)
        
    def log_with_timestamp(self, message):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

class RegisterWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("User Registration")
        header.setAlignment(Qt.AlignCenter)
        header.setFont(QFont("Arial", 18, QFont.Bold))
        layout.addWidget(header)
        
        # Registration form
        form_layout = QGridLayout()
        
        username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose a username")
        
        password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Choose a password")
        self.password_input.setEchoMode(QLineEdit.Password)
        
        confirm_label = QLabel("Confirm Password:")
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Confirm your password")
        self.confirm_input.setEchoMode(QLineEdit.Password)
        
        # Removed role selection - all new registrations will be regular users
        
        form_layout.addWidget(username_label, 0, 0)
        form_layout.addWidget(self.username_input, 0, 1)
        form_layout.addWidget(password_label, 1, 0)
        form_layout.addWidget(self.password_input, 1, 1)
        form_layout.addWidget(confirm_label, 2, 0)
        form_layout.addWidget(self.confirm_input, 2, 1)
        
        self.enable_2fa_checkbox = QPushButton("Enable Two-Factor Authentication")
        self.enable_2fa_checkbox.setCheckable(True)
        form_layout.addWidget(self.enable_2fa_checkbox, 3, 1)
        
        layout.addLayout(form_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.back_button = QPushButton("Back to Login")
        self.back_button.clicked.connect(self.back_to_login)
        
        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.register)
        
        button_layout.addWidget(self.back_button)
        button_layout.addWidget(self.register_button)
        
        layout.addLayout(button_layout)
        
        # Status message
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        
    def back_to_login(self):
        self.parent.stacked_widget.setCurrentIndex(0)
        
    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        role = "User"  # Default role is always User now
        
        if not username or not password or not confirm:
            self.status_label.setText("Please fill all required fields")
            return
            
        if password != confirm:
            self.status_label.setText("Passwords do not match")
            return
            
        # Call the backend register function using subprocess
        result = subprocess.run(
            ["./main", "register", username, password, role],
            capture_output=True,
            text=True
        )
        
        if "User added successfully" in result.stdout:
            # Log registration with timestamp
            self.log_with_timestamp(f"[REGISTER] New user: {username}, Role: {role}")
            
            # Setup 2FA if enabled
            if self.enable_2fa_checkbox.isChecked():
                setup_dialog = TwoFactorSetupDialog(username)
                setup_dialog.exec_()
            
            self.status_label.setText("Registration successful!")
            QMessageBox.information(self, "Success", "User registered successfully!")
            self.back_to_login()
        else:
            self.status_label.setText("Registration failed")
            
    def log_with_timestamp(self, message):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

class CommandPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("System Command Panel")
        header.setAlignment(Qt.AlignCenter)
        header.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(header)
        
        # Command input
        command_layout = QHBoxLayout()
        command_label = QLabel("Command:")
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter system command")
        self.run_button = QPushButton("Run")
        self.run_button.clicked.connect(self.run_command)
        
        command_layout.addWidget(command_label)
        command_layout.addWidget(self.command_input)
        command_layout.addWidget(self.run_button)
        
        layout.addLayout(command_layout)
        
        # Quick command buttons
        quick_commands_label = QLabel("Quick Commands:")
        layout.addWidget(quick_commands_label)
        
        quick_buttons = QHBoxLayout()
        
        ls_button = QPushButton("ls")
        ls_button.clicked.connect(lambda: self.set_command("ls"))
        
        whoami_button = QPushButton("whoami")
        whoami_button.clicked.connect(lambda: self.set_command("whoami"))
        
        uptime_button = QPushButton("uptime")
        uptime_button.clicked.connect(lambda: self.set_command("uptime"))
        
        pwd_button = QPushButton("pwd")
        pwd_button.clicked.connect(lambda: self.set_command("pwd"))
        
        quick_buttons.addWidget(ls_button)
        quick_buttons.addWidget(whoami_button)
        quick_buttons.addWidget(uptime_button)
        quick_buttons.addWidget(pwd_button)
        
        layout.addLayout(quick_buttons)
        
        # Command output
        output_label = QLabel("Output:")
        layout.addWidget(output_label)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)
        
        self.setLayout(layout)
        
    def set_command(self, command):
        self.command_input.setText(command)
        
    def run_command(self):
        command = self.command_input.text()
        username = self.parent.parent.username
        user_role = self.parent.parent.user_role
        
        if not command:
            return
        
        # Check if user is allowed to run this command
        command_base = command.split()[0]  # Extract the base command
        
        if user_role.lower() != "admin" and command_base not in USER_ALLOWED_COMMANDS:
            self.output_text.setText(f"Permission denied: '{command_base}' is restricted to admin users.")
            self.log_with_timestamp(f"[SYSCALL] User: {username}, Command: {command}, Status: Denied (Permission)")
            return
            
        # Call the backend system call function using subprocess
        result = subprocess.run(
            ["./main", "run_cmd", username, command],
            capture_output=True,
            text=True
        )
        
        self.output_text.setText(result.stdout)
        
        # Log command execution with timestamp
        self.log_with_timestamp(f"[SYSCALL] User: {username}, Command: {command}, Status: Executed")
        
    def log_with_timestamp(self, message):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

class LogViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("System Logs")
        header.setAlignment(Qt.AlignCenter)
        header.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(header)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        refresh_button = QPushButton("Refresh Logs")
        refresh_button.clicked.connect(self.load_logs)
        
        export_button = QPushButton("Export Logs")
        export_button.clicked.connect(self.export_logs)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter logs...")
        self.filter_input.textChanged.connect(self.filter_logs)
        
        controls_layout.addWidget(refresh_button)
        controls_layout.addWidget(export_button)
        controls_layout.addWidget(self.filter_input)
        
        layout.addLayout(controls_layout)
        
        # Log table
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(4)
        self.log_table.setHorizontalHeaderLabels(["Timestamp", "Type", "User", "Details"])
        self.log_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        
        layout.addWidget(self.log_table)
        
        self.setLayout(layout)
        
        # Initial load
        self.load_logs()
        
    def load_logs(self):
        self.log_table.setRowCount(0)
        
        if not os.path.exists(LOG_FILE):
            return
            
        with open(LOG_FILE, "r") as f:
            for line in f:
                if line.strip():
                    self.add_log_entry(line)
                    
        self.filter_logs()
        
    def add_log_entry(self, log_line):
        # Parse log line
        parts = log_line.strip().split("] ", 1)
        if len(parts) < 2:
            return
            
        timestamp = parts[0].lstrip("[")
        content = parts[1]
        
        # Parse content
        type_match = content.split("] ", 1)
        if len(type_match) >= 2:
            log_type = type_match[0].lstrip("[")
            details = type_match[1]
            
            # Extract user if available
            user = "N/A"
            if "User:" in details:
                user_parts = details.split("User:", 1)[1].split(",", 1)
                if len(user_parts) >= 1:
                    user = user_parts[0].strip()
        else:
            log_type = "SYSTEM"
            details = content
            user = "N/A"
        
        # Add to table
        row = self.log_table.rowCount()
        self.log_table.insertRow(row)
        
        self.log_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.log_table.setItem(row, 1, QTableWidgetItem(log_type))
        self.log_table.setItem(row, 2, QTableWidgetItem(user))
        self.log_table.setItem(row, 3, QTableWidgetItem(details))
        
    def filter_logs(self):
        filter_text = self.filter_input.text().lower()
        
        for row in range(self.log_table.rowCount()):
            visible = False
            
            for col in range(self.log_table.columnCount()):
                item = self.log_table.item(row, col)
                if item and filter_text in item.text().lower():
                    visible = True
                    break
                    
            self.log_table.setRowHidden(row, not visible)
            
    def export_logs(self):
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Logs", "", "CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if not filename:
            return
            
        try:
            with open(filename, "w") as f:
                # Write header
                headers = []
                for col in range(self.log_table.columnCount()):
                    headers.append(self.log_table.horizontalHeaderItem(col).text())
                f.write(",".join(headers) + "\n")
                
                # Write data
                for row in range(self.log_table.rowCount()):
                    if not self.log_table.isRowHidden(row):
                        row_data = []
                        for col in range(self.log_table.columnCount()):
                            item = self.log_table.item(row, col)
                            row_data.append(item.text() if item else "")
                        f.write(",".join(row_data) + "\n")
                        
            QMessageBox.information(self, "Export Successful", f"Logs exported to {filename}")
        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Error exporting logs: {str(e)}")

class UserManagement(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("User Management")
        header.setAlignment(Qt.AlignCenter)
        header.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(header)
        
        # User table
        self.user_table = QTableWidget()
        self.user_table.setColumnCount(3)
        self.user_table.setHorizontalHeaderLabels(["Username", "Role", "2FA Enabled"])
        self.user_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.user_table)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        refresh_button = QPushButton("Refresh Users")
        refresh_button.clicked.connect(self.load_users)
        
        # Admin promotion section
        promote_layout = QHBoxLayout()
        promote_label = QLabel("Promote to Admin:")
        self.promote_input = QLineEdit()
        self.promote_input.setPlaceholderText("Enter username")
        promote_button = QPushButton("Promote")
        promote_button.clicked.connect(self.promote_user)
        
        promote_layout.addWidget(promote_label)
        promote_layout.addWidget(self.promote_input)
        promote_layout.addWidget(promote_button)
        
        controls_layout.addWidget(refresh_button)
        
        layout.addLayout(controls_layout)
        layout.addLayout(promote_layout)
        
        self.setLayout(layout)
        
        # Initial load
        self.load_users()
        
    def load_users(self):
        self.user_table.setRowCount(0)
        
        # Load users from user_data.txt
        if os.path.exists("users/user_data.txt"):
            with open("users/user_data.txt", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        username = parts[0]
                        role = parts[2]
                        
                        # Check if user has 2FA enabled
                        has_2fa = "No"
                        if os.path.exists(TOTP_SECRET_FILE):
                            with open(TOTP_SECRET_FILE, "r") as totp_file:
                                for totp_line in totp_file:
                                    if totp_line.strip().startswith(username + " "):
                                        has_2fa = "Yes"
                                        break
                        
                        # Add to table
                        row = self.user_table.rowCount()
                        self.user_table.insertRow(row)
                        
                        self.user_table.setItem(row, 0, QTableWidgetItem(username))
                        self.user_table.setItem(row, 1, QTableWidgetItem(role))
                        self.user_table.setItem(row, 2, QTableWidgetItem(has_2fa))
                        
    def promote_user(self):
        username = self.promote_input.text().strip()
        if not username:
            QMessageBox.warning(self, "Error", "Please enter a username to promote")
            return
            
        # Check if user exists
        user_found = False
        updated_lines = []
        
        if os.path.exists("users/user_data.txt"):
            with open("users/user_data.txt", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0] == username:
                        user_found = True
                        # Update role to Admin
                        parts[2] = "Admin"
                        updated_line = " ".join(parts)
                        updated_lines.append(updated_line + "\n")
                    else:
                        updated_lines.append(line)
                        
            if user_found:
                # Write updated user data
                with open("users/user_data.txt", "w") as f:
                    f.writelines(updated_lines)
                    
                QMessageBox.information(self, "Success", f"User '{username}' promoted to Admin")
                self.log_with_timestamp(f"[ADMIN] User '{username}' promoted to Admin by {self.parent.parent.username}")
                self.load_users()
            else:
                QMessageBox.warning(self, "Error", f"User '{username}' not found")
        else:
            QMessageBox.warning(self, "Error", "User database not found")
            
def log_with_timestamp(self, message):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

class SettingsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("User Settings")
        header.setAlignment(Qt.AlignCenter)
        header.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(header)
        
        # Change password section
        password_group = QWidget()
        password_layout = QVBoxLayout(password_group)
        
        password_header = QLabel("Change Password")
        password_header.setFont(QFont("Arial", 12, QFont.Bold))
        password_layout.addWidget(password_header)
        
        form_layout = QGridLayout()
        
        current_label = QLabel("Current Password:")
        self.current_input = QLineEdit()
        self.current_input.setEchoMode(QLineEdit.Password)
        
        new_label = QLabel("New Password:")
        self.new_input = QLineEdit()
        self.new_input.setEchoMode(QLineEdit.Password)
        
        confirm_label = QLabel("Confirm New Password:")
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        
        form_layout.addWidget(current_label, 0, 0)
        form_layout.addWidget(self.current_input, 0, 1)
        form_layout.addWidget(new_label, 1, 0)
        form_layout.addWidget(self.new_input, 1, 1)
        form_layout.addWidget(confirm_label, 2, 0)
        form_layout.addWidget(self.confirm_input, 2, 1)
        
        change_button = QPushButton("Change Password")
        change_button.clicked.connect(self.change_password)
        
        password_layout.addLayout(form_layout)
        password_layout.addWidget(change_button)
        
        layout.addWidget(password_group)
        
        # Two-factor authentication setup
        twofa_group = QWidget()
        twofa_layout = QVBoxLayout(twofa_group)
        
        twofa_header = QLabel("Two-Factor Authentication")
        twofa_header.setFont(QFont("Arial", 12, QFont.Bold))
        twofa_layout.addWidget(twofa_header)
        
        self.twofa_status = QLabel("Status: Checking...")
        twofa_layout.addWidget(self.twofa_status)
        
        self.twofa_button = QPushButton("Enable Two-Factor Authentication")
        self.twofa_button.clicked.connect(self.toggle_2fa)
        twofa_layout.addWidget(self.twofa_button)
        
        layout.addWidget(twofa_group)
        
        # Account info
        info_group = QWidget()
        info_layout = QVBoxLayout(info_group)
        
        info_header = QLabel("Account Information")
        info_header.setFont(QFont("Arial", 12, QFont.Bold))
        info_layout.addWidget(info_header)
        
        self.username_label = QLabel(f"Username: {self.parent.parent.username}")
        self.role_label = QLabel(f"Role: {self.parent.parent.user_role}")
        self.created_label = QLabel("Account Created: N/A")
        
        info_layout.addWidget(self.username_label)
        info_layout.addWidget(self.role_label)
        info_layout.addWidget(self.created_label)
        
        layout.addWidget(info_group)
        
        self.setLayout(layout)
        
        # Check 2FA status
        self.check_2fa_status()
        
    def check_2fa_status(self):
        username = self.parent.parent.username
        has_2fa = False
        
        if os.path.exists(TOTP_SECRET_FILE):
            with open(TOTP_SECRET_FILE, "r") as f:
                for line in f:
                    if line.strip().startswith(username + " "):
                        has_2fa = True
                        break
        
        if has_2fa:
            self.twofa_status.setText("Status: Enabled")
            self.twofa_button.setText("Disable Two-Factor Authentication")
        else:
            self.twofa_status.setText("Status: Disabled")
            self.twofa_button.setText("Enable Two-Factor Authentication")
    
    def toggle_2fa(self):
        username = self.parent.parent.username
        has_2fa = False
        
        if os.path.exists(TOTP_SECRET_FILE):
            with open(TOTP_SECRET_FILE, "r") as f:
                for line in f:
                    if line.strip().startswith(username + " "):
                        has_2fa = True
                        break
        
        if has_2fa:
            # Disable 2FA
            if QMessageBox.question(
                self, "Confirm Disable 2FA", 
                "Are you sure you want to disable two-factor authentication? This will reduce your account security.",
                QMessageBox.Yes | QMessageBox.No
            ) == QMessageBox.Yes:
                # Remove the 2FA entry
                lines = []
                with open(TOTP_SECRET_FILE, "r") as f:
                    lines = f.readlines()
                
                with open(TOTP_SECRET_FILE, "w") as f:
                    for line in lines:
                        if not line.strip().startswith(username + " "):
                            f.write(line)
                
                self.twofa_status.setText("Status: Disabled")
                self.twofa_button.setText("Enable Two-Factor Authentication")
                QMessageBox.information(self, "Success", "Two-factor authentication has been disabled")
                self.log_with_timestamp(f"[SECURITY] User: {username}, Action: Disabled 2FA")
        else:
            # Enable 2FA
            setup_dialog = TwoFactorSetupDialog(username)
            setup_dialog.exec_()
            self.check_2fa_status()
            self.log_with_timestamp(f"[SECURITY] User: {username}, Action: Enabled 2FA")
    
    def change_password(self):
        username = self.parent.parent.username
        current = self.current_input.text()
        new_password = self.new_input.text()
        confirm = self.confirm_input.text()
        
        if not current or not new_password or not confirm:
            QMessageBox.warning(self, "Error", "Please fill all password fields")
            return
        
        if new_password != confirm:
            QMessageBox.warning(self, "Error", "New passwords do not match")
            return
        
        # Verify current password
        result = subprocess.run(
            ["./main", "verify", username, current],
            capture_output=True,
            text=True
        )
        
        if "Verification successful" in result.stdout:
            # Update password
            result = subprocess.run(
                ["./main", "update_password", username, new_password],
                capture_output=True,
                text=True
            )
            
            if "Password updated successfully" in result.stdout:
                QMessageBox.information(self, "Success", "Password has been updated")
                self.current_input.clear()
                self.new_input.clear()
                self.confirm_input.clear()
                self.log_with_timestamp(f"[SECURITY] User: {username}, Action: Changed password")
            else:
                QMessageBox.warning(self, "Error", "Failed to update password")
        else:
            QMessageBox.warning(self, "Error", "Current password is incorrect")
    
    def log_with_timestamp(self, message):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

class MainWindow(QTabWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()
        
    def init_ui(self):
        # Create tabs
        self.command_panel = CommandPanel(self)
        self.addTab(self.command_panel, "Command Panel")
        
        self.settings_panel = SettingsPanel(self)
        self.addTab(self.settings_panel, "Settings")
        
        self.log_viewer = LogViewer(self)
        self.addTab(self.log_viewer, "System Logs")
        
        # User management only visible to admins
        if self.parent.user_role.lower() == "admin":
            self.user_management = UserManagement(self)
            self.addTab(self.user_management, "User Management")
        
        # Logout button
        self.logout_button = QPushButton("Logout")
        self.logout_button.clicked.connect(self.logout)
        self.setCornerWidget(self.logout_button, Qt.TopRightCorner)
        
        # Set window properties
        self.setWindowTitle(f"Secure Access System - {self.parent.username} ({self.parent.user_role})")
        self.resize(800, 600)
        
    def logout(self):
        if QMessageBox.question(
            self, "Confirm Logout", 
            "Are you sure you want to logout?",
            QMessageBox.Yes | QMessageBox.No
        ) == QMessageBox.Yes:
            self.log_with_timestamp(f"[AUTH] User: {self.parent.username}, Status: Logout")
            self.parent.username = None
            self.parent.user_role = None
            self.parent.show_login_window()
            
    def log_with_timestamp(self, message):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

class MainApplication(QMainWindow):
    def __init__(self):
        super().__init__()
        self.username = None
        self.user_role = None
        self.init_ui()
        
    def init_ui(self):
        self.stacked_widget = QStackedWidget()
        
        # Create login and register windows
        self.login_window = LoginWindow(self)
        self.register_window = RegisterWindow(self)
        
        # Add to stacked widget
        self.stacked_widget.addWidget(self.login_window)
        self.stacked_widget.addWidget(self.register_window)
        
        self.setCentralWidget(self.stacked_widget)
        
        # Set window properties
        self.setWindowTitle("Secure Access System")
        self.resize(600, 400)
        
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        os.makedirs("users", exist_ok=True)
        
    def show_login_window(self):
        self.login_window = LoginWindow(self)
        self.stacked_widget.removeWidget(self.stacked_widget.widget(0))
        self.stacked_widget.insertWidget(0, self.login_window)
        self.stacked_widget.setCurrentIndex(0)
        self.setWindowTitle("Secure Access System")
        self.resize(600, 400)
        
    def show_main_window(self):
        self.main_window = MainWindow(self)
        # Replace any existing widgets with the main window
        for i in range(self.stacked_widget.count()):
            self.stacked_widget.removeWidget(self.stacked_widget.widget(0))
        self.stacked_widget.addWidget(self.main_window)
        self.stacked_widget.setCurrentIndex(0)
        self.setWindowTitle(f"Secure Access System - {self.username} ({self.user_role})")
        self.resize(800, 600)

if __name__ == "__main__":
    app = QApplication([])
    
    # Set application style
    app.setStyle("Fusion")
    
    # Dark theme
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.WindowText, Qt.white)
    dark_palette.setColor(QPalette.Base, QColor(35, 35, 35))
    dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ToolTipBase, QColor(25, 25, 25))
    dark_palette.setColor(QPalette.ToolTipText, Qt.white)
    dark_palette.setColor(QPalette.Text, Qt.white)
    dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ButtonText, Qt.white)
    dark_palette.setColor(QPalette.BrightText, Qt.red)
    dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(dark_palette)
    
    main_app = MainApplication()
    main_app.show()
    
    sys.exit(app.exec_())
