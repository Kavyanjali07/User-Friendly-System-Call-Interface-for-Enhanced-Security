#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import qrcode
import pyotp
import hashlib
from PyQt5.QtWidgets import (QFrame, QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QStackedWidget, QComboBox, 
                            QTextEdit, QDialog, QTabWidget, QGridLayout, QMessageBox,
                            QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog)
from PyQt5.QtGui import QPixmap, QIcon, QFont, QColor, QPalette
from PyQt5.QtCore import Qt, QTimer, QDateTime

# Constants
TOTP_SECRET_FILE = "users/totp_secrets.txt"
LOG_FILE = "logs/system_logs.txt"
# List of commands that regular users are allowed to run
USER_ALLOWED_COMMANDS = ["ls", "uptime", "echo", "pwd", "touch", "cat", "nano"]

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
        
        # Quick command buttons - show all buttons for admin, only allowed ones for users
        quick_commands_label = QLabel("Quick Commands:")
        layout.addWidget(quick_commands_label)
        
        quick_buttons = QHBoxLayout()
        
        # Create buttons for common commands - show all for admin and only allowed ones for users
        commands_to_add = USER_ALLOWED_COMMANDS
        if self.parent.parent.user_role.lower() == "admin":
            # Add more admin commands
            commands_to_add += ["whoami", "ps", "df", "netstat", "ifconfig"]
        
        # Create a button for each allowed command
        for cmd in commands_to_add[:5]:  # Show only first 5 buttons in first row
            button = QPushButton(cmd)
            button.clicked.connect(lambda checked, cmd=cmd: self.set_command(cmd))
            quick_buttons.addWidget(button)
        
        layout.addLayout(quick_buttons)
        
        # Add second row of buttons if needed
        if len(commands_to_add) > 5:
            quick_buttons2 = QHBoxLayout()
            for cmd in commands_to_add[5:]:
                button = QPushButton(cmd)
                button.clicked.connect(lambda checked, cmd=cmd: self.set_command(cmd))
                quick_buttons2.addWidget(button)
            layout.addLayout(quick_buttons2)
        
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
    
    # At this point, either the user is an admin, or the command is in the allowed list
    # Call the backend system call function using subprocess
        try:
            if command_base in ['ps', 'df', 'whoami', 'netstat', 'ifconfig'] and user_role.lower() == "admin":
            # For admin-specific commands, run them directly
                result = subprocess.run(
                    command.split(),
                    capture_output=True,
                    text=True,
                    timeout=10  # Add timeout for safety
                )
                output = result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
            else:
            # Use the normal command execution path for other commands
                result = subprocess.run(
                    ["./main", "run_cmd", username, command],
                    capture_output=True,
                    text=True
                )
                output = result.stdout
            
            self.output_text.setText(output)
        
        # Log command execution with timestamp
            status = "Executed" if result.returncode == 0 else "Failed"
            self.log_with_timestamp(f"[SYSCALL] User: {username}, Command: {command}, Status: {status}")
        except Exception as e:
            self.output_text.setText(f"Error executing command: {str(e)}")
            self.log_with_timestamp(f"[SYSCALL] User: {username}, Command: {command}, Status: Error ({str(e)})")
        
    def log_with_timestamp(self, message):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

class ProfileSettings(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()
        self.load_settings()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Profile Settings")
        header.setAlignment(Qt.AlignCenter)
        header.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(header)
        
        # User info section
        info_group = QGridLayout()
        
        username_label = QLabel("Username:")
        username_value = QLabel(self.parent.parent.username)
        username_value.setFont(QFont("Arial", 10, QFont.Bold))
        
        role_label = QLabel("Role:")
        role_value = QLabel(self.parent.parent.user_role)
        role_value.setFont(QFont("Arial", 10, QFont.Bold))
        
        # Check for 2FA status
        has_2fa = self.check_2fa_status(self.parent.parent.username)
        tfa_label = QLabel("2FA Status:")
        tfa_value = QLabel("Enabled" if has_2fa else "Disabled")
        tfa_value.setFont(QFont("Arial", 10, QFont.Bold))
        
        info_group.addWidget(username_label, 0, 0)
        info_group.addWidget(username_value, 0, 1)
        info_group.addWidget(role_label, 1, 0)
        info_group.addWidget(role_value, 1, 1)
        info_group.addWidget(tfa_label, 2, 0)
        info_group.addWidget(tfa_value, 2, 1)
        
        layout.addLayout(info_group)
        
        # Password change section
        password_group_label = QLabel("Change Password")
        password_group_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(password_group_label)
        
        password_layout = QGridLayout()
        
        current_pwd_label = QLabel("Current Password:")
        self.current_pwd_input = QLineEdit()
        self.current_pwd_input.setEchoMode(QLineEdit.Password)
        
        new_pwd_label = QLabel("New Password:")
        self.new_pwd_input = QLineEdit()
        self.new_pwd_input.setEchoMode(QLineEdit.Password)
        
        confirm_pwd_label = QLabel("Confirm New Password:")
        self.confirm_pwd_input = QLineEdit()
        self.confirm_pwd_input.setEchoMode(QLineEdit.Password)
        
        password_layout.addWidget(current_pwd_label, 0, 0)
        password_layout.addWidget(self.current_pwd_input, 0, 1)
        password_layout.addWidget(new_pwd_label, 1, 0)
        password_layout.addWidget(self.new_pwd_input, 1, 1)
        password_layout.addWidget(confirm_pwd_label, 2, 0)
        password_layout.addWidget(self.confirm_pwd_input, 2, 1)
        
        layout.addLayout(password_layout)
        
        # Change password button
        change_pwd_button = QPushButton("Change Password")
        change_pwd_button.clicked.connect(self.change_password)
        layout.addWidget(change_pwd_button)
        
        # 2FA management section
        tfa_group_label = QLabel("Two-Factor Authentication")
        tfa_group_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(tfa_group_label)
        
        # Toggle 2FA button (text depends on current state)
        self.toggle_2fa_button = QPushButton("Disable 2FA" if has_2fa else "Enable 2FA")
        self.toggle_2fa_button.clicked.connect(self.toggle_2fa)
        layout.addWidget(self.toggle_2fa_button)
        
        # Theme section
        theme_group_label = QLabel("Theme Settings")
        theme_group_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(theme_group_label)
        
        theme_layout = QHBoxLayout()
        theme_label = QLabel("Select Theme:")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark Theme", "Light Theme", "System Default"])
        self.theme_combo.currentIndexChanged.connect(self.change_theme)
        
        theme_layout.addWidget(theme_label)
        theme_layout.addWidget(self.theme_combo)
        
        layout.addLayout(theme_layout)
        
        # Save button
        save_button = QPushButton("Save Settings")
        save_button.clicked.connect(self.save_settings)
        layout.addWidget(save_button)
        
        # Status message
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        self.setLayout(layout)
        
    def check_2fa_status(self, username):
        """Check if the user has 2FA enabled"""
        if os.path.exists(TOTP_SECRET_FILE):
            with open(TOTP_SECRET_FILE, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] == username:
                        return True
        return False
        
    def change_password(self):
        """Handle password change"""
        current_pwd = self.current_pwd_input.text()
        new_pwd = self.new_pwd_input.text()
        confirm_pwd = self.confirm_pwd_input.text()
        username = self.parent.parent.username
        
        if not current_pwd or not new_pwd or not confirm_pwd:
            self.status_label.setText("Please fill all password fields")
            return
            
        if new_pwd != confirm_pwd:
            self.status_label.setText("New passwords do not match")
            return
            
        # Verify current password
        result = subprocess.run(
            ["./main", "verify_password", username, current_pwd],
            capture_output=True,
            text=True
        )
        
        if "Password verified" not in result.stdout:
            self.status_label.setText("Current password is incorrect")
            return
            
        # Update password
        result = subprocess.run(
            ["./main", "change_password", username, new_pwd],
            capture_output=True,
            text=True
        )
        
        if "Password updated" in result.stdout:
            self.status_label.setText("Password changed successfully")
            self.log_with_timestamp(f"[PROFILE] User: {username}, Action: Password changed")
            # Clear password fields
            self.current_pwd_input.clear()
            self.new_pwd_input.clear()
            self.confirm_pwd_input.clear()
        else:
            self.status_label.setText("Failed to update password")
        
    def toggle_2fa(self):
        """Enable or disable 2FA"""
        username = self.parent.parent.username
        has_2fa = self.check_2fa_status(username)
        
        if has_2fa:
            # Disable 2FA
            if os.path.exists(TOTP_SECRET_FILE):
                updated_lines = []
                with open(TOTP_SECRET_FILE, "r") as f:
                    for line in f:
                        if not line.strip().startswith(username + " "):
                            updated_lines.append(line)
                            
                with open(TOTP_SECRET_FILE, "w") as f:
                    f.writelines(updated_lines)
                    
                self.toggle_2fa_button.setText("Enable 2FA")
                self.status_label.setText("Two-factor authentication disabled")
                self.log_with_timestamp(f"[PROFILE] User: {username}, Action: 2FA disabled")
        else:
            # Enable 2FA
            setup_dialog = TwoFactorSetupDialog(username)
            if setup_dialog.exec_() == QDialog.Accepted:
                self.toggle_2fa_button.setText("Disable 2FA")
                self.status_label.setText("Two-factor authentication enabled")
                self.log_with_timestamp(f"[PROFILE] User: {username}, Action: 2FA enabled")
        
    def change_theme(self):
        """Change application theme"""
        theme = self.theme_combo.currentText()
        
        if theme == "Dark Theme":
            # Apply dark theme
            self.apply_dark_theme()
        elif theme == "Light Theme":
            # Apply light theme
            self.apply_light_theme()
        else:
            # Apply system default theme
            app = QApplication.instance()
            app.setPalette(app.style().standardPalette())
            
        self.status_label.setText(f"Theme changed to {theme}")
        
    def apply_dark_theme(self):
        app = QApplication.instance()
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        app.setPalette(dark_palette)
        
    def apply_light_theme(self):
        app = QApplication.instance()
        light_palette = QPalette()
        light_palette.setColor(QPalette.Window, QColor(240, 240, 240))
        light_palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
        light_palette.setColor(QPalette.Base, QColor(255, 255, 255))
        light_palette.setColor(QPalette.AlternateBase, QColor(245, 245, 245))
        light_palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
        light_palette.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
        light_palette.setColor(QPalette.Text, QColor(0, 0, 0))
        light_palette.setColor(QPalette.Button, QColor(240, 240, 240))
        light_palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))
        light_palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        light_palette.setColor(QPalette.Link, QColor(0, 0, 255))
        light_palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
        light_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        app.setPalette(light_palette)
        
    def save_settings(self):
        """Save user settings to file"""
        username = self.parent.parent.username
        theme = self.theme_combo.currentText()
        
        # Create settings directory if it doesn't exist
        os.makedirs("settings", exist_ok=True)
        
        # Save theme preference
        with open(f"settings/{username}_settings.txt", "w") as f:
            f.write(f"theme={theme}\n")
            
        self.status_label.setText("Settings saved successfully")
        self.log_with_timestamp(f"[PROFILE] User: {username}, Action: Settings saved")
        
    def log_with_timestamp(self, message):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
            
    def load_settings(self):
        """Load user settings from file"""
        username = self.parent.parent.username
        settings_file = f"settings/{username}_settings.txt"
        
        if os.path.exists(settings_file):
            with open(settings_file, "r") as f:
                for line in f:
                    if line.startswith("theme="):
                        theme = line.strip().split("=")[1]
                        index = self.theme_combo.findText(theme)
                        if index >= 0:
                            self.theme_combo.setCurrentIndex(index)
                            # Apply the theme
                            self.change_theme()

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
        
        # User deletion section
        delete_layout = QHBoxLayout()
        delete_label = QLabel("Delete User:")
        self.delete_input = QLineEdit()
        self.delete_input.setPlaceholderText("Enter username")
        delete_button = QPushButton("Delete")
        delete_button.clicked.connect(self.delete_user)
        
        delete_layout.addWidget(delete_label)
        delete_layout.addWidget(self.delete_input)
        delete_layout.addWidget(delete_button)
        
        controls_layout.addWidget(refresh_button)
        
        layout.addLayout(controls_layout)
        layout.addLayout(promote_layout)
        layout.addLayout(delete_layout)
        
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
    
    def delete_user(self):
        username = self.delete_input.text().strip()
        if not username:
            QMessageBox.warning(self, "Error", "Please enter a username to delete")
            return
        
        # Prevent admin from deleting themselves
        if username == self.parent.parent.username:
            QMessageBox.warning(self, "Error", "You cannot delete your own account while logged in")
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
                        # Skip this line to delete the user
                    else:
                        updated_lines.append(line)
                        
            if user_found:
                # Confirm deletion
                confirm = QMessageBox.question(
                    self, 
                    "Confirm Deletion", 
                    f"Are you sure you want to delete user '{username}'?",
                    QMessageBox.Yes | QMessageBox.No
                )
                
                if confirm == QMessageBox.Yes:
                    # Write updated user data
                    with open("users/user_data.txt", "w") as f:
                        f.writelines(updated_lines)
                    
                    # Also remove from TOTP secrets if exists
                    if os.path.exists(TOTP_SECRET_FILE):
                        totp_lines = []
                        with open(TOTP_SECRET_FILE, "r") as f:
                            for line in f:
                                if not line.strip().startswith(username + " "):
                                    totp_lines.append(line)
                        
                        with open(TOTP_SECRET_FILE, "w") as f:
                            f.writelines(totp_lines)
                    
                    QMessageBox.information(self, "Success", f"User '{username}' has been deleted")
                    self.log_with_timestamp(f"[ADMIN] User '{username}' deleted by {self.parent.parent.username}")
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

class MainWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()
        self.apply_dashboard_style()
        
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)  # Reduced spacing
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Enhanced header with user info and time - MADE COMPACT
        header_frame = QFrame()
        header_frame.setStyleSheet("QFrame {background-color: #2A2A2A; border-radius: 10px; padding: 8px;}")  # Reduced padding
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(15, 5, 15, 5)  # Reduced margins
        
        # User greeting with icon - simplified
        user_container = QHBoxLayout()
        user_icon = QLabel("👤")
        user_icon.setFont(QFont("Arial", 14))  # Slightly smaller font
        user_icon.setStyleSheet("color: #4DA6FF;")
        
        user_info = QHBoxLayout()  # Changed to horizontal layout
        welcome_label = QLabel(f"Welcome, {self.parent.username}")
        welcome_label.setFont(QFont("Arial", 12, QFont.Bold))  # Smaller font
        welcome_label.setStyleSheet("color: #FFFFFF;")
        
        role_label = QLabel(f" ({self.parent.user_role})")  # Simplified role display
        role_label.setFont(QFont("Arial", 10))
        role_label.setStyleSheet("color: #AAAAAA;")
        
        user_info.addWidget(welcome_label)
        user_info.addWidget(role_label)
        
        user_container.addWidget(user_icon)
        user_container.addLayout(user_info)
        user_container.addStretch()
        
        # Time display - simplified to one line
        time_label = QLabel(QDateTime.currentDateTime().toString("hh:mm AP - ddd, MMM d"))
        time_label.setFont(QFont("Arial", 11))
        time_label.setStyleSheet("color: #AAAAAA;")
        time_label.setAlignment(Qt.AlignRight)
        
        # Logout button
        logout_button = QPushButton("Logout")
        logout_button.setStyleSheet("""
            QPushButton {
                background-color: #3D3D3D;
                color: #FFFFFF;
                border: none;
                border-radius: 5px;
                padding: 5px 12px;  /* Smaller padding */
            }
            QPushButton:hover {
                background-color: #E53935;
            }
        """)
        logout_button.clicked.connect(self.logout)
        
        header_layout.addLayout(user_container)
        header_layout.addStretch()
        header_layout.addWidget(time_label)
        header_layout.addWidget(logout_button)
        
        main_layout.addWidget(header_frame)
        
        # System status quick overview - MADE SMALLER
        status_frame = QFrame()
        status_frame.setStyleSheet("QFrame {background-color: #2A2A2A; border-radius: 10px; padding: 10px;}")  # Reduced padding
        status_layout = QHBoxLayout(status_frame)  # Changed to horizontal layout
        status_layout.setContentsMargins(10, 5, 10, 5)  # Reduced margins
        
        status_header = QLabel("System Status:")
        status_header.setFont(QFont("Arial", 11, QFont.Bold))
        status_header.setStyleSheet("color: #FFFFFF;")
        status_layout.addWidget(status_header)
        
        # Create compact status indicators
        status_metrics = [
            {"title": "Uptime", "value": self.get_system_uptime(), "icon": "⏱️"},
            {"title": "Last Login", "value": self.get_last_login(), "icon": "🔑"},
            {"title": "Security", "value": "Protected" if self.check_2fa_status() else "Basic", "icon": "🔒"}
        ]
        
        for metric in status_metrics:
            status_layout.addWidget(QLabel("|"))  # Separator
            
            metric_layout = QHBoxLayout()
            icon_label = QLabel(metric["icon"])
            icon_label.setFont(QFont("Arial", 12))
            
            info_label = QLabel(f"{metric['title']}: {metric['value']}")
            info_label.setFont(QFont("Arial", 10))
            info_label.setStyleSheet("color: #4DA6FF;")
            
            metric_layout.addWidget(icon_label)
            metric_layout.addWidget(info_label)
            
            container = QWidget()
            container.setLayout(metric_layout)
            status_layout.addWidget(container)
        
        status_layout.addStretch()
        main_layout.addWidget(status_frame)
        
        # Dashboard tabs with enhanced styling - GIVE MORE SPACE
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3D3D3D;
                background-color: #2A2A2A;
                border-radius: 5px;
            }
            QTabBar::tab {
                background-color: #353535;
                color: #AAAAAA;
                padding: 8px 15px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #2A2A2A;
                color: #FFFFFF;
            }
            QTabBar::tab:hover:!selected {
                background-color: #404040;
            }
        """)
        
        # Add Profile Settings tab - available to all users
        self.profile_settings = ProfileSettings(self)
        self.tabs.addTab(self.profile_settings, "Profile Settings")
        self.tabs.setTabToolTip(0, "Configure your account preferences and security settings")
        
        # Command Panel tab
        self.command_panel = CommandPanel(self)
        self.tabs.addTab(self.command_panel, "Command Panel")
        self.tabs.setTabToolTip(1, "Execute system commands with proper authorization")
        
        # Admin-only tabs
        tab_index = 2
        if self.parent.user_role.lower() == "admin":
            # Log Viewer tab
            self.log_viewer = LogViewer(self)
            self.tabs.addTab(self.log_viewer, "System Logs")
            self.tabs.setTabToolTip(tab_index, "View and analyze system activity logs")
            tab_index += 1
            
            # User Management tab
            self.user_management = UserManagement(self)
            self.tabs.addTab(self.user_management, "User Management")
            self.tabs.setTabToolTip(tab_index, "Manage user accounts and permissions")
        
        # Give the tab widget more space
        main_layout.addWidget(self.tabs, 1)  # Give it a stretch factor of 1
        
        # Minimal status bar
        status_bar = QLabel(f"Secure Access System v2.0")
        status_bar.setStyleSheet("color: #777777; font-size: 9pt;")
        status_bar.setAlignment(Qt.AlignRight)
        main_layout.addWidget(status_bar)
        
        self.setLayout(main_layout)
        
        # Set minimum size for the window to ensure command area is visible
        self.setMinimumSize(800, 600)
    
    def get_system_uptime(self):
        """Get system uptime or a placeholder value"""
        try:
            result = subprocess.run(["uptime", "-p"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().replace("up ", "")  # Simplified
            return "3d 7h"
        except:
            return "3d 7h"  # Shorter fallback value
    
    def get_last_login(self):
        """Get user's last login time from logs or use placeholder"""
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    for line in reversed(list(f)):
                        if f"[AUTH] User: {self.parent.username}, Status: Success" in line:
                            # Extract timestamp and simplify
                            timestamp = line.split("[", 2)[1].split("]")[0]
                            # Return just the date part if today, otherwise abbreviated
                            return timestamp.split()[1]  # Just return time portion
            return "Yesterday"
        except:
            return "Yesterday"
    
    def check_2fa_status(self):
        """Check if the current user has 2FA enabled"""
        username = self.parent.username
        if os.path.exists(TOTP_SECRET_FILE):
            with open(TOTP_SECRET_FILE, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] == username:
                        return True
        return False
    
    def apply_dashboard_style(self):
        """Apply custom styling to the dashboard"""
        self.setStyleSheet("""
            QWidget {
                background-color: #202020;
                color: #DDDDDD;
            }
            QLabel {
                color: #DDDDDD;
            }
            QPushButton {
                background-color: #3D3D3D;
                color: #FFFFFF;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #4DA6FF;
            }
            QLineEdit {
                background-color: #353535;
                border: 1px solid #454545;
                border-radius: 4px;
                padding: 6px;
                color: #FFFFFF;
            }
            QTextEdit {
                background-color: #353535;
                border: 1px solid #454545;
                border-radius: 4px;
                padding: 6px;
                color: #FFFFFF;
            }
        """)
        
    def logout(self):
        # Log logout action
        self.log_with_timestamp(f"[AUTH] User: {self.parent.username}, Status: Logout")
        
        # Switch back to login screen
        self.parent.show_login_window()
        
    def log_with_timestamp(self, message):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

class SecureAccessApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.username = ""
        self.user_role = ""
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Secure Access System")
        self.setMinimumSize(800, 600)
        
        # Create stacked widget for different screens
        self.stacked_widget = QStackedWidget()
        
        # Create login window
        self.login_window = LoginWindow(self)
        self.stacked_widget.addWidget(self.login_window)
        
        # Create register window
        self.register_window = RegisterWindow(self)
        self.stacked_widget.addWidget(self.register_window)
        
        # Create main application window
        self.main_window = MainWindow(self)
        self.stacked_widget.addWidget(self.main_window)
        
        # Set central widget
        self.setCentralWidget(self.stacked_widget)
        
        # Start with login window
        self.show_login_window()
        
    def show_login_window(self):
        self.username = ""
        self.user_role = ""
        self.stacked_widget.setCurrentIndex(0)
        
    def show_main_window(self):
        # Refresh main window to update user information
        self.stacked_widget.removeWidget(self.main_window)
        self.main_window = MainWindow(self)
        self.stacked_widget.addWidget(self.main_window)
        self.stacked_widget.setCurrentIndex(2)
        
if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create dark palette
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.WindowText, Qt.white)
    dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
    dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
    dark_palette.setColor(QPalette.ToolTipText, Qt.white)
    dark_palette.setColor(QPalette.Text, Qt.white)
    dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ButtonText, Qt.white)
    dark_palette.setColor(QPalette.BrightText, Qt.red)
    dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.HighlightedText, Qt.black)
    
    # Apply palette
    app.setPalette(dark_palette)
    
    # Create and show application
    window = SecureAccessApp()
    window.show()
    
    sys.exit(app.exec_())
