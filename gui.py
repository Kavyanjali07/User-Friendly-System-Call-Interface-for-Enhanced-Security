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
        if totp.verify(self.code_input.text()):
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
        if totp.verify(self.code_input.text()):
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
        return "Unknown"
    
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
        
        role_label = QLabel("Role:")
        self.role_combo = QComboBox()
        self.role_combo.addItems(["User", "Admin"])
        
        form_layout.addWidget(username_label, 0, 0)
        form_layout.addWidget(self.username_input, 0, 1)
        form_layout.addWidget(password_label, 1, 0)
        form_layout.addWidget(self.password_input, 1, 1)
        form_layout.addWidget(confirm_label, 2, 0)
        form_layout.addWidget(self.confirm_input, 2, 1)
        form_layout.addWidget(role_label, 3, 0)
        form_layout.addWidget(self.role_combo, 3, 1)
        
        self.enable_2fa_checkbox = QPushButton("Enable Two-Factor Authentication")
        self.enable_2fa_checkbox.setCheckable(True)
        form_layout.addWidget(self.enable_2fa_checkbox, 4, 1)
        
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
        role = self.role_combo.currentText()
        
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
        
        if not command:
            return
            
        # Call the backend system call function using subprocess
        result = subprocess.run(
            ["./main", "run_cmd", username, command],
            capture_output=True,
            text=True
        )
        
        self.output_text.setText(result.stdout)
        
        # Log command execution with timestamp
        self.log_with_timestamp(f"[SYSCALL] User: {username}, Command: {command}")
        
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
        
        controls_layout.addWidget(refresh_button)
        
        layout.addLayout(controls_layout)
        
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

class MainWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header with user info
        header_layout = QHBoxLayout()
        
        self.welcome_label = QLabel("Welcome, User")
        self.welcome_label.setFont(QFont("Arial", 14))
        
        self.role_label = QLabel("Role: User")
        self.role_label.setAlignment(Qt.AlignRight)
        
        header_layout.addWidget(self.welcome_label)
        header_layout.addWidget(self.role_label)
        
        layout.addLayout(header_layout)
        
        # Tabs
        self.tabs = QTabWidget()
        
        self.command_panel = CommandPanel(self)
        self.log_viewer = LogViewer(self)
        self.user_management = UserManagement(self)
        
        self.tabs.addTab(self.command_panel, "Command Panel")
        self.tabs.addTab(self.log_viewer, "Log Viewer")
        self.tabs.addTab(self.user_management, "User Management")
        
        layout.addWidget(self.tabs)
        
        # Logout button
        logout_layout = QHBoxLayout()
        logout_layout.addStretch()
        
        self.logout_button = QPushButton("Logout")
        self.logout_button.clicked.connect(self.logout)
        logout_layout.addWidget(self.logout_button)
        
        layout.addLayout(logout_layout)
        
        self.setLayout(layout)
        
    def update_user_info(self, username, role):
        self.welcome_label.setText(f"Welcome, {username}")
        self.role_label.setText(f"Role: {role}")
        
        # Hide User Management tab for non-admin users
        if role.lower() != "admin":
            self.tabs.setTabVisible(2, False)
        else:
            self.tabs.setTabVisible(2, True)
            
    def logout(self):
        # Log logout with timestamp
        username = self.parent.username
        self.log_with_timestamp(f"[AUTH] User: {username}, Status: Logout")
        
        self.parent.username = ""
        self.parent.user_role = ""
        self.parent.show_login_window()
        
    def log_with_timestamp(self, message):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

class SecureAccessSystem(QMainWindow):
    def __init__(self):
        super().__init__()
        self.username = ""
        self.user_role = ""
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Secure Access System")
        self.setMinimumSize(800, 600)
        
        # Set cybersecurity-themed dark style# Set cybersecurity-themed dark style
        self.set_dark_theme()
        
        # Create stacked widget for different screens
        self.stacked_widget = QStackedWidget()
        
        # Create login and register screens
        self.login_window = LoginWindow(self)
        self.register_window = RegisterWindow(self)
        self.main_window = MainWindow(self)
        
        # Add screens to stacked widget
        self.stacked_widget.addWidget(self.login_window)
        self.stacked_widget.addWidget(self.register_window)
        self.stacked_widget.addWidget(self.main_window)
        
        # Set initial screen
        self.stacked_widget.setCurrentIndex(0)
        
        self.setCentralWidget(self.stacked_widget)
        
    def set_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
            }
            QLabel {
                color: #cdd6f4;
            }
            QPushButton {
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 4px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #45475a;
                border: 1px solid #585b70;
            }
            QPushButton:pressed {
                background-color: #585b70;
            }
            QPushButton:checked {
                background-color: #89b4fa;
                color: #1e1e2e;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 4px;
                padding: 5px;
            }
            QTableWidget {
                background-color: #313244;
                color: #cdd6f4;
                gridline-color: #45475a;
                border: 1px solid #45475a;
            }
            QHeaderView::section {
                background-color: #45475a;
                color: #cdd6f4;
                border: 1px solid #585b70;
                padding: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #45475a;
                border-radius: 4px;
            }
            QTabBar::tab {
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-bottom-color: transparent;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 5px 10px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #45475a;
            }
            QTabBar::tab:hover {
                background-color: #585b70;
            }
        """)
        
    def show_login_window(self):
        self.stacked_widget.setCurrentIndex(0)
        self.login_window.username_input.clear()
        self.login_window.password_input.clear()
        self.login_window.status_label.clear()
        
    def show_register_window(self):
        self.stacked_widget.setCurrentIndex(1)
        
    def show_main_window(self):
        self.stacked_widget.setCurrentIndex(2)
        self.main_window.update_user_info(self.username, self.user_role)
        
def main():
    app = QApplication(sys.argv)
    
    # Set application icon
    #app.setWindowIcon(QIcon("icon.png"))
    
    # Create directories if they don't exist
    os.makedirs("users", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    
    window = SecureAccessSystem()
    window.show()
    
    sys.exit(app.exec_())
    
if __name__ == "__main__":
    main()
