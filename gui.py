import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess

class SecureSysCallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure System Call Interface")
        self.root.geometry("500x400")

        # Username Entry
        tk.Label(root, text="Username:").pack()
        self.username_entry = tk.Entry(root)
        self.username_entry.pack()

        # Password Entry
        tk.Label(root, text="Password:").pack()
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        # Login Button
        tk.Button(root, text="Login", command=self.authenticate).pack()

        # Command Entry & Execute Button
        self.command_frame = tk.Frame(root)
        self.command_frame.pack(pady=10)
        
        tk.Label(self.command_frame, text="Command:").pack(side=tk.LEFT)
        self.command_entry = tk.Entry(self.command_frame)
        self.command_entry.pack(side=tk.LEFT)
        
        tk.Button(self.command_frame, text="Run", command=self.run_command).pack(side=tk.LEFT)
        tk.Button(self.command_frame, text="View Logs", command=self.view_logs).pack(side=tk.LEFT)

        # Output Box
        self.output_box = scrolledtext.ScrolledText(root, height=10, width=60)
        self.output_box.pack()

        self.process = None

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        self.process = subprocess.Popen(
            ["./secure_syscall"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        self.process.stdin.write(username + "\n")
        self.process.stdin.write(password + "\n")
        self.process.stdin.flush()

        response = self.process.stdout.readline().strip()

        if response == "AUTH_SUCCESS":
            messagebox.showinfo("Login", "Authentication Successful!")
        else:
            messagebox.showerror("Login", "Authentication Failed!")
            self.process = None  

    def run_command(self):
        if self.process:
            command = self.command_entry.get()
            self.process.stdin.write(command + "\n")
            self.process.stdin.flush()
            output = self.process.stdout.readline().strip()
            self.output_box.insert(tk.END, output + "\n")
        else:
            messagebox.showerror("Error", "Please login first!")

    def view_logs(self):
        if self.process:
            self.process.stdin.write("LOGS\n")
            self.process.stdin.flush()

            log_output = ""
            while True:
                line = self.process.stdout.readline().strip()
                if not line:
                    break
                log_output += line + "\n"

            self.output_box.insert(tk.END, "=== LOGS ===\n" + log_output + "\n")
        else:
            messagebox.showerror("Error", "Please login first!")

root = tk.Tk()
app = SecureSysCallGUI(root)
root.mainloop()
