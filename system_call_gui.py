import tkinter as tk
from tkinter import messagebox
import subprocess

# Function to execute system calls securely
def execute_command():
    command = command_entry.get().strip()  # Get the command input from user
    
    if not command:
        messagebox.showerror("Error", "Command cannot be empty!")
        return

    try:
        # Run the system command securely
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)

        # Display output in the text box
        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)  # Clear previous output
        output_text.insert(tk.END, output)  # Insert new output
        output_text.config(state=tk.DISABLED)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Execution Error", f"Error executing command:\n{e.output}")

# Setting up the GUI window
root = tk.Tk()
root.title("Secure System Call Interface")
root.geometry("600x400")  # Set window size

# Label
tk.Label(root, text="Enter System Command:", font=("Arial", 12)).pack(pady=5)

# Input Field
command_entry = tk.Entry(root, width=50, font=("Arial", 12))
command_entry.pack(pady=5)

# Execute Button
execute_button = tk.Button(root, text="Execute", command=execute_command, font=("Arial", 12), bg="green", fg="white")
execute_button.pack(pady=10)

# Output Area
output_text = tk.Text(root, height=10, width=60, font=("Arial", 10), state=tk.DISABLED)
output_text.pack(pady=10)

# Run the GUI
root.mainloop()
