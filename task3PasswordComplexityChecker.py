import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk, ImageFilter  # Import Pillow to handle blur

# Function to calculate and display password complexity
def check_password_complexity():
    password = password_entry.get()

    if len(password) < 8:
        feedback_label.config(text="Password too short! Must be at least 8 characters.", fg="red")
        return

    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in "!@#$%^&*()-_+=<>?/;:" for char in password)

    score = sum([has_upper, has_lower, has_digit, has_special])

    if len(password) >= 12:
        score += 1

    if score <= 2:
        feedback_label.config(text="Weak Password: Improve by adding more complexity!", fg="red")
    elif score == 3:
        feedback_label.config(text="Moderate Password: Can be better!", fg="orange")
    else:
        feedback_label.config(text="Strong Password: Good job!", fg="green")

# Function to toggle password visibility
def toggle_password_visibility():
    if show_password_var.get():
        password_entry.config(show="")  # Show password
    else:
        password_entry.config(show="*")  # Hide password

# Create the main application window
root = tk.Tk()
root.title("Password Complexity Checker")
root.geometry("320x260")
root.configure(bg="#f9f9f9")

# Create a plain white image to act as a background
bg_image = Image.new("RGB", (320, 260), "#f9f9f9")
bg_image = bg_image.filter(ImageFilter.GaussianBlur(5))  # Apply Gaussian blur to simulate transparency
bg_photo = ImageTk.PhotoImage(bg_image)

# Create a Label widget to display the background image
bg_label = tk.Label(root, image=bg_photo)
bg_label.place(relwidth=1, relheight=1)  # Fill the entire window with the background image

# Create the shadow effect frame (for the shadow)
shadow_frame = tk.Frame(root, bg="#808080", relief=tk.RAISED, bd=15)  # Increased border width for more shadow
shadow_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=280, height=240)

# Create the form frame on top of the shadow frame (for the content)
form_frame = tk.Frame(root, bg="white", relief=tk.RAISED, bd=0)  # No border, rounded corners
form_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=280, height=240)

# Header label
header_label = tk.Label(
    form_frame, 
    text="Password Checker", 
    font=("Poppins", 12, "bold"), 
    bg="#fff", 
    fg="#a7289b",
)
header_label.pack(pady=5)

# Password Entry Field
password_label = tk.Label(
    form_frame, 
    text="Enter Password (at least 8 characters):", 
    font=("Poppins", 10), 
    bg="white"
)
password_label.pack(anchor="w", padx=10, pady=5)
password_entry = tk.Entry(
    form_frame, 
    font=("Poppins", 10), 
    show="*", 
    width=25
)
password_entry.pack(pady=5)

# Toggle Password Visibility Checkbox
show_password_var = tk.BooleanVar()
show_password_checkbox = tk.Checkbutton(
    form_frame,
    text="Show Password",
    variable=show_password_var,
    onvalue=True,
    offvalue=False,
    command=toggle_password_visibility,
    bg="white",
    font=("Poppins", 9),
)
show_password_checkbox.pack(pady=5)

# Check Password Complexity Button
check_button = tk.Button(
    form_frame,
    text="Check Complexity",
    font=("Poppins", 10, "bold"),
    bg="#a7289b",  # Purple-pink color
    fg="white",
    relief=tk.FLAT,
    width=20,
    command=check_password_complexity,
)
# Styling the button with rounded corners
check_button.config(highlightbackground="#a7289b", borderwidth=0)
check_button.pack(pady=15)

# Feedback Label (with wraplength for responsiveness)
feedback_label = tk.Label(
    form_frame, 
    text="", 
    font=("Poppins", 10), 
    bg="white", 
    fg="#fff",
    wraplength=240  # Allow the text to wrap within the frame
)
feedback_label.pack(pady=5)

# Run the application
root.mainloop()
