import tkinter as tk
from tkinter import messagebox
import random
import string

def generate_password():
    length = 12  # Default password length
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    password_entry.config(show='*')  # Hide password initially
    password_var.set(password)  # Store the password internally

def toggle_password():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')  # Show password
        show_password_btn.config(text='Hide Password')
    else:
        password_entry.config(show='*')  # Hide password
        show_password_btn.config(text='Show Password')

def check_strength():
    password = password_var.get()
    if len(password) < 8:
        messagebox.showinfo("Strength", "Weak Password")
    elif any(char.isdigit() for char in password) and any(char.isupper() for char in password):
        messagebox.showinfo("Strength", "Strong Password")
    else:
        messagebox.showinfo("Strength", "Moderate Password")

def hash_sha256():
    import hashlib
    password = password_var.get()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    messagebox.showinfo("SHA-256 Hash", hashed_password)

# GUI setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x300")

password_var = tk.StringVar()

# Password Entry
password_label = tk.Label(root, text="Generated Password:")
password_label.pack()
password_entry = tk.Entry(root, textvariable=password_var, state='readonly', show='*', width=30)
password_entry.pack()

# Show Password Button
show_password_btn = tk.Button(root, text="Show Password", command=toggle_password)
show_password_btn.pack()

# Generate Password Button
generate_btn = tk.Button(root, text="Generate Password", command=generate_password)
generate_btn.pack()

# Strength Check Button
strength_btn = tk.Button(root, text="Check Strength", command=check_strength)
strength_btn.pack()

# SHA-256 Hash Button
sha256_btn = tk.Button(root, text="SHA-256", command=hash_sha256)
sha256_btn.pack()

root.mainloop()
