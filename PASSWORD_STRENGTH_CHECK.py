import tkinter as tk
from tkinter import ttk, messagebox
import re
import string
import hashlib
import math


class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("600x500")
        self.root.resizable(False, False)
        self.root.configure(bg="#f0f0f0")

        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Create main frame
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Create GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Title
        title_label = ttk.Label(
            self.main_frame,
            text="Password Strength Checker",
            font=("Arial", 16, "bold")
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # Password entry
        ttk.Label(
            self.main_frame,
            text="Enter Password:",
            font=("Arial", 10)
        ).grid(row=1, column=0, sticky=tk.W, pady=(0, 5))

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            self.main_frame,
            textvariable=self.password_var,
            show="•",
            font=("Arial", 12),
            width=40
        )
        self.password_entry.grid(row=2, column=0, sticky=tk.EW, pady=(0, 10))
        self.password_entry.bind("<KeyRelease>", self.check_password_strength)

        # Show password checkbox
        self.show_password_var = tk.IntVar()
        self.show_password_cb = ttk.Checkbutton(
            self.main_frame,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        self.show_password_cb.grid(row=3, column=0, sticky=tk.W, pady=(0, 20))

        # Strength indicator
        ttk.Label(
            self.main_frame,
            text="Password Strength:",
            font=("Arial", 10)
        ).grid(row=4, column=0, sticky=tk.W, pady=(0, 5))

        self.strength_bar = ttk.Progressbar(
            self.main_frame,
            orient=tk.HORIZONTAL,
            length=400,
            mode='determinate'
        )
        self.strength_bar.grid(row=5, column=0, sticky=tk.EW, pady=(0, 5))

        self.strength_label = ttk.Label(
            self.main_frame,
            text="Not checked",
            font=("Arial", 10, "bold")
        )
        self.strength_label.grid(row=6, column=0, sticky=tk.W, pady=(0, 20))

        # Details frame
        details_frame = ttk.LabelFrame(
            self.main_frame,
            text="Password Analysis",
            padding="10"
        )
        details_frame.grid(row=7, column=0, sticky=tk.EW, pady=(0, 20))
        details_frame.columnconfigure(0, weight=1)

        # Criteria labels
        self.length_var = tk.StringVar(value="❌ At least 8 characters")
        ttk.Label(
            details_frame,
            textvariable=self.length_var,
            font=("Arial", 9)
        ).grid(row=0, column=0, sticky=tk.W, pady=2)

        self.uppercase_var = tk.StringVar(value="❌ Contains uppercase letters")
        ttk.Label(
            details_frame,
            textvariable=self.uppercase_var,
            font=("Arial", 9)
        ).grid(row=1, column=0, sticky=tk.W, pady=2)

        self.lowercase_var = tk.StringVar(value="❌ Contains lowercase letters")
        ttk.Label(
            details_frame,
            textvariable=self.lowercase_var,
            font=("Arial", 9)
        ).grid(row=2, column=0, sticky=tk.W, pady=2)

        self.digit_var = tk.StringVar(value="❌ Contains digits")
        ttk.Label(
            details_frame,
            textvariable=self.digit_var,
            font=("Arial", 9)
        ).grid(row=3, column=0, sticky=tk.W, pady=2)

        self.special_var = tk.StringVar(value="❌ Contains special characters")
        ttk.Label(
            details_frame,
            textvariable=self.special_var,
            font=("Arial", 9)
        ).grid(row=4, column=0, sticky=tk.W, pady=2)

        self.common_var = tk.StringVar(value="✅ Not a common password")
        ttk.Label(
            details_frame,
            textvariable=self.common_var,
            font=("Arial", 9)
        ).grid(row=5, column=0, sticky=tk.W, pady=2)

        # Entropy label
        self.entropy_var = tk.StringVar(value="Entropy: 0 bits")
        ttk.Label(
            self.main_frame,
            textvariable=self.entropy_var,
            font=("Arial", 9)
        ).grid(row=8, column=0, sticky=tk.W, pady=(0, 20))

        # Check button
        self.check_button = ttk.Button(
            self.main_frame,
            text="Check Password",
            command=self.check_password_strength
        )
        self.check_button.grid(row=9, column=0, pady=(0, 10))

        # Set column weight for proper resizing
        self.main_frame.columnconfigure(0, weight=1)

    def toggle_password_visibility(self):
        if self.show_password_var.get() == 1:
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")

    def check_password_strength(self, event=None):
        password = self.password_var.get()

        if not password:
            self.strength_bar['value'] = 0
            self.strength_label.config(text="No password entered")
            return

        # Check criteria
        length_ok = len(password) >= 8
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        is_common = self.is_common_password(password)

        # Update criteria labels
        self.length_var.set("✅ At least 8 characters" if length_ok else "❌ At least 8 characters")
        self.uppercase_var.set("✅ Contains uppercase letters" if has_upper else "❌ Contains uppercase letters")
        self.lowercase_var.set("✅ Contains lowercase letters" if has_lower else "❌ Contains lowercase letters")
        self.digit_var.set("✅ Contains digits" if has_digit else "❌ Contains digits")
        self.special_var.set("✅ Contains special characters" if has_special else "❌ Contains special characters")
        self.common_var.set("✅ Not a common password" if not is_common else "❌ Common password")

        # Calculate score (0-100)
        score = 0
        if length_ok:
            score += 20
        if has_upper:
            score += 20
        if has_lower:
            score += 20
        if has_digit:
            score += 20
        if has_special:
            score += 10
        if not is_common:
            score += 10

        # Adjust score based on length beyond minimum
        if len(password) > 12:
            score = min(100, score + 10)
        if len(password) > 16:
            score = min(100, score + 10)

        # Calculate entropy
        entropy = self.calculate_entropy(password)
        self.entropy_var.set(f"Entropy: {entropy:.2f} bits")

        # Update progress bar and label
        self.strength_bar['value'] = score

        # Set strength text and color
        if score < 40:
            self.strength_label.config(text="Very Weak", foreground="red")
        elif score < 60:
            self.strength_label.config(text="Weak", foreground="orange")
        elif score < 80:
            self.strength_label.config(text="Moderate", foreground="blue")
        elif score < 90:
            self.strength_label.config(text="Strong", foreground="green")
        else:
            self.strength_label.config(text="Very Strong", foreground="darkgreen")

    def calculate_entropy(self, password):
        """Calculate the entropy of a password in bits"""
        # Character set detection
        char_set = 0
        if any(c in string.ascii_lowercase for c in password):
            char_set += 26
        if any(c in string.ascii_uppercase for c in password):
            char_set += 26
        if any(c in string.digits for c in password):
            char_set += 10
        if any(c in string.punctuation for c in password):
            char_set += 32

        # If no character set detected, assume minimal
        if char_set == 0:
            char_set = 1

        # Calculate entropy
        entropy = len(password) * math.log2(char_set)
        return entropy

    def is_common_password(self, password):
        """Check if the password is in a list of common passwords"""
        common_passwords = {
            'password', '123456', '12345678', '1234', 'qwerty', '12345',
            'dragon', 'baseball', 'football', 'letmein', 'monkey', 'mustang',
            'michael', 'shadow', 'master', 'jennifer', '111111', '2000',
            'jordan', 'superman', 'harley', '1234567', 'freedom', 'matrix',
            'hello', 'cookie', 'password1', 'solo', 'banana', 'starwars',
            'welcome', 'photoshop', 'password123', 'trustno1', 'whatever',
            'admin', 'login', 'passw0rd', 'sunshine', 'princess', 'azerty',
            '123123', '654321', '1q2w3e4r', 'qwerty123', 'iloveyou', 'aa123456'
        }

        return password.lower() in common_passwords


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()