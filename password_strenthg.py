import tkinter as tk
from tkinter import ttk
import re
import hashlib
import string
import secrets
import math

# Constants for brute force calculation
GUESSES_PER_SECOND = {
    "Regular PC": 1_000_000,  # 1 million/second
    "High-End PC": 100_000_000,  # 100 million/second
    "Supercomputer": 1_000_000_000_000  # 1 trillion/second
}

class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Security Analyzer")
        self.root.geometry("800x900")  # Increased size for better layout
        
        # Configure modern dark theme
        self.root.configure(bg='#0d1117')  # GitHub dark theme color
        style = ttk.Style()
        
        # Enhanced modern styling
        style.configure('Custom.TFrame', background='#0d1117')
        style.configure('Custom.TLabel',
                       background='#0d1117',
                       foreground='#58a6ff',  # GitHub blue
                       font=('Segoe UI', 11))
        style.configure('Custom.TLabelframe',
                       background='#0d1117',
                       foreground='#58a6ff')
        style.configure('Custom.TLabelframe.Label',
                       background='#0d1117',
                       foreground='#58a6ff',
                       font=('Segoe UI', 12, 'bold'))
        
        # Main container with padding
        self.main_frame = ttk.Frame(root, padding="30", style='Custom.TFrame')
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.main_frame.columnconfigure(0, weight=1)
        
        # Title with modern effect
        self.title_label = tk.Label(self.main_frame,
                                   text="Password Security Analyzer",
                                   font=('Segoe UI', 28, 'bold'),
                                   fg='#58a6ff',
                                   bg='#0d1117')
        self.title_label.grid(row=0, column=0, pady=25, sticky='ew')
        
        # Subtitle
        self.subtitle_label = tk.Label(self.main_frame,
                                     text="Analyze and generate secure passwords",
                                     font=('Segoe UI', 12),
                                     fg='#8b949e',  # GitHub secondary text
                                     bg='#0d1117')
        self.subtitle_label.grid(row=1, column=0, pady=(0, 30))

        # Create a frame for input section
        input_frame = ttk.Frame(self.main_frame, style='Custom.TFrame')
        input_frame.grid(row=2, column=0, sticky='ew', pady=10)
        input_frame.columnconfigure(1, weight=1)

        # Password entry with improved layout
        ttk.Label(input_frame, 
                 text="Enter Password:",
                 style='Custom.TLabel').grid(row=0, column=0, padx=(0, 10), sticky='w')
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(input_frame,
                                      textvariable=self.password_var,
                                      show="•",
                                      width=50)
        self.password_entry.grid(row=0, column=1, sticky='ew')

        # Control buttons frame
        button_frame = ttk.Frame(self.main_frame, style='Custom.TFrame')
        button_frame.grid(row=3, column=0, pady=20)

        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(button_frame,
                        text="Show Password",
                        variable=self.show_password_var,
                        command=self.toggle_password_visibility,
                        style='Custom.TCheckbutton').pack(side=tk.LEFT, padx=5)

        # Analysis button with improved styling
        self.analyze_btn = tk.Button(button_frame,
                                   text="Analyze Security",
                                   command=self.check_password,
                                   bg='#238636',  # GitHub green
                                   fg='white',
                                   font=('Segoe UI', 11),
                                   relief='flat',
                                   padx=20,
                                   pady=8,
                                   cursor='hand2')
        self.analyze_btn.pack(side=tk.LEFT, padx=5)

        # Generate button
        self.generate_btn = tk.Button(button_frame,
                                    text="Generate Strong Password",
                                    command=self.generate_secure_password,
                                    bg='#2ea043',  # Slightly lighter green
                                    fg='white',
                                    font=('Segoe UI', 11),
                                    relief='flat',
                                    padx=20,
                                    pady=8,
                                    cursor='hand2')
        self.generate_btn.pack(side=tk.LEFT, padx=5)

        # Results area with improved styling
        self.result_frame = ttk.LabelFrame(self.main_frame,
                                         text=" Security Analysis ",
                                         padding="20",
                                         style='Custom.TLabelframe')
        self.result_frame.grid(row=4, column=0, pady=20, sticky='ew')

        # Strength meter with prominent display
        self.strength_label = ttk.Label(self.main_frame,
                                      text="Security Level: Not Analyzed",
                                      style='Custom.TLabel',
                                      font=('Segoe UI', 14, 'bold'))
        self.strength_label.grid(row=5, column=0, pady=15)

        # Hash display with monospace font
        self.hash_label = ttk.Label(self.main_frame,
                                   text="SHA-256: Not calculated",
                                   style='Custom.TLabel',
                                   font=('Consolas', 10),
                                   wraplength=700)
        self.hash_label.grid(row=6, column=0, pady=10)

    def calculate_entropy(self, password):
        char_set = 0
        if any(c.isupper() for c in password): char_set += 26
        if any(c.islower() for c in password): char_set += 26
        if any(c.isdigit() for c in password): char_set += 10
        if any(c in string.punctuation for c in password): char_set += 32
        
        entropy = len(password) * (char_set.bit_length() if char_set else 0)
        return entropy

    def calculate_crack_time(self, password):
        char_set_size = 0
        if any(c.isupper() for c in password): char_set_size += 26
        if any(c.islower() for c in password): char_set_size += 26
        if any(c.isdigit() for c in password): char_set_size += 10
        if any(c in string.punctuation for c in password): char_set_size += 32
        
        possible_combinations = char_set_size ** len(password)
        
        crack_times = {}
        for device, speed in GUESSES_PER_SECOND.items():
            seconds = possible_combinations / speed
            
            # Convert to human-readable format
            if seconds < 60:
                crack_times[device] = f"{seconds:.2f} seconds"
            elif seconds < 3600:
                crack_times[device] = f"{seconds/60:.2f} minutes"
            elif seconds < 86400:
                crack_times[device] = f"{seconds/3600:.2f} hours"
            elif seconds < 31536000:
                crack_times[device] = f"{seconds/86400:.2f} days"
            elif seconds < 315360000:
                crack_times[device] = f"{seconds/31536000:.2f} years"
            else:
                crack_times[device] = "centuries"
                
        return crack_times

    def check_password(self):
        password = self.password_var.get()
        
        # Clear previous results
        for widget in self.result_frame.winfo_children():
            widget.destroy()
        
        # Security checks
        checks = {
            "length": len(password) >= 12,
            "uppercase": bool(re.search(r'[A-Z]', password)),
            "lowercase": bool(re.search(r'[a-z]', password)),
            "numbers": bool(re.search(r'\d', password)),
            "special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        
        # Display strength criteria
        row = 0
        for criterion, passed in checks.items():
            icon = "✓" if passed else "✗"
            color = "#238636" if passed else "#f85149"  # GitHub colors
            label = ttk.Label(self.result_frame,
                             text=f"{icon} {criterion.title()}",
                             style='Custom.TLabel',
                             font=('Segoe UI', 11))
            label.grid(row=row, column=0, sticky=tk.W, pady=4)
            row += 1
        
        # Add separator
        ttk.Separator(self.result_frame, orient='horizontal').grid(
            row=row, column=0, sticky='ew', pady=10)
        row += 1
        
        # Enhanced entropy display
        entropy = self.calculate_entropy(password)
        ttk.Label(self.result_frame,
                 text=f"Password Entropy: {entropy} bits",
                 style='Custom.TLabel',
                 font=('Segoe UI', 11, 'bold')).grid(
            row=row, column=0, sticky=tk.W, pady=4)
        row += 1
        
        # Enhanced crack time display
        crack_times = self.calculate_crack_time(password)
        ttk.Label(self.result_frame,
                 text="Estimated Time to Crack:",
                 style='Custom.TLabel',
                 font=('Segoe UI', 11, 'bold')).grid(
            row=row, column=0, sticky=tk.W, pady=(10, 4))
        row += 1
        
        for device, time in crack_times.items():
            ttk.Label(self.result_frame,
                     text=f"• {device}: {time}",
                     style='Custom.TLabel',
                     font=('Segoe UI', 11)).grid(
                row=row, column=0, sticky=tk.W, pady=2)
            row += 1
        
        # Calculate overall strength
        strength_score = sum(checks.values())
        entropy_bonus = 1 if entropy > 60 else 0
        final_score = strength_score + entropy_bonus
        
        strength_levels = {
            (0, 2): ("Critical", "#FF0000"),
            (3, 3): ("Weak", "#FF6600"),
            (4, 4): ("Moderate", "#FFCC00"),
            (5, 5): ("Strong", "#33FF33"),
            (6, 6): ("Maximum", "#00FF00")
        }
        
        for (min_score, max_score), (level, color) in strength_levels.items():
            if min_score <= final_score <= max_score:
                self.strength_label.config(
                    text=f"Password Strength: {level}",
                    foreground=color)
                break

    def toggle_password_visibility(self):
        self.password_entry.config(
            show="" if self.show_password_var.get() else "•")

    def generate_secure_password(self):
        # Generate a cryptographically secure password
        length = 16
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        self.password_var.set(password)
        self.check_password()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()