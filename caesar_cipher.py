import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import string

class CaesarCipherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Caesar Cipher - Encryption & Decryption Tool")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')
        
        # Configure style
        self.setup_styles()
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Caesar Cipher Tool", 
                               style="Title.TLabel")
        title_label.pack(pady=(0, 20))
        
        # Input section
        self.create_input_section(main_frame)
        
        # Controls section
        self.create_controls_section(main_frame)
        
        # Output section
        self.create_output_section(main_frame)
        
        # Information section
        self.create_info_section(main_frame)
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure("Title.TLabel", font=("Arial", 18, "bold"), 
                       foreground="#ecf0f1", background="#2c3e50")
        style.configure("Heading.TLabel", font=("Arial", 12, "bold"), 
                       foreground="#3498db", background="#34495e")
        style.configure("TLabel", foreground="#ecf0f1", background="#34495e")
        style.configure("TFrame", background="#34495e")
        style.configure("TButton", font=("Arial", 10, "bold"))
        style.map("TButton",
                 background=[('active', '#3498db'), ('!active', '#2980b9')],
                 foreground=[('active', 'white'), ('!active', 'white')])
    
    def create_input_section(self, parent):
        input_frame = ttk.LabelFrame(parent, text="Input", padding="15")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Message input
        ttk.Label(input_frame, text="Enter your message:", 
                 style="Heading.TLabel").pack(anchor=tk.W, pady=(0, 5))
        
        self.input_text = scrolledtext.ScrolledText(input_frame, height=6, 
                                                   font=("Consolas", 11),
                                                   bg="#ecf0f1", fg="#2c3e50",
                                                   insertbackground="#2c3e50")
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Shift value input
        shift_frame = ttk.Frame(input_frame)
        shift_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(shift_frame, text="Shift Value:", 
                 style="Heading.TLabel").pack(side=tk.LEFT)
        
        self.shift_var = tk.StringVar(value="3")
        shift_spinbox = ttk.Spinbox(shift_frame, from_=-25, to=25, width=10,
                                   textvariable=self.shift_var, font=("Arial", 11))
        shift_spinbox.pack(side=tk.LEFT, padx=(10, 0))
        
        # Info label
        info_label = ttk.Label(shift_frame, 
                              text="(Range: -25 to 25, Negative values for reverse shift)",
                              font=("Arial", 9), foreground="#95a5a6")
        info_label.pack(side=tk.LEFT, padx=(10, 0))
    
    def create_controls_section(self, parent):
        controls_frame = ttk.Frame(parent)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Buttons
        encrypt_btn = ttk.Button(controls_frame, text="🔒 Encrypt", 
                                command=self.encrypt_text, width=15)
        encrypt_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        decrypt_btn = ttk.Button(controls_frame, text="🔓 Decrypt", 
                                command=self.decrypt_text, width=15)
        decrypt_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        clear_btn = ttk.Button(controls_frame, text="🗑️ Clear All", 
                              command=self.clear_all, width=15)
        clear_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Options
        options_frame = ttk.Frame(controls_frame)
        options_frame.pack(side=tk.RIGHT)
        
        self.preserve_case = tk.BooleanVar(value=True)
        case_check = ttk.Checkbutton(options_frame, text="Preserve Case",
                                    variable=self.preserve_case)
        case_check.pack(side=tk.LEFT, padx=(0, 10))
        
        self.preserve_spaces = tk.BooleanVar(value=True)
        space_check = ttk.Checkbutton(options_frame, text="Preserve Spaces & Punctuation",
                                     variable=self.preserve_spaces)
        space_check.pack(side=tk.LEFT)
    
    def create_output_section(self, parent):
        output_frame = ttk.LabelFrame(parent, text="Output", padding="15")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        ttk.Label(output_frame, text="Result:", 
                 style="Heading.TLabel").pack(anchor=tk.W, pady=(0, 5))
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=6,
                                                    font=("Consolas", 11), 
                                                    bg="#ecf0f1", fg="#2c3e50",
                                                    state=tk.DISABLED)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Copy button
        copy_btn = ttk.Button(output_frame, text="📋 Copy Result", 
                             command=self.copy_result)
        copy_btn.pack(anchor=tk.E)
    
    def create_info_section(self, parent):
        info_frame = ttk.LabelFrame(parent, text="Information", padding="10")
        info_frame.pack(fill=tk.X)
        
        info_text = ("Caesar Cipher shifts each letter by a fixed number of positions in the alphabet.\n"
                    "• Positive shift: A→D (shift=3), B→E, etc.\n"
                    "• Negative shift: D→A (shift=-3), E→B, etc.\n"
                    "• Decryption uses the opposite shift of encryption.")
        
        ttk.Label(info_frame, text=info_text, font=("Arial", 9),
                 foreground="#95a5a6", justify=tk.LEFT).pack(anchor=tk.W)
    
    def caesar_cipher(self, text, shift, decrypt=False):
        """Core Caesar cipher algorithm"""
        if decrypt:
            shift = -shift
        
        result = ""
        
        for char in text:
            if char.isalpha():
                # Determine if uppercase or lowercase
                is_upper = char.isupper()
                char = char.lower()
                
                # Shift the character
                shifted = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                
                # Preserve original case if option is selected
                if self.preserve_case.get() and is_upper:
                    shifted = shifted.upper()
                
                result += shifted
            else:
                # Preserve non-alphabetic characters if option is selected
                if self.preserve_spaces.get():
                    result += char
                # Otherwise skip non-alphabetic characters
        
        return result
    
    def encrypt_text(self):
        """Encrypt the input text"""
        try:
            message = self.input_text.get("1.0", tk.END).strip()
            if not message:
                messagebox.showwarning("Warning", "Please enter a message to encrypt.")
                return
            
            shift = int(self.shift_var.get())
            encrypted = self.caesar_cipher(message, shift)
            
            self.display_result(encrypted)
            messagebox.showinfo("Success", "Text encrypted successfully!")
            
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid shift value.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def decrypt_text(self):
        """Decrypt the input text"""
        try:
            message = self.input_text.get("1.0", tk.END).strip()
            if not message:
                messagebox.showwarning("Warning", "Please enter a message to decrypt.")
                return
            
            shift = int(self.shift_var.get())
            decrypted = self.caesar_cipher(message, shift, decrypt=True)
            
            self.display_result(decrypted)
            messagebox.showinfo("Success", "Text decrypted successfully!")
            
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid shift value.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def display_result(self, result):
        """Display result in output text widget"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", result)
        self.output_text.config(state=tk.DISABLED)
    
    def copy_result(self):
        """Copy result to clipboard"""
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Success", "Result copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No result to copy.")
    
    def clear_all(self):
        """Clear all text fields"""
        self.input_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.shift_var.set("3")

def main():
    root = tk.Tk()
    app = CaesarCipherGUI(root)
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()

if __name__ == "__main__":
    main()