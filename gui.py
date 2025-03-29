import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import subprocess
import sys
import threading
import tempfile
import base64

class ObfuscationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Obfuscation & Steganography Toolkit")
        self.root.geometry("800x700")
        self.root.resizable(True, True)
        
        # Create main notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.obfuscate_tab = ttk.Frame(self.notebook)
        self.deobfuscate_tab = ttk.Frame(self.notebook)
        self.text_obfuscate_tab = ttk.Frame(self.notebook)
        self.text_deobfuscate_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.obfuscate_tab, text="Obfuscate File")
        self.notebook.add(self.deobfuscate_tab, text="Deobfuscate File")
        self.notebook.add(self.text_obfuscate_tab, text="Obfuscate Text")
        self.notebook.add(self.text_deobfuscate_tab, text="Deobfuscate Text")
        
        # Setup all tabs
        self.setup_obfuscate_tab()
        self.setup_deobfuscate_tab()
        self.setup_text_obfuscate_tab()
        self.setup_text_deobfuscate_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Output console
        self.console_frame = ttk.LabelFrame(root, text="Output Console")
        self.console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.console = tk.Text(self.console_frame, height=8, wrap=tk.WORD, bg='black', fg='green')
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbar for console
        console_scrollbar = ttk.Scrollbar(self.console, command=self.console.yview)
        console_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.console.config(yscrollcommand=console_scrollbar.set)
        
    def setup_obfuscate_tab(self):
        # File selection
        file_frame = ttk.LabelFrame(self.obfuscate_tab, text="Input File")
        file_frame.pack(fill=tk.X, padx=10, pady=10, ipady=5)
        
        self.obf_file_var = tk.StringVar()
        ttk.Label(file_frame, text="File:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(file_frame, textvariable=self.obf_file_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=lambda: self.browse_file(self.obf_file_var)).grid(row=0, column=2, padx=5, pady=5)
        
        # Binary option
        self.obf_binary_var = tk.BooleanVar()
        ttk.Checkbutton(file_frame, text="Process as binary", variable=self.obf_binary_var).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Methods
        methods_frame = ttk.LabelFrame(self.obfuscate_tab, text="Obfuscation Methods")
        methods_frame.pack(fill=tk.X, padx=10, pady=10, ipady=5)
        
        # Method checkboxes
        self.obf_base64_var = tk.BooleanVar()
        self.obf_xor_var = tk.BooleanVar()
        self.obf_steg_image_var = tk.BooleanVar()
        self.obf_whitespace_var = tk.BooleanVar()
        
        ttk.Checkbutton(methods_frame, text="Base64", variable=self.obf_base64_var).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(methods_frame, text="XOR", variable=self.obf_xor_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(methods_frame, text="Image Steganography", variable=self.obf_steg_image_var).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(methods_frame, text="Whitespace", variable=self.obf_whitespace_var).grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        
        # XOR key
        xor_frame = ttk.Frame(methods_frame)
        xor_frame.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(xor_frame, text="XOR Key:").pack(side=tk.LEFT, padx=5)
        self.obf_xor_key_var = tk.StringVar()
        ttk.Entry(xor_frame, textvariable=self.obf_xor_key_var, width=30).pack(side=tk.LEFT, padx=5)
        
        # Image steganography options
        steg_frame = ttk.LabelFrame(self.obfuscate_tab, text="Image Steganography Options")
        steg_frame.pack(fill=tk.X, padx=10, pady=10, ipady=5)
        
        ttk.Label(steg_frame, text="Input Image:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.obf_image_var = tk.StringVar()
        ttk.Entry(steg_frame, textvariable=self.obf_image_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(steg_frame, text="Browse", command=lambda: self.browse_file(self.obf_image_var, [("Image files", "*.png;*.jpg;*.jpeg;*.bmp")])).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(steg_frame, text="Output Image:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.obf_output_var = tk.StringVar()
        ttk.Entry(steg_frame, textvariable=self.obf_output_var, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(steg_frame, text="Browse", command=lambda: self.save_file(self.obf_output_var, [("PNG files", "*.png")])).grid(row=1, column=2, padx=5, pady=5)
        
        # Execute button
        ttk.Button(self.obfuscate_tab, text="Obfuscate", command=self.run_obfuscation).pack(pady=10)
        
    def setup_deobfuscate_tab(self):
        # File selection
        file_frame = ttk.LabelFrame(self.deobfuscate_tab, text="Input File")
        file_frame.pack(fill=tk.X, padx=10, pady=10, ipady=5)
        
        self.deobf_file_var = tk.StringVar()
        ttk.Label(file_frame, text="File:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(file_frame, textvariable=self.deobf_file_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=lambda: self.browse_file(self.deobf_file_var)).grid(row=0, column=2, padx=5, pady=5)
        
        # Binary option
        self.deobf_binary_var = tk.BooleanVar()
        ttk.Checkbutton(file_frame, text="Process as binary", variable=self.deobf_binary_var).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Methods
        methods_frame = ttk.LabelFrame(self.deobfuscate_tab, text="Deobfuscation Methods (in reverse order)")
        methods_frame.pack(fill=tk.X, padx=10, pady=10, ipady=5)
        
        # Method checkboxes
        self.deobf_base64_var = tk.BooleanVar()
        self.deobf_xor_var = tk.BooleanVar()
        self.deobf_steg_image_var = tk.BooleanVar()
        self.deobf_whitespace_var = tk.BooleanVar()
        
        ttk.Checkbutton(methods_frame, text="Base64", variable=self.deobf_base64_var).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(methods_frame, text="XOR", variable=self.deobf_xor_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(methods_frame, text="Image Steganography", variable=self.deobf_steg_image_var).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(methods_frame, text="Whitespace", variable=self.deobf_whitespace_var).grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        
        # XOR key
        xor_frame = ttk.Frame(methods_frame)
        xor_frame.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(xor_frame, text="XOR Key:").pack(side=tk.LEFT, padx=5)
        self.deobf_xor_key_var = tk.StringVar()
        ttk.Entry(xor_frame, textvariable=self.deobf_xor_key_var, width=30).pack(side=tk.LEFT, padx=5)
        
        # Image steganography options
        steg_frame = ttk.LabelFrame(self.deobfuscate_tab, text="Image Steganography Options")
        steg_frame.pack(fill=tk.X, padx=10, pady=10, ipady=5)
        
        ttk.Label(steg_frame, text="Steganography Image:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.deobf_image_var = tk.StringVar()
        ttk.Entry(steg_frame, textvariable=self.deobf_image_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(steg_frame, text="Browse", command=lambda: self.browse_file(self.deobf_image_var, [("Image files", "*.png;*.jpg;*.jpeg;*.bmp")])).grid(row=0, column=2, padx=5, pady=5)
        
        # Execute button
        ttk.Button(self.deobfuscate_tab, text="Deobfuscate", command=self.run_deobfuscation).pack(pady=10)
    
    def setup_text_obfuscate_tab(self):
        # Main layout with split panes
        paned = ttk.PanedWindow(self.text_obfuscate_tab, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Input frame
        input_frame = ttk.LabelFrame(paned, text="Input Text")
        paned.add(input_frame, weight=1)
        
        self.obf_text_input = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=10)
        self.obf_text_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Options frame
        options_frame = ttk.Frame(paned)
        paned.add(options_frame, weight=0)
        
        # Methods
        methods_frame = ttk.LabelFrame(options_frame, text="Obfuscation Methods")
        methods_frame.pack(fill=tk.X, padx=5, pady=5, ipady=5)
        
        # Method checkboxes
        self.text_obf_base64_var = tk.BooleanVar()
        self.text_obf_xor_var = tk.BooleanVar()
        self.text_obf_whitespace_var = tk.BooleanVar()
        
        ttk.Checkbutton(methods_frame, text="Base64", variable=self.text_obf_base64_var).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(methods_frame, text="XOR", variable=self.text_obf_xor_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(methods_frame, text="Whitespace", variable=self.text_obf_whitespace_var).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        
        # XOR key
        xor_frame = ttk.Frame(methods_frame)
        xor_frame.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(xor_frame, text="XOR Key:").pack(side=tk.LEFT, padx=5)
        self.text_obf_xor_key_var = tk.StringVar()
        ttk.Entry(xor_frame, textvariable=self.text_obf_xor_key_var, width=30).pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(options_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Obfuscate Text", command=self.run_text_obfuscation).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=lambda: self.obf_text_input.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy Output", command=lambda: self.copy_to_clipboard(self.obf_text_output.get(1.0, tk.END))).pack(side=tk.RIGHT, padx=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(paned, text="Output Text")
        paned.add(output_frame, weight=1)
        
        self.obf_text_output = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=10)
        self.obf_text_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_text_deobfuscate_tab(self):
        # Main layout with split panes
        paned = ttk.PanedWindow(self.text_deobfuscate_tab, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Input frame
        input_frame = ttk.LabelFrame(paned, text="Input Text")
        paned.add(input_frame, weight=1)
        
        self.deobf_text_input = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=10)
        self.deobf_text_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Options frame
        options_frame = ttk.Frame(paned)
        paned.add(options_frame, weight=0)
        
        # Methods
        methods_frame = ttk.LabelFrame(options_frame, text="Deobfuscation Methods (in reverse order)")
        methods_frame.pack(fill=tk.X, padx=5, pady=5, ipady=5)
        
        # Method checkboxes
        self.text_deobf_base64_var = tk.BooleanVar()
        self.text_deobf_xor_var = tk.BooleanVar()
        self.text_deobf_whitespace_var = tk.BooleanVar()
        
        ttk.Checkbutton(methods_frame, text="Base64", variable=self.text_deobf_base64_var).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(methods_frame, text="XOR", variable=self.text_deobf_xor_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Checkbutton(methods_frame, text="Whitespace", variable=self.text_deobf_whitespace_var).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        
        # XOR key
        xor_frame = ttk.Frame(methods_frame)
        xor_frame.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(xor_frame, text="XOR Key:").pack(side=tk.LEFT, padx=5)
        self.text_deobf_xor_key_var = tk.StringVar()
        ttk.Entry(xor_frame, textvariable=self.text_deobf_xor_key_var, width=30).pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(options_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Deobfuscate Text", command=self.run_text_deobfuscation).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=lambda: self.deobf_text_input.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy Output", command=lambda: self.copy_to_clipboard(self.deobf_text_output.get(1.0, tk.END))).pack(side=tk.RIGHT, padx=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(paned, text="Output Text")
        paned.add(output_frame, weight=1)
        
        self.deobf_text_output = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=10)
        self.deobf_text_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def browse_file(self, var, filetypes=None):
        if filetypes is None:
            filetypes = [("All files", "*.*")]
        filename = filedialog.askopenfilename(filetypes=filetypes)
        if filename:
            var.set(filename)
    
    def save_file(self, var, filetypes=None):
        if filetypes is None:
            filetypes = [("All files", "*.*")]
        filename = filedialog.asksaveasfilename(filetypes=filetypes)
        if filename:
            var.set(filename)
    
    def log_to_console(self, message):
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)
    
    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("Copied to clipboard")
    
    def run_obfuscation(self):
        # Validate inputs
        if not self.obf_file_var.get():
            messagebox.showerror("Error", "Please select an input file.")
            return
        
        # Determine methods
        methods = []
        if self.obf_base64_var.get():
            methods.append("base64")
        if self.obf_xor_var.get():
            methods.append("xor")
            if not self.obf_xor_key_var.get():
                messagebox.showerror("Error", "XOR key is required when using XOR method.")
                return
        if self.obf_steg_image_var.get():
            methods.append("steg-image")
            if not self.obf_image_var.get() or not self.obf_output_var.get():
                messagebox.showerror("Error", "Input and output images are required for image steganography.")
                return
        if self.obf_whitespace_var.get():
            methods.append("whitespace")
        
        if not methods:
            messagebox.showerror("Error", "Please select at least one obfuscation method.")
            return
        
        # Build command
        cmd = ["python", "main.py", "obfuscate", self.obf_file_var.get(), "--methods", ",".join(methods)]
        
        if self.obf_binary_var.get():
            cmd.append("--binary")
        
        if "steg-image" in methods:
            cmd.extend(["--image", self.obf_image_var.get(), "--output", self.obf_output_var.get()])
        
        if "xor" in methods:
            cmd.extend(["--key", self.obf_xor_key_var.get()])
        
        # Execute command in a thread
        self.status_var.set("Obfuscating...")
        self.log_to_console("Running command: " + " ".join(cmd))
        threading.Thread(target=self.execute_command, args=(cmd,)).start()
    
    def run_deobfuscation(self):
        # Validate inputs
        if not self.deobf_file_var.get():
            messagebox.showerror("Error", "Please select an input file.")
            return
        
        # Determine methods
        methods = []
        if self.deobf_base64_var.get():
            methods.append("base64")
        if self.deobf_xor_var.get():
            methods.append("xor")
            if not self.deobf_xor_key_var.get():
                messagebox.showerror("Error", "XOR key is required when using XOR method.")
                return
        if self.deobf_steg_image_var.get():
            methods.append("steg-image")
            if not self.deobf_image_var.get():
                messagebox.showerror("Error", "Input image is required for image steganography.")
                return
        if self.deobf_whitespace_var.get():
            methods.append("whitespace")
        
        if not methods:
            messagebox.showerror("Error", "Please select at least one deobfuscation method.")
            return
        
        # Build command
        cmd = ["python", "main.py", "deobfuscate", self.deobf_file_var.get(), "--methods", ",".join(methods)]
        
        if self.deobf_binary_var.get():
            cmd.append("--binary")
        
        if "steg-image" in methods:
            cmd.extend(["--image", self.deobf_image_var.get()])
        
        if "xor" in methods:
            cmd.extend(["--key", self.deobf_xor_key_var.get()])
        
        # Execute command in a thread
        self.status_var.set("Deobfuscating...")
        self.log_to_console("Running command: " + " ".join(cmd))
        threading.Thread(target=self.execute_command, args=(cmd,)).start()
    
    def run_text_obfuscation(self):
        # Get input text
        input_text = self.obf_text_input.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showerror("Error", "Please enter some text to obfuscate.")
            return
        
        # Determine methods
        methods = []
        if self.text_obf_base64_var.get():
            methods.append("base64")
        if self.text_obf_xor_var.get():
            methods.append("xor")
            if not self.text_obf_xor_key_var.get():
                messagebox.showerror("Error", "XOR key is required when using XOR method.")
                return
        if self.text_obf_whitespace_var.get():
            methods.append("whitespace")
        
        if not methods:
            messagebox.showerror("Error", "Please select at least one obfuscation method.")
            return
        
        # Clear output
        self.obf_text_output.delete("1.0", tk.END)
        
        # Process directly
        try:
            result = input_text
            for method in methods:
                if method == "base64":
                    result = base64.b64encode(result.encode()).decode()
                elif method == "xor":
                    key = self.text_obf_xor_key_var.get()
                    result = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(result))
                elif method == "whitespace":
                    binary_message = ''.join(format(ord(c), '08b') for c in result)
                    result = binary_message.replace('0', '\u200B').replace('1', '\u200C')
            
            self.obf_text_output.insert("1.0", result)
            self.status_var.set("Text obfuscated successfully")
            self.log_to_console("[SUCCESS] Text obfuscated successfully")
            
        except Exception as e:
            self.status_var.set("Error obfuscating text")
            self.log_to_console("[ERROR] " + str(e))
            messagebox.showerror("Error", str(e))
    
    def run_text_deobfuscation(self):
        # Get input text
        input_text = self.deobf_text_input.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showerror("Error", "Please enter some text to deobfuscate.")
            return
        
        # Determine methods
        methods = []
        if self.text_deobf_base64_var.get():
            methods.append("base64")
        if self.text_deobf_xor_var.get():
            methods.append("xor")
            if not self.text_deobf_xor_key_var.get():
                messagebox.showerror("Error", "XOR key is required when using XOR method.")
                return
        if self.text_deobf_whitespace_var.get():
            methods.append("whitespace")
        
        if not methods:
            messagebox.showerror("Error", "Please select at least one deobfuscation method.")
            return
        
        # Clear output
        self.deobf_text_output.delete("1.0", tk.END)
        
        # Process directly
        try:
            result = input_text
            for method in reversed(methods):
                if method == "base64":
                    try:
                        result = base64.b64decode(result.encode()).decode()
                    except Exception as e:
                        raise Exception(f"Base64 decoding failed: {e}")
                elif method == "xor":
                    key = self.text_deobf_xor_key_var.get()
                    result = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(result))
                elif method == "whitespace":
                    binary_message = result.replace('\u200B', '0').replace('\u200C', '1')
                    bytes_list = [binary_message[i:i+8] for i in range(0, len(binary_message), 8) if i+8 <= len(binary_message)]
                    try:
                        result = "".join(chr(int(byte, 2)) for byte in bytes_list)
                    except Exception as e:
                        raise Exception(f"Whitespace decoding failed: {e}")
            
            self.deobf_text_output.insert("1.0", result)
            self.status_var.set("Text deobfuscated successfully")
            self.log_to_console("[SUCCESS] Text deobfuscated successfully")
            
        except Exception as e:
            self.status_var.set("Error deobfuscating text")
            self.log_to_console("[ERROR] " + str(e))
            messagebox.showerror("Error", str(e))
    
    def execute_command(self, cmd):
        try:
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            if stdout:
                self.log_to_console(stdout)
            
            if stderr:
                self.log_to_console("ERROR: " + stderr)
            
            if process.returncode == 0:
                self.status_var.set("Operation completed successfully")
                messagebox.showinfo("Success", "Operation completed successfully")
            else:
                self.status_var.set("Operation failed with exit code " + str(process.returncode))
                messagebox.showerror("Error", "Operation failed with exit code " + str(process.returncode))
    
        except Exception as e:
            self.log_to_console("Exception: " + str(e))
            self.status_var.set("Operation failed with exception")
            messagebox.showerror("Error", str(e))
   
if __name__ == "__main__":
    root = tk.Tk()
    app = ObfuscationApp(root)
    root.mainloop()