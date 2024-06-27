import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from hashlib import sha256

def modinv(a, m):
    m0 = m
    x0, x1 = 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_keys():
    p = 11
    q = 13
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    d = modinv(e, phi)
    return ((e, n), (d, n))

def sign_message(message, private_key):
    d, n = private_key
    message_hash = int.from_bytes(sha256(message.encode()).digest(), byteorder='big') % n
    signature = pow(message_hash, d, n)
    return signature

def verify_signature(message, signature, public_key):
    e, n = public_key
    message_hash = int.from_bytes(sha256(message.encode()).digest(), byteorder='big') % n
    hash_from_signature = pow(signature, e, n)
    return message_hash == hash_from_signature

def sign_file():
    private_key = generate_keys()[1]
    file_path = filedialog.askopenfilename(title="Select a text file to sign", filetypes=(("Text files", "*.txt"),))
    if file_path:
        with open(file_path, 'r') as file:
            message = file.read()
        signature = sign_message(message, private_key)
        signed_message = message + "\n---Signature: " + str(signature)
        with open("signed.txt", 'w') as signed_file:
            signed_file.write(signed_message)
        messagebox.showinfo("Success", "File signed successfully and saved as signed.txt")

def verify_file():
    public_key = generate_keys()[0]
    file_path = filedialog.askopenfilename(title="Select a signed text file", filetypes=(("Text files", "*.txt"),))
    if file_path:
        with open(file_path, 'r') as file:
            content = file.read()
        message, signature = content.rsplit("\n---Signature: ", 1)
        signature = int(signature)
        if verify_signature(message, signature, public_key):
            messagebox.showinfo("Verification", "Signature is valid. Message: " + message)
        else:
            messagebox.showwarning("Verification", "Signature is invalid or the message is corrupt.")


root = tk.Tk()
root.title("Digital Signature Application")

root.geometry("600x400")


root.update_idletasks()
width = root.winfo_width()
height = root.winfo_height()
x = (root.winfo_screenwidth() // 2) - (width // 2)
y = (root.winfo_screenheight() // 2) - (height // 2)
root.geometry('{}x{}+{}+{}'.format(width, height, x, y))


style = ttk.Style()
style.configure("TButton", font=("Helvetica", 14), padding=10)
style.configure("TLabel", font=("Helvetica", 16))

# Frame
frame = ttk.Frame(root, padding="20 20 20 20")
frame.pack(expand=True)

# Title
title_label = ttk.Label(frame, text="Digital Signature Application", style="TLabel")
title_label.grid(row=0, column=0, columnspan=2, pady=20)

# Description
description_label = ttk.Label(frame, text="Sign and Verify Text Files", style="TLabel")
description_label.grid(row=1, column=0, columnspan=2, pady=10)

# Buttons
sign_button = ttk.Button(frame, text="Sign a Message", command=sign_file)
sign_button.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

verify_button = ttk.Button(frame, text="Verify a Message", command=verify_file)
verify_button.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

# Make the buttons fill the space
frame.columnconfigure(0, weight=1)
frame.columnconfigure(1, weight=1)

root.mainloop()
