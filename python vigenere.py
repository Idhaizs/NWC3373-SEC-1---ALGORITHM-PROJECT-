import tkinter as tk
from tkinter import messagebox, filedialog

# --- Vigenère Functions ---
def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()
    ciphertext = ""
    key_index = 0
    key_length = len(key)

    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % key_length]) - ord('A')
            encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            ciphertext += encrypted_char
            key_index += 1
        else:
            ciphertext += char
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()
    plaintext = ""
    key_index = 0
    key_length = len(key)

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % key_length]) - ord('A')
            decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            plaintext += decrypted_char
            key_index += 1
        else:
            plaintext += char
    return plaintext

# --- GUI Functions ---
def encrypt_action():
    text = entry_input.get()
    key = entry_key.get()
    if not key.isalpha():
        messagebox.showerror("Key Error", "Key must contain only letters (A–Z).")
        return
    result = vigenere_encrypt(text, key)
    text_output.config(state='normal')
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, f"Encrypted Ciphertext:\n{result}")
    text_output.config(state='disabled')

def decrypt_action():
    text = entry_input.get()
    key = entry_key.get()
    if not key.isalpha():
        messagebox.showerror("Key Error", "Key must contain only letters (A–Z).")
        return
    result = vigenere_decrypt(text, key)
    text_output.config(state='normal')
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, f"Decrypted Plaintext:\n{result}")
    text_output.config(state='disabled')

def clear_action():
    entry_input.delete(0, tk.END)
    entry_key.delete(0, tk.END)
    text_output.config(state='normal')
    text_output.delete(1.0, tk.END)
    text_output.config(state='disabled')

# --- GUI Setup ---
window = tk.Tk()
window.title("🔐 Vigenère Cipher")
window.geometry("600x500")
window.configure(bg="#1e1e2f")

# --- Fonts & Colors ---
TITLE_FONT = ("Segoe UI", 20, "bold")
LABEL_FONT = ("Segoe UI", 11)
ENTRY_FONT = ("Segoe UI", 11)
BUTTON_FONT = ("Segoe UI", 10)
TEXT_BG = "#ffffff"
TEXT_FG = "#000000"
BTN_COLOR = "#007acc"
BTN_TEXT_COLOR = "#ffffff"

# --- Title ---
tk.Label(window, text="Vigenère Cipher Encryption Tool", bg="#1e1e2f",
         fg="#ffffff", font=TITLE_FONT).pack(pady=20)

# --- Input Text ---
tk.Label(window, text="Enter Text (Plaintext or Ciphertext):", bg="#1e1e2f",
         fg="#ffffff", font=LABEL_FONT).pack()
entry_input = tk.Entry(window, width=60, font=ENTRY_FONT)
entry_input.pack(pady=8)

# --- Key Input ---
tk.Label(window, text="Enter Key (letters only):", bg="#1e1e2f",
         fg="#ffffff", font=LABEL_FONT).pack()
entry_key = tk.Entry(window, width=60, font=ENTRY_FONT)
entry_key.pack(pady=8)

# --- Buttons ---
btn_frame = tk.Frame(window, bg="#1e1e2f")
btn_frame.pack(pady=15)

def style_button(btn):
    btn.configure(
        bg=BTN_COLOR,
        fg=BTN_TEXT_COLOR,
        font=BUTTON_FONT,
        activebackground="#005f99",
        activeforeground="#ffffff",
        relief=tk.FLAT,
        padx=10,
        pady=5,
        width=12
    )

btn_encrypt = tk.Button(btn_frame, text="Encrypt", command=encrypt_action)
style_button(btn_encrypt)
btn_encrypt.grid(row=0, column=0, padx=5)

btn_decrypt = tk.Button(btn_frame, text="Decrypt", command=decrypt_action)
style_button(btn_decrypt)
btn_decrypt.grid(row=0, column=1, padx=5)

btn_clear = tk.Button(btn_frame, text="Clear", command=clear_action)
style_button(btn_clear)
btn_clear.grid(row=0, column=2, padx=5)

# --- Output Box ---
tk.Label(window, text="Output:", bg="#1e1e2f", fg="#ffffff", font=LABEL_FONT).pack()
text_output = tk.Text(window, height=6, width=60, font=("Courier New", 11),
                      bg=TEXT_BG, fg=TEXT_FG, state='disabled')
text_output.pack(pady=10)

# --- Run ---
window.mainloop()
