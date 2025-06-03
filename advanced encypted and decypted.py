import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
import json


# --- Caesar Cipher Logic ---
def caesar_cipher(text, shift, mode):
    result = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift if mode == "Encrypt" else ord(char) - shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result


# --- Enhanced AES Helpers ---
def password_to_key(password, salt=None):
    """Derive a 32-byte key from password using PBKDF2"""
    if salt is None:
        salt = get_random_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key, salt


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# --- Advanced AES Image Encryption ---
def encrypt_image_file(image_path, password, mode='CBC'):
    """Encrypt entire image file with AES"""
    try:
        # Read the entire image file
        with open(image_path, 'rb') as f:
            file_data = f.read()

        # Generate key and salt
        key, salt = password_to_key(password)

        # Create cipher
        if mode == 'CBC':
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
        elif mode == 'GCM':
            cipher = AES.new(key, AES.MODE_GCM)
            encrypted_data, auth_tag = cipher.encrypt_and_digest(file_data)
            iv = cipher.nonce
        else:  # ECB mode (less secure, for compatibility)
            cipher = AES.new(key, AES.MODE_ECB)
            encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
            iv = None

        # Save encrypted file
        base_name = os.path.splitext(image_path)[0]
        enc_path = base_name + "_encrypted.aes"

        with open(enc_path, 'wb') as f:
            f.write(encrypted_data)

        # Save metadata
        metadata = {
            'salt': salt.hex(),
            'mode': mode,
            'password_hash': hash_password(password),
            'original_extension': os.path.splitext(image_path)[1]
        }

        if mode == 'CBC':
            metadata['iv'] = iv.hex()
        elif mode == 'GCM':
            metadata['nonce'] = iv.hex()
            metadata['auth_tag'] = auth_tag.hex()

        with open(enc_path + '.meta', 'w') as f:
            json.dump(metadata, f)

        return enc_path, "File encryption successful"

    except Exception as e:
        return None, f"File encryption failed: {str(e)}"


def decrypt_image_file(enc_path, password):
    """Decrypt AES encrypted image file"""
    try:
        # Load metadata
        with open(enc_path + '.meta', 'r') as f:
            metadata = json.load(f)

        # Verify password
        if hash_password(password) != metadata['password_hash']:
            return None, "Incorrect password"

        # Reconstruct key
        salt = bytes.fromhex(metadata['salt'])
        key, _ = password_to_key(password, salt)

        # Read encrypted data
        with open(enc_path, 'rb') as f:
            encrypted_data = f.read()

        # Decrypt based on mode
        mode = metadata['mode']
        if mode == 'CBC':
            iv = bytes.fromhex(metadata['iv'])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        elif mode == 'GCM':
            nonce = bytes.fromhex(metadata['nonce'])
            auth_tag = bytes.fromhex(metadata['auth_tag'])
            cipher = AES.new(key, AES.MODE_GCM, nonce)
            decrypted_data = cipher.decrypt_and_verify(encrypted_data, auth_tag)
        else:  # ECB
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        # Save decrypted file
        base_name = os.path.splitext(enc_path)[0]
        dec_path = base_name + "_decrypted" + metadata['original_extension']

        with open(dec_path, 'wb') as f:
            f.write(decrypted_data)

        return dec_path, "File decryption successful"

    except Exception as e:
        return None, f"File decryption failed: {str(e)}"


# --- Pixel-level AES Encryption (Visual Effect) ---
def encrypt_image_pixels(image_path, password):
    """Encrypt image pixels for visual scrambling effect"""
    try:
        img = Image.open(image_path).convert('RGB')
        pixel_bytes = img.tobytes()

        key, salt = password_to_key(password)
        cipher = AES.new(key, AES.MODE_ECB)

        # Pad to block size
        padded_pixels = pad(pixel_bytes, AES.block_size)
        encrypted_pixels = cipher.encrypt(padded_pixels)

        # Truncate to original length for image reconstruction
        encrypted_pixels = encrypted_pixels[:len(pixel_bytes)]

        # Create scrambled image
        encrypted_img = Image.frombytes('RGB', img.size, encrypted_pixels)
        enc_path = os.path.splitext(image_path)[0] + "_pixel_encrypted.jpg"
        encrypted_img.save(enc_path)

        # Save metadata
        metadata = {
            'salt': salt.hex(),
            'password_hash': hash_password(password),
            'mode': 'pixel_encryption'
        }

        with open(enc_path + '.meta', 'w') as f:
            json.dump(metadata, f)

        return enc_path, "Pixel encryption successful"

    except Exception as e:
        return None, f"Pixel encryption failed: {str(e)}"


def decrypt_image_pixels(enc_path, password):
    """Decrypt pixel-encrypted image"""
    try:
        # Load metadata
        with open(enc_path + '.meta', 'r') as f:
            metadata = json.load(f)

        # Verify password
        if hash_password(password) != metadata['password_hash']:
            return None, "Incorrect password"

        # Reconstruct key
        salt = bytes.fromhex(metadata['salt'])
        key, _ = password_to_key(password, salt)

        # Load and decrypt pixels
        img = Image.open(enc_path).convert('RGB')
        pixel_bytes = img.tobytes()

        cipher = AES.new(key, AES.MODE_ECB)
        padded_pixels = pad(pixel_bytes, AES.block_size)
        decrypted_pixels = cipher.decrypt(padded_pixels)
        decrypted_pixels = decrypted_pixels[:len(pixel_bytes)]

        # Reconstruct image
        decrypted_img = Image.frombytes('RGB', img.size, decrypted_pixels)
        dec_path = os.path.splitext(enc_path)[0] + "_decrypted.jpg"
        decrypted_img.save(dec_path)

        return dec_path, "Pixel decryption successful"

    except Exception as e:
        return None, f"Pixel decryption failed: {str(e)}"


# --- GUI Helper Functions ---
def display_image_in_label(image_path, label_widget, title=""):
    try:
        img = Image.open(image_path)
        img.thumbnail((200, 200))
        img_tk = ImageTk.PhotoImage(img)
        label_widget.config(image=img_tk, text="")
        label_widget.image = img_tk
        if title:
            label_widget.config(text=title, compound='top')
    except Exception as e:
        messagebox.showerror("Error", f"Could not display image: {e}")


def clear_image_displays():
    original_image_label.config(image="", text="No image selected")
    original_image_label.image = None
    encrypted_image_label.config(image="", text="Encrypted image will appear here")
    encrypted_image_label.image = None
    decrypted_image_label.config(image="", text="Decrypted image will appear here")
    decrypted_image_label.image = None


# --- Caesar Cipher GUI Logic ---
def process_text():
    text = entry_text.get("1.0", tk.END).strip()
    try:
        shift = int(entry_shift.get())
    except ValueError:
        messagebox.showerror("Error", "Shift must be an integer.")
        return
    mode = mode_var.get()
    result = caesar_cipher(text, shift, mode)
    entry_result.delete("1.0", tk.END)
    entry_result.insert(tk.END, result)


# --- Image Selection ---
def select_image():
    global selected_image_path
    selected_image_path = filedialog.askopenfilename(
        title="Select Image to Encrypt",
        filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp *.tiff")]
    )
    if selected_image_path:
        display_image_in_label(selected_image_path, original_image_label, "Original Image")
        # Clear other displays when new image is selected
        encrypted_image_label.config(image="", text="Encrypted image will appear here")
        decrypted_image_label.config(image="", text="Decrypted image will appear here")


# --- AES File Encryption ---
def encrypt_image_as_file():
    if not selected_image_path:
        messagebox.showerror("Error", "No image selected")
        return

    password = entry_key.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password")
        return

    mode = aes_mode_var.get()
    enc_path, message = encrypt_image_file(selected_image_path, password, mode)

    if enc_path:
        messagebox.showinfo("Success", f"{message}\nEncrypted file saved as:\n{enc_path}")
    else:
        messagebox.showerror("Error", message)


# --- AES Pixel Encryption ---
def encrypt_image_pixels_gui():
    if not selected_image_path:
        messagebox.showerror("Error", "No image selected")
        return

    password = entry_key.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password")
        return

    enc_path, message = encrypt_image_pixels(selected_image_path, password)

    if enc_path:
        messagebox.showinfo("Success", f"{message}\nScrambled image saved as:\n{enc_path}")
        display_image_in_label(enc_path, encrypted_image_label, "Encrypted Pixels")
    else:
        messagebox.showerror("Error", message)


# --- AES File Decryption ---
def decrypt_image_file_gui():
    enc_path = filedialog.askopenfilename(
        title="Select Encrypted File",
        filetypes=[("AES files", "*.aes"), ("All files", "*.*")]
    )
    if not enc_path:
        return

    password = simpledialog.askstring(
        "Password Required",
        "Enter the decryption password:",
        show="*"
    )
    if not password:
        return

    dec_path, message = decrypt_image_file(enc_path, password)

    if dec_path:
        messagebox.showinfo("Success", f"{message}\nDecrypted file saved as:\n{dec_path}")
        display_image_in_label(dec_path, decrypted_image_label, "Decrypted Image")
    else:
        messagebox.showerror("Error", message)


# --- AES Pixel Decryption ---
def decrypt_image_pixels_gui():
    enc_path = filedialog.askopenfilename(
        title="Select Pixel-Encrypted Image",
        filetypes=[("Image files", "*.jpg *.jpeg *.png")]
    )
    if not enc_path:
        return

    password = simpledialog.askstring(
        "Password Required",
        "Enter the decryption password:",
        show="*"
    )
    if not password:
        return

    dec_path, message = decrypt_image_pixels(enc_path, password)

    if dec_path:
        messagebox.showinfo("Success", f"{message}\nDecrypted image saved as:\n{dec_path}")
        display_image_in_label(dec_path, decrypted_image_label, "Decrypted Image")
    else:
        messagebox.showerror("Error", message)


# --- GUI Setup ---
window = tk.Tk()
window.title("Advanced Caesar Cipher + AES Image Encryptor")
window.geometry("900x1000")
window.configure(bg="#f0f0f0")
selected_image_path = ""

# --- Caesar Cipher UI ---
frame_text = tk.LabelFrame(window, text="Caesar Cipher", padx=10, pady=10)
frame_text.pack(padx=10, pady=5, fill="x")

label_text = tk.Label(frame_text, text="Enter text:")
label_text.pack(anchor="w")
entry_text = tk.Text(frame_text, height=3)
entry_text.pack(fill="x")

controls_frame = tk.Frame(frame_text)
controls_frame.pack(fill="x", pady=5)

label_shift = tk.Label(controls_frame, text="Shift:")
label_shift.pack(side="left")
entry_shift = tk.Entry(controls_frame, width=10)
entry_shift.pack(side="left", padx=5)

label_mode = tk.Label(controls_frame, text="Mode:")
label_mode.pack(side="left", padx=(10, 0))
mode_var = tk.StringVar(value="Encrypt")
mode_dropdown = ttk.Combobox(controls_frame, textvariable=mode_var, values=["Encrypt", "Decrypt"], width=10)
mode_dropdown.pack(side="left", padx=5)

button_process = tk.Button(controls_frame, text="Process", command=process_text, bg="#4CAF50", fg="white")
button_process.pack(side="left", padx=10)

label_result = tk.Label(frame_text, text="Result:")
label_result.pack(anchor="w", pady=(10, 0))
entry_result = tk.Text(frame_text, height=3)
entry_result.pack(fill="x")

# --- AES Image Encryption UI ---
frame_image = tk.LabelFrame(window, text="Advanced AES Image Encryption", padx=10, pady=10)
frame_image.pack(padx=10, pady=5, fill="both", expand=True)

# Image display section
image_display_frame = tk.Frame(frame_image)
image_display_frame.pack(fill="both", expand=True, pady=10)

# Original image
original_frame = tk.Frame(image_display_frame)
original_frame.pack(side="left", fill="both", expand=True, padx=2)
tk.Label(original_frame, text="Original Image", font=("Arial", 10, "bold")).pack()
original_image_label = tk.Label(original_frame, text="No image selected", bg="lightgray",
                                width=20, height=12, relief="sunken")
original_image_label.pack(pady=5)

# Encrypted image
encrypted_frame = tk.Frame(image_display_frame)
encrypted_frame.pack(side="left", fill="both", expand=True, padx=2)
tk.Label(encrypted_frame, text="Encrypted Image", font=("Arial", 10, "bold")).pack()
encrypted_image_label = tk.Label(encrypted_frame, text="Encrypted image will appear here",
                                 bg="lightgray", width=20, height=12, relief="sunken")
encrypted_image_label.pack(pady=5)

# Decrypted image
decrypted_frame = tk.Frame(image_display_frame)
decrypted_frame.pack(side="left", fill="both", expand=True, padx=2)
tk.Label(decrypted_frame, text="Decrypted Image", font=("Arial", 10, "bold")).pack()
decrypted_image_label = tk.Label(decrypted_frame, text="Decrypted image will appear here",
                                 bg="lightgray", width=20, height=12, relief="sunken")
decrypted_image_label.pack(pady=5)

# Controls section
controls_main_frame = tk.Frame(frame_image)
controls_main_frame.pack(fill="x", pady=10)

# File selection
btn_select_image = tk.Button(controls_main_frame, text="📁 Select Image", command=select_image,
                             font=("Arial", 10), padx=20)
btn_select_image.pack(pady=5)

# Password entry
password_frame = tk.Frame(controls_main_frame)
password_frame.pack(fill="x", pady=5)
tk.Label(password_frame, text="Password:", font=("Arial", 10, "bold")).pack(anchor="w")
entry_key = tk.Entry(password_frame, show="*", font=("Arial", 10))
entry_key.pack(fill="x", pady=2)

# AES Mode selection
mode_frame = tk.Frame(controls_main_frame)
mode_frame.pack(fill="x", pady=5)
tk.Label(mode_frame, text="AES Mode (for file encryption):", font=("Arial", 10, "bold")).pack(anchor="w")
aes_mode_var = tk.StringVar(value="CBC")
aes_mode_frame = tk.Frame(mode_frame)
aes_mode_frame.pack(fill="x")
tk.Radiobutton(aes_mode_frame, text="CBC (Recommended)", variable=aes_mode_var, value="CBC").pack(side="left")
tk.Radiobutton(aes_mode_frame, text="GCM (Authenticated)", variable=aes_mode_var, value="GCM").pack(side="left")
tk.Radiobutton(aes_mode_frame, text="ECB (Simple)", variable=aes_mode_var, value="ECB").pack(side="left")

# Encryption buttons
encrypt_frame = tk.LabelFrame(controls_main_frame, text="Encryption Options", padx=10, pady=5)
encrypt_frame.pack(fill="x", pady=10)

encrypt_buttons_frame = tk.Frame(encrypt_frame)
encrypt_buttons_frame.pack()

btn_encrypt_file = tk.Button(encrypt_buttons_frame, text="🔒 Encrypt as File",
                             command=encrypt_image_as_file, bg="#2196F3", fg="white",
                             font=("Arial", 9), padx=15)
btn_encrypt_file.pack(side="left", padx=5)

btn_encrypt_pixels = tk.Button(encrypt_buttons_frame, text="🎨 Scramble Pixels",
                               command=encrypt_image_pixels_gui, bg="#9C27B0", fg="white",
                               font=("Arial", 9), padx=15)
btn_encrypt_pixels.pack(side="left", padx=5)

# Decryption buttons
decrypt_frame = tk.LabelFrame(controls_main_frame, text="Decryption Options", padx=10, pady=5)
decrypt_frame.pack(fill="x", pady=5)

decrypt_buttons_frame = tk.Frame(decrypt_frame)
decrypt_buttons_frame.pack()

btn_decrypt_file = tk.Button(decrypt_buttons_frame, text="🔓 Decrypt File",
                             command=decrypt_image_file_gui, bg="#FF5722", fg="white",
                             font=("Arial", 9), padx=15)
btn_decrypt_file.pack(side="left", padx=5)

btn_decrypt_pixels = tk.Button(decrypt_buttons_frame, text="🎨 Unscramble Pixels",
                               command=decrypt_image_pixels_gui, bg="#E91E63", fg="white",
                               font=("Arial", 9), padx=15)
btn_decrypt_pixels.pack(side="left", padx=5)

btn_clear = tk.Button(decrypt_buttons_frame, text="🗑️ Clear All",
                      command=clear_image_displays, bg="#9E9E9E", fg="white",
                      font=("Arial", 9), padx=15)
btn_clear.pack(side="left", padx=5)

# Information panel
info_frame = tk.LabelFrame(controls_main_frame, text="Information", padx=10, pady=5)
info_frame.pack(fill="x", pady=5)

info_text = tk.Text(info_frame, height=4, font=("Arial", 8), bg="#f8f8f8")
info_text.pack(fill="x")
info_text.insert("1.0", """• File Encryption: Encrypts the entire image file securely (recommended for security)
• Pixel Scrambling: Encrypts image pixels for visual effect (shows scrambled image)
• CBC/GCM modes provide better security than ECB
• All encrypted files include metadata for proper decryption""")
info_text.config(state="disabled")

window.mainloop()
