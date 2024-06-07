import tkinter as tk
from tkinter import ttk


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


def process_text():
    text = entry_text.get("1.0", tk.END).strip()
    shift = int(entry_shift.get())
    mode = mode_var.get()

    if mode == "Encrypt":
        result = caesar_cipher(text, shift, "Encrypt")
    elif mode == "Decrypt":
        result = caesar_cipher(text, shift, "Decrypt")

    entry_result.delete("1.0", tk.END)
    entry_result.insert(tk.END, result)


# Create main window
window = tk.Tk()
window.title("Caesar Cipher Encoder/Decoder")

# Create widgets
label_text = tk.Label(window, text="Enter text:")
entry_text = tk.Text(window, height=5, width=50)
label_shift = tk.Label(window, text="Enter shift value:")
entry_shift = tk.Entry(window)
label_mode = tk.Label(window, text="Select mode:")
mode_var = tk.StringVar()
mode_dropdown = ttk.Combobox(window, textvariable=mode_var, values=["Encrypt", "Decrypt"])
mode_dropdown.current(0)
button_process = tk.Button(window, text="Process", command=process_text)
label_result = tk.Label(window, text="Result:")
entry_result = tk.Text(window, height=5, width=50)

# Layout widgets
label_text.grid(row=0, column=0, sticky="w", padx=10, pady=5)
entry_text.grid(row=1, column=0, columnspan=2, padx=10, pady=5)
label_shift.grid(row=2, column=0, sticky="w", padx=10, pady=5)
entry_shift.grid(row=2, column=1, padx=10, pady=5)
label_mode.grid(row=3, column=0, sticky="w", padx=10, pady=5)
mode_dropdown.grid(row=3, column=1, padx=10, pady=5)
button_process.grid(row=4, column=0, columnspan=2, padx=10, pady=5)
label_result.grid(row=5, column=0, sticky="w", padx=10, pady=5)
entry_result.grid(row=6, column=0, columnspan=2, padx=10, pady=5)

# Start the GUI
window.mainloop()
