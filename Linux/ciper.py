import tkinter as tk
from tkinter import messagebox

def caesar_cipher(message, shift, mode='encrypt'):

    if mode == 'decrypt':
        shift = -shift

    encrypted_message = []

    for char in message:
        if char.isalpha():
            shift_amount = 65 if char.isupper() else 97
            encrypted_message.append(chr((ord(char) - shift_amount + shift) % 26 + shift_amount))
        else:
            encrypted_message.append(char)

    return ''.join(encrypted_message)

def process_cipher():
    # Change button color to indicate it has been pressed
    process_button.config(bg="lightgrey")
    root.update_idletasks()  # Update the GUI to reflect the color change
    
    message = message_entry.get()
    shift = shift_entry.get()
    
    if not shift.isdigit():
        messagebox.showerror("Invalid Input", "Shift value must be an integer.")
        process_button.config(bg=button_default_color)
        return
    
    shift = int(shift)
    mode = mode_var.get()

    result = caesar_cipher(message, shift, mode)
    result_var.set(result)
    
    # Reset button color after processing
    process_button.config(bg=button_default_color)

# Create the main application window
root = tk.Tk()
root.title("Caesar Cipher")

# Create and place the components in the window
tk.Label(root, text="Message:").grid(row=0, column=0, padx=10, pady=10)
message_entry = tk.Entry(root, width=50)
message_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Shift:").grid(row=1, column=0, padx=10, pady=10)
shift_entry = tk.Entry(root, width=10)
shift_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

mode_var = tk.StringVar(value="encrypt")
tk.Radiobutton(root, text="Encrypt", variable=mode_var, value="encrypt").grid(row=2, column=0, padx=10, pady=10, sticky="w")
tk.Radiobutton(root, text="Decrypt", variable=mode_var, value="decrypt").grid(row=2, column=1, padx=10, pady=10, sticky="w")

button_default_color = root.cget("bg")
process_button = tk.Button(root, text="Process", command=process_cipher)
process_button.grid(row=3, column=0, columnspan=2, pady=20)

result_var = tk.StringVar()
tk.Label(root, text="Result:").grid(row=4, column=0, padx=10, pady=10)
tk.Entry(root, textvariable=result_var, width=50, state="readonly").grid(row=4, column=1, padx=10, pady=10)

# Start the Tkinter event loop and also end of the code 
root.mainloop()