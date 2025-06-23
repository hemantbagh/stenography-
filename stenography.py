from PIL import Image
import numpy as np

def to_bin(data):
    """Convert data to binary format as string"""
    if isinstance(data, str):
        return ''.join([format(ord(i), '08b') for i in data])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [format(i, '08b') for i in data]
    elif isinstance(data, int):
        return format(data, '08b')
    else:
        raise TypeError("Type not supported.")

def encode_image(image_path, secret_message, output_path):
    image = Image.open(image_path)
    image = image.convert("RGB")
    data = np.array(image)
    flat_data = data.flatten()

    binary_secret = to_bin(secret_message) + '1111111111111110'  # delimiter
    secret_index = 0

    for i in range(len(flat_data)):
        if secret_index < len(binary_secret):
            flat_data[i] = (flat_data[i] & ~1) | int(binary_secret[secret_index])
            secret_index += 1
        else:
            break

    encoded_data = flat_data.reshape(data.shape)
    encoded_image = Image.fromarray(encoded_data.astype('uint8'), 'RGB')
    encoded_image.save(output_path)
    print(f"Message encoded and saved to {output_path}")

def decode_image(encoded_image_path):
    image = Image.open(encoded_image_path)
    image = image.convert("RGB")
    data = np.array(image)
    flat_data = data.flatten()

    binary_data = ""
    for value in flat_data:
        binary_data += str(value & 1)

    # Split into 8-bit chunks
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_message = ""
    for byte in all_bytes:
        if byte == '11111110':  # delimiter
            break
        decoded_message += chr(int(byte, 2))
    return decoded_message

# Example usage:
# Encode
encode_image("input.png", "This is a hidden message!", "encoded_output.png")

# Decode
message = decode_image("encoded_output.png")
print("Decoded message:", message)
# Example usage:
# Encode    from PIL import Image
import numpy as np
from cryptography.fernet import Fernet
import base64
import hashlib

def to_bin(data):
    """Convert data to binary format"""
    if isinstance(data, str):
        return ''.join([format(ord(i), '08b') for i in data])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [format(i, '08b') for i in data]
    elif isinstance(data, int):
        return format(data, '08b')
    else:
        raise TypeError("Unsupported type.")

def generate_key(password):
    """Generate Fernet key from password"""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_message(message, password):
    key = generate_key(password)
    f = Fernet(key)
    return f.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, password):
    key = generate_key(password)
    f = Fernet(key)
    return f.decrypt(encrypted_message.encode()).decode()

def encode_image(image_path, secret_message, password, output_path):
    encrypted_message = encrypt_message(secret_message, password)
    binary_secret = to_bin(encrypted_message) + '1111111111111110'  # delimiter

    image = Image.open(image_path).convert("RGB")
    data = np.array(image)
    flat_data = data.flatten()

    if len(binary_secret) > len(flat_data):
        raise ValueError("Message is too large for the image.")

    for i in range(len(binary_secret)):
        flat_data[i] = (flat_data[i] & ~1) | int(binary_secret[i])

    encoded_data = flat_data.reshape(data.shape)
    encoded_image = Image.fromarray(encoded_data.astype('uint8'), 'RGB')
    encoded_image.save(output_path)
    print(f"Encrypted message encoded and saved to {output_path}")

def decode_image(encoded_image_path, password):
    image = Image.open(encoded_image_path).convert("RGB")
    data = np.array(image)
    flat_data = data.flatten()

    binary_data = ""
    for value in flat_data:
        binary_data += str(value & 1)

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    encrypted_message = ""
    for byte in all_bytes:
        if byte == '11111110':  # delimiter
            break
        encrypted_message += chr(int(byte, 2))

    try:
        decrypted = decrypt_message(encrypted_message, password)
        return decrypted
    except Exception as e:
        return "Decryption failed: " + str(e)

# =========================
# 🔍 Example Usage:
# =========================
# Encode
encode_image("input.png", "This is a top secret!", "mypassword123", "secret_output.png")

# Decode
message = decode_image("secret_output.png", "mypassword123")
print("Decoded & Decrypted message:", message)
# Example usage:
# Encode    from PIL import Image
import numpy as np  
from cryptography.fernet import Fernet
import base64   
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import numpy as np
from cryptography.fernet import Fernet
import base64
import hashlib
import os

# === Utility Functions ===

def to_bin(data):
    if isinstance(data, str):
        return ''.join([format(ord(i), '08b') for i in data])
    elif isinstance(data, bytes):
        return ''.join([format(i, '08b') for i in data])
    else:
        raise TypeError("Unsupported type.")

def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_message(message, password):
    key = generate_key(password)
    f = Fernet(key)
    return f.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, password):
    key = generate_key(password)
    f = Fernet(key)
    return f.decrypt(encrypted_message.encode()).decode()

def encode_image(image_path, secret_message, password, output_path):
    encrypted_message = encrypt_message(secret_message, password)
    binary_secret = to_bin(encrypted_message) + '1111111111111110'

    image = Image.open(image_path).convert("RGB")
    data = np.array(image)
    flat_data = data.flatten()

    if len(binary_secret) > len(flat_data):
        raise ValueError("Message too large for the image.")

    for i in range(len(binary_secret)):
        flat_data[i] = (flat_data[i] & ~1) | int(binary_secret[i])

    encoded_data = flat_data.reshape(data.shape)
    encoded_image = Image.fromarray(encoded_data.astype('uint8'), 'RGB')
    encoded_image.save(output_path)

def decode_image(image_path, password):
    image = Image.open(image_path).convert("RGB")
    data = np.array(image)
    flat_data = data.flatten()

    binary_data = ""
    for value in flat_data:
        binary_data += str(value & 1)

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    encrypted_message = ""
    for byte in all_bytes:
        if byte == '11111110':
            break
        encrypted_message += chr(int(byte, 2))

    return decrypt_message(encrypted_message, password)

# === GUI Code ===

class StegoApp:
    def __init__(self, master):
        self.master = master
        master.title("Steganography Tool")
        master.geometry("500x400")
        master.resizable(False, False)

        self.image_path = ""

        tk.Label(master, text="Secret Message:").pack(pady=5)
        self.message_entry = tk.Text(master, height=4, width=50)
        self.message_entry.pack()

        tk.Label(master, text="Password:").pack(pady=5)
        self.password_entry = tk.Entry(master, show="*", width=30)
        self.password_entry.pack()

        self.select_button = tk.Button(master, text="Select Image", command=self.select_image)
        self.select_button.pack(pady=5)

        self.encode_button = tk.Button(master, text="Encode & Save Image", command=self.encode)
        self.encode_button.pack(pady=5)

        self.decode_button = tk.Button(master, text="Decode Message from Image", command=self.decode)
        self.decode_button.pack(pady=10)

        self.result_text = tk.Text(master, height=6, width=60, state=tk.DISABLED)
        self.result_text.pack()

    def select_image(self):
        self.image_path = filedialog.askopenfilename(title="Select Image", filetypes=[("PNG Files", "*.png")])
        if self.image_path:
            messagebox.showinfo("Image Selected", f"Selected: {os.path.basename(self.image_path)}")

    def encode(self):
        message = self.message_entry.get("1.0", tk.END).strip()
        password = self.password_entry.get().strip()

        if not self.image_path or not message or not password:
            messagebox.showwarning("Missing Info", "Please select image, message, and password.")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if not save_path:
            return

        try:
            encode_image(self.image_path, message, password, save_path)
            messagebox.showinfo("Success", "Message encoded and saved.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decode(self):
        if not self.image_path:
            self.image_path = filedialog.askopenfilename(title="Select Encoded Image", filetypes=[("PNG Files", "*.png")])

        password = self.password_entry.get().strip()
        if not self.image_path or not password:
            messagebox.showwarning("Missing Info", "Please select image and enter password.")
            return

        try:
            decoded_msg = decode_image(self.image_path, password)
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, f"Decrypted Message:\n{decoded_msg}")
            self.result_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed or no message found.")

# === Run the App ===

if __name__ == "__main__":
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()
# Example usage:
# Encode                
# encode_image("input.png", "This is a top secret!", "mypassword123 
from PIL import Image
import numpy as np
import base64
import hashlib
from cryptography.fernet import Fernet

def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def decrypt_message(encrypted_message, password):
    key = generate_key(password)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message.encode()).decode()

def decode_image(image_path, password):
    image = Image.open(image_path).convert("RGB")
    data = np.array(image)
    flat_data = data.flatten()

    binary_data = "".join([str(byte & 1) for byte in flat_data])
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]

    encrypted_message = ""
    for byte in all_bytes:
        if byte == '11111110':  # Delimiter
            break
        encrypted_message += chr(int(byte, 2))

    try:
        return decrypt_message(encrypted_message, password)
    except Exception as e:
        return f"[!] Decryption failed or wrong password: {e}"

# === USAGE ===
image_path = "secret_image.png"
password = input("Enter password to decode the message: ")
hidden_message = decode_image(image_path, password)
print("🔓 Hidden message:", hidden_message)

# 🔓 Hidden message: The password is "trustno1" and the launch code is 0457Z

# encode_image("input.png", "This is a top secret!", "mypassword123
