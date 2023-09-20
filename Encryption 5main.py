import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Create the main window
window = tk.Tk()
window.title("File Encryption")
window.geometry("400x200")
window.resizable(False, False)


# Function to display a message box with a custom title
def show_title_message(title, message):
    messagebox.showinfo(title, message)


def generate_or_load_private_key():
    private_key_file_path = "private_key.pem"

    if os.path.exists(private_key_file_path):
        # Load the private key from file
        try:
            with open(private_key_file_path, "rb") as file:
                private_key = serialization.load_pem_private_key(
                    file.read(),
                    password=None
                )
            return private_key
        except Exception as e:
            messagebox.showerror("Private Key Error", str(e))
            return None
    else:
        # Generate recipient's private key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Save the private key to file
        try:
            with open(private_key_file_path, "wb") as file:
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                file.write(private_pem)
            return private_key
        except Exception as e:
            messagebox.showerror("Private Key Error", str(e))
            return None

# Function to handle the encryption process
def encrypt_file(public_key):
    # Prompt the user to select a file
    file_path = filedialog.askopenfilename()

    # Encrypt the file
    try:
        with open(file_path, "rb") as file:
            plaintext = file.read()

        # Generate new random AES-256 key and IV
        key = os.urandom(256 // 8)
        iv = os.urandom(128 // 8)

        # Pad the plaintext
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the plaintext
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Encrypt the AES key using the public key
        cipherkey = public_key.encrypt(key,
                                       OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None))

        # Save the encrypted file
        encrypted_file_path = filedialog.asksaveasfilename(defaultextension=".enc")
        with open(encrypted_file_path, "wb") as file:
            file.write(iv + ciphertext)

        # Save the cipherkey file
        cipherkey_file_path = filedialog.asksaveasfilename(defaultextension=".pem")
        with open(cipherkey_file_path, "wb") as file:
            file.write(cipherkey)

        show_title_message("Encryption Successful", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))


# Function to handle the decryption process
def decrypt_file(private_key):
    # Prompt the user to select the encrypted file
    encrypted_file_path = filedialog.askopenfilename(title="Select the Encrypted File")
    if not encrypted_file_path:
        show_title_message("Decryption Error", "Encrypted file not selected.")
        return

    # Read the encrypted file
    try:
        with open(encrypted_file_path, "rb") as file:
            encrypted_data = file.read()

        # Extract the IV and ciphertext from the encrypted file
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        if len(iv) != 16 or len(ciphertext) == 0:
            messagebox.showerror("Decryption Error", "Invalid encryption data.")
            return

    except Exception as e:
        messagebox.showerror("File Read Error", str(e))
        return

    # Prompt the user to select the cipherkey file
    cipherkey_file_path = filedialog.askopenfilename(title="Select the Cipherkey File")
    if not cipherkey_file_path:
        show_title_message("Decryption Error", "Cipherkey file not selected.")
        return

    # Read the cipherkey file
    try:
        with open(cipherkey_file_path, "rb") as file:
            cipherkey = file.read()
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))
        return

    # Decrypt the file
    try:
        # Decrypt AES key
        oaep_padding = OAEP(mgf=MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
        recovered_key = private_key.decrypt(cipherkey, oaep_padding)

        # Decrypt the ciphertext
        cipher = Cipher(algorithms.AES(recovered_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()

        # Prompt the user to select a location to save the decrypted file
        decrypted_file_path = filedialog.asksaveasfilename()

        # Save the decrypted file
        with open(decrypted_file_path, "wb") as file:
            file.write(decrypted_plaintext)

        show_title_message("Decryption Successful", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))


# Load or generate recipient's private key
private_key = generate_or_load_private_key()

# Public key to make available to senders
public_key = private_key.public_key()

# Create and position the GUI elements
frame = ttk.Frame(window, padding=20)
frame.pack(fill="both", expand=True)

encrypt_button = ttk.Button(frame, text="Encrypt File", command=lambda: encrypt_file(public_key))
encrypt_button.pack(pady=10)

decrypt_button = ttk.Button(frame, text="Decrypt File", command=lambda: decrypt_file(private_key))
decrypt_button.pack(pady=10)

# Start the GUI event loop
window.mainloop()
