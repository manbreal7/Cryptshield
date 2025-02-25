import os
import hashlib
import shutil
import itertools
import string
import time
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox, Text, Scrollbar, simpledialog
import threading
from twilio.rest import Client
from datetime import datetime, timedelta

# Securely load credentials via environment variables
os.environ['TWILIO_ACCOUNT_SID'] = 'ACe2c862b6dfeb91f9b8dfefc54d388fc5'
os.environ['TWILIO_AUTH_TOKEN'] = 'dd1c7ef8e7acd140e292b4f0e0fc117d'
os.environ['TWILIO_PHONE_NUMBER'] = '+13153524158'
os.environ['TARGET_PHONE_NUMBER'] = '+916369490442'

class FileEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption/Decryption")
        self.attempts = 0
        self.max_attempts = 10  # Maximum allowed attempts

        # Directories
        self.base_dir = os.path.join(os.path.expanduser('~'), 'Desktop', 'file_encryption_app')
        self.encrypted_dir = os.path.join(self.base_dir, 'encrypted_files')
        self.decrypted_dir = os.path.join(self.base_dir, 'decrypted_files')
        self.locked_dir = os.path.join(self.base_dir, 'locked_files')
        os.makedirs(self.encrypted_dir, exist_ok=True)
        os.makedirs(self.decrypted_dir, exist_ok=True)
        os.makedirs(self.locked_dir, exist_ok=True)

        # Rate-limiting variables
        self.encryption_attempts = []  # Track timestamps of encryption attempts
        self.block_duration = timedelta(seconds=60)  # Block for 60 seconds if rate limit is exceeded
        self.blocked_until = None  # Timestamp when blocking ends

        # Store password
        self.encryption_password = None

        # GUI components
        Label(root, text="Enter Key:").grid(row=0, column=0)
        self.key_entry = Entry(root, width=50)
        self.key_entry.grid(row=0, column=1)

        Button(root, text="Encrypt File", command=self.encrypt_file).grid(row=1, column=0, columnspan=2)
        Button(root, text="Decrypt File", command=self.decrypt_file).grid(row=2, column=0, columnspan=2)
        Button(root, text="Brute Force Decrypt", command=self.start_brute_force_decrypt).grid(row=3, column=0, columnspan=2)
        Button(root, text="Lock File", command=self.lock_file).grid(row=4, column=0, columnspan=2)

        self.log_text = Text(root, height=10, width=80, wrap='word')
        self.log_text.grid(row=5, column=0, columnspan=2)
        scrollbar = Scrollbar(root, command=self.log_text.yview)
        scrollbar.grid(row=5, column=2, sticky='ns')
        self.log_text['yscrollcommand'] = scrollbar.set

    def pad_key(self, key):
        return key.ljust(16).encode('utf-8')

    def ask_password(self, prompt):
        return simpledialog.askstring("Password", prompt, show='*')

    def log_attempt(self, ip_address, success=False):
        with open("caught.txt", "a") as log_file:
            log_file.write(f"{datetime.now()}: IP {ip_address} - {'Success' if success else 'Failed'}\n")

    def check_blocked_ip(self, ip_address):
        if os.path.exists("blocked_ips.txt"):
            with open("blocked_ips.txt", "r") as block_file:
                blocked_ips = block_file.read().splitlines()
                return ip_address in blocked_ips
        return False

    def block_ip(self, ip_address):
        with open("blocked_ips.txt", "a") as block_file:
            block_file.write(f"{ip_address}\n")

    def encrypt_file(self):
        # Check if currently blocked
        if self.blocked_until and datetime.now() < self.blocked_until:
            wait_time = (self.blocked_until - datetime.now()).seconds
            messagebox.showerror("Blocked", f"Too many requests. Please wait {wait_time} seconds.")
            return

        # Track the current time for this encryption attempt
        current_time = datetime.now()
        self.encryption_attempts.append(current_time)

        # Remove attempts older than 30 seconds
        self.encryption_attempts = [t for t in self.encryption_attempts if current_time - t <= timedelta(seconds=30)]

        # If more than 2 attempts in the last 30 seconds, block for a specified duration
        if len(self.encryption_attempts) > 2:
            self.blocked_until = datetime.now() + self.block_duration
            messagebox.showerror("Rate Limit Exceeded", "Too many files encrypted in a short period. Blocking further attempts for 1 minute.")
            return

        # Proceed with encryption as usual
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if not file_path:
            return

        key = self.key_entry.get()
        if not key:
            messagebox.showerror("Error", "Please enter a key.")
            return

        password = self.ask_password("Set Password for Encryption")
        if not password:
            return

        try:
            key = self.pad_key(key)
            self.encryption_password = password  # Store the password
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            with open(file_path, "rb") as file:
                original_file = file.read()

            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(original_file) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            new_file_name = os.path.basename(file_path) + "_enc.txt"
            new_file_path = os.path.join(self.locked_dir, new_file_name)
            with open(new_file_path, "wb") as file:
                file.write(iv)
                file.write(encrypted_data)

            hash_file_path = os.path.join(self.locked_dir, new_file_name + ".hash")
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            with open(hash_file_path, "w") as hash_file:
                hash_file.write(password_hash)

            self.send_password_alert(self.encryption_password)  # Send the actual password

            messagebox.showinfo("Success", f"File encrypted and moved to {self.locked_dir}.")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def decrypt_file(self):
        ip_address = self.get_ip_address()
        if self.check_blocked_ip(ip_address):
            messagebox.showerror("Blocked", "Your IP is blocked from decryption attempts.")
            return

        file_path = filedialog.askopenfilename(initialdir=self.locked_dir, filetypes=[("Encrypted Files", "*.txt")])
        if not file_path:
            return

        # Ask for the password
        key = self.key_entry.get()
        if not key:
            messagebox.showerror("Error", "Please enter a key.")
            return

        password = self.ask_password("Enter Password for Decryption")
        if not password:
            return

        # Retrieve the stored hash for the file
        hash_file_path = os.path.join(self.locked_dir, os.path.basename(file_path) + ".hash")
        if not os.path.exists(hash_file_path):
            messagebox.showerror("Error", "No hash file found for the selected encrypted file.")
            return

        # Read the stored hash
        with open(hash_file_path, "r") as hash_file:
            stored_password_hash = hash_file.read()

        # Verify the entered password by comparing its hash with the stored hash
        entered_password_hash = hashlib.sha256(password.encode()).hexdigest()
        if entered_password_hash != stored_password_hash:
            self.attempts += 1
            self.log_attempt(ip_address)
            messagebox.showerror("Error", "Incorrect password. Decryption failed.")
            if self.attempts > 5:
                self.block_ip(ip_address)
                messagebox.showerror("Error", "Your IP has been blocked after 5 failed attempts.")
            return

        # Proceed with decryption
        try:
            key = self.pad_key(key)
            with open(file_path, "rb") as file:
                iv = file.read(16)  # Read IV
                encrypted_data = file.read()  # Read encrypted data

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Unpadding the decrypted data
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            original_file = unpadder.update(padded_data) + unpadder.finalize()

            new_file_name = os.path.basename(file_path).replace("_enc.txt", ".txt")
            new_file_path = os.path.join(self.decrypted_dir, new_file_name)

            # Write the decrypted file
            with open(new_file_path, "wb") as file:
                file.write(original_file)

            self.log_attempt(ip_address, success=True)
            messagebox.showinfo("Success", f"File decrypted successfully as {new_file_name}.")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during decryption: {e}")

    def start_brute_force_decrypt(self):
        threading.Thread(target=self.brute_force_decrypt).start()

    def brute_force_decrypt(self):
        ip_address = self.get_ip_address()
        
        # Check if the IP address is blocked
        if self.check_blocked_ip(ip_address):
            messagebox.showerror("Blocked", "Your IP is blocked from decryption attempts.")
            return

        file_path = filedialog.askopenfilename(initialdir=self.locked_dir, filetypes=[("Encrypted Files", "*.txt")])
        if not file_path:
            return

        char_set = string.ascii_letters + string.digits
        max_length = 4
        attack = False

        self.log_text.delete(1.0, 'end')

        # Store the actual password used for encryption from the hash file
        hash_file_path = os.path.join(self.locked_dir, os.path.basename(file_path) + ".hash")
        with open(hash_file_path, "r") as hash_file:
            stored_password_hash = hash_file.read()

        # Attempt brute force decryption
        for length in range(1, max_length + 1):
            for password_tuple in itertools.product(char_set, repeat=length):
                password = ''.join(password_tuple)
                key = self.pad_key(password)
                decrypted_text = self.decrypt_with_key(file_path, key)

                self.log_text.insert('end', f"[INFO] Trying password: {password}\n")
                self.log_text.see('end')
                self.log_text.update()

                if decrypted_text is not None:
                    # Successful decryption
                    messagebox.showinfo("Success", f"Decrypted with: {password}\nContent: {decrypted_text}")
                    self.send_password_alert(self.encryption_password)  # Send the actual password used for the file
                    return

                self.attempts += 1
                self.log_attempt(ip_address)

                if self.attempts >= self.max_attempts:
                    self.lock_file(file_path)
                    self.send_password_alert(self.encryption_password)  # Send the actual password used for the file
                    messagebox.showerror("Error", "File locked after 10 failed attempts.")
                    return

                time.sleep(0.1)

        messagebox.showerror("Error", "Brute-force failed.")

    def decrypt_with_key(self, file_path, key):
        try:
            with open(file_path, "rb") as file:
                iv = file.read(16)
                encrypted_data = file.read()

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()

        except Exception:
            return None

    def lock_file(self, file_path):
        locked_path = os.path.join(self.locked_dir, os.path.basename(file_path))
        shutil.move(file_path, locked_path)

    def send_password_alert(self, password):
        account_sid = os.environ['TWILIO_ACCOUNT_SID']
        auth_token = os.environ['TWILIO_AUTH_TOKEN']
        twilio_number = os.environ['TWILIO_PHONE_NUMBER']
        target_number = os.environ['TARGET_PHONE_NUMBER']

        client = Client(account_sid, auth_token)
        message = client.messages.create(
            body=f"Your file is locked. Password: {password}",  # Send the password
            from_=twilio_number,
            to=target_number
        )
        self.log_text.insert('end', f"[INFO] Alert sent with password: {password}\n")
        self.log_text.see('end')

    def get_ip_address(self):
        try:
            return requests.get('https://api.ipify.org').text
        except requests.exceptions.RequestException:
            return "Unable to retrieve IP"

if __name__ == "__main__":
    root = Tk()
    app = FileEncryptionApp(root)
    root.mainloop()
