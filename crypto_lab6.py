import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

class RSACryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption System")

        # Змінні для ключів
        self.private_key = None
        self.public_key = None

        # Тексти інтерфейсу
        self.texts = {
            "generate_keys": "Generate Keys",
            "message_to_encrypt": "Message to Encrypt:",
            "encrypt": "Encrypt",
            "encrypted_message": "Encrypted Message:",
            "decrypt": "Decrypt",
            "decrypted_message": "Decrypted Message:",
            "keys_generated": "Keys Generated",
            "keys_message": "Public and Private keys have been generated.",
            "error": "Error",
            "enter_message": "Please enter a message to encrypt.",
            "keys_not_generated": "Keys have not been generated yet.",
            "enter_encrypted_message": "Please enter an encrypted message to decrypt.",
            "decryption_failed": "Decryption failed: ",
            "load_file": "Load File",
            "save_file": "Save File"
        }

        # Побудова інтерфейсу
        self.setup_ui()

    def setup_ui(self):
        """Налаштування елементів інтерфейсу."""
        # Кнопка для генерації ключів
        self.generate_keys_btn = tk.Button(self.root, text=self.texts["generate_keys"], command=self.generate_keys)
        self.generate_keys_btn.pack(pady=10)

        # Секція для роботи з файлами
        self.file_frame = tk.Frame(self.root)
        self.file_frame.pack(pady=10)

        self.load_file_btn = tk.Button(self.file_frame, text=self.texts["load_file"], command=self.load_file)
        self.load_file_btn.grid(row=0, column=0, padx=5)

        self.save_file_btn = tk.Button(self.file_frame, text=self.texts["save_file"], command=self.save_file)
        self.save_file_btn.grid(row=0, column=1, padx=5)

        # Секція шифрування
        self.encrypt_label = tk.Label(self.root, text=self.texts["message_to_encrypt"])
        self.encrypt_label.pack()
        self.encrypt_entry = tk.Entry(self.root, width=50)
        self.encrypt_entry.pack(pady=5)

        self.encrypt_btn = tk.Button(self.root, text=self.texts["encrypt"], command=self.encrypt_message)
        self.encrypt_btn.pack(pady=10)

        # Секція дешифрування
        self.decrypt_label = tk.Label(self.root, text=self.texts["encrypted_message"])
        self.decrypt_label.pack()
        self.decrypt_entry = tk.Entry(self.root, width=50)
        self.decrypt_entry.pack(pady=5)

        self.decrypt_btn = tk.Button(self.root, text=self.texts["decrypt"], command=self.decrypt_message)
        self.decrypt_btn.pack(pady=10)

        # Виведення результатів
        self.output_label = tk.Label(self.root, text="Output:")
        self.output_label.pack()
        self.output_text = tk.Text(self.root, height=10, width=60, state=tk.DISABLED)
        self.output_text.pack(pady=10)

    def generate_keys(self):
        """Генерує пару ключів RSA."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        messagebox.showinfo(self.texts["keys_generated"], self.texts["keys_message"])

    def load_file(self):
        """Завантажує файл для шифрування чи дешифрування."""
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, "rb") as file:
                data = file.read()
                self.encrypt_entry.delete(0, tk.END)
                self.encrypt_entry.insert(0, data.decode(errors="ignore"))

    def save_file(self):
        """Зберігає зашифроване або розшифроване повідомлення у файл."""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, "wb") as file:
                data = self.output_text.get(1.0, tk.END).strip()
                content = data.split("\n", 1)[1] if "\n" in data else data
                file.write(content.encode())

    def encrypt_message(self):
        """Шифрує введене повідомлення за допомогою публічного ключа."""
        message = self.encrypt_entry.get()
        if not message:
            messagebox.showerror(self.texts["error"], self.texts["enter_message"])
            return
        if not self.public_key:
            messagebox.showerror(self.texts["error"], self.texts["keys_not_generated"])
            return

        encrypted_message = self.public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.decrypt_entry.delete(0, tk.END)
        self.decrypt_entry.insert(0, encrypted_message.hex())
        self.display_output(self.texts["encrypted_message"], encrypted_message.hex())

    def decrypt_message(self):
        """Розшифровує введене зашифроване повідомлення за допомогою приватного ключа."""
        encrypted_message_hex = self.decrypt_entry.get()
        if not encrypted_message_hex:
            messagebox.showerror(self.texts["error"], self.texts["enter_encrypted_message"])
            return
        if not self.private_key:
            messagebox.showerror(self.texts["error"], self.texts["keys_not_generated"])
            return

        try:
            encrypted_message = bytes.fromhex(encrypted_message_hex)
            decrypted_message = self.private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.display_output(self.texts["decrypted_message"], decrypted_message.decode())
        except Exception as e:
            messagebox.showerror(self.texts["error"], f"{self.texts['decryption_failed']}{e}")

    def display_output(self, title, content):
        """Виводить результат у текстовий віджет."""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"{title}\n{content}\n")
        self.output_text.config(state=tk.DISABLED)

# Головний цикл програми
if __name__ == "__main__":
    root = tk.Tk()
    app = RSACryptoApp(root)
    root.mainloop()
