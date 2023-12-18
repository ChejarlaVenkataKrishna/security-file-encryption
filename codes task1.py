
import os

from cryptography.fernet import Fernet


def generate_key():
    return Fernet.generate_key()

def write_key(key, key_file="secret.key"):
    with open(key_file, "wb") as key_file:
        key_file.write(key)

def load_key(key_file="secret.key"):
    return open(key_file, "rb").read()

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        data = file.read()
        encrypted_data = fernet.encrypt(data)
    with open(file_path + ".encrypted", "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

def decrypt_file(encrypted_file_path, key):
    fernet = Fernet(key)
    with open(encrypted_file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
    with open(encrypted_file_path[:-10], "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

# Example usage
if __name__ == "__main__":
    # Generate and write a key
    key = generate_key()
    write_key(key)

    # Load the key
    loaded_key = load_key()

    # Encrypt a file
    file_to_encrypt = "example.txt"
    encrypt_file(file_to_encrypt, loaded_key)
    print(f"File {file_to_encrypt} encrypted.")

    # Decrypt the file
    encrypted_file = file_to_encrypt + ".encrypted"
    decrypt_file(encrypted_file, loaded_key)
    print(f"File {encrypted_file} decrypted.")

