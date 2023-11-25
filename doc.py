from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from getpass import getpass

def encrypt_document(file_path, key):
    cipher = AES.new(key, AES.MODE_CBC)
    
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    with open('encrypted_' + file_path, 'wb') as file:
        file.write(cipher.iv)
        file.write(ciphertext)

def decrypt_document(file_path, key):
    with open(file_path, 'rb') as file:
        iv = file.read(16)
        ciphertext = file.read()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    with open('decrypted_' + file_path, 'wb') as file:
        file.write(decrypted_data)

def authenticate_user():
    # Simulating user authentication (replace with real authentication logic)
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")  # Using getpass to securely input the password
    
    # In a real-world scenario, you would verify the credentials against a database
    # For simplicity, we'll use a hardcoded example
    if username == "user123" and password == "securepassword":
        return True
    else:
        return False

# Example usage:
file_to_encrypt = 'document.pdf'
output_encrypted_file = 'encrypted_document.pdf'

# Authenticate the user before encryption
if authenticate_user():
    encryption_key = get_random_bytes(16)  # 128-bit key for AES
    encrypt_document(file_to_encrypt, encryption_key)
    print("Document encrypted successfully.")
else:
    print("Authentication failed. Access denied.")

# Now, let's decrypt the document
file_to_decrypt = 'encrypted_document.pdf'

# Authenticate the user before decryption
if authenticate_user():
    decrypt_document(file_to_decrypt, encryption_key)
    print("Document decrypted successfully.")
else:
    print("Authentication failed. Access denied.")
