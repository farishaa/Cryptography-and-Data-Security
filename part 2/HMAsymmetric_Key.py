from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os

# The RSA Key generation for Person B (Public Key & Private Key )
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Saving the RSA keys in their own files 
def save_rsa_keys(private_key, public_key):
    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Load RSA Keys
def load_rsa_keys():
    with open("private_key.pem", "rb") as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,
            backend=default_backend()
        )
    with open("public_key.pem", "rb") as pub_file:
        public_key = serialization.load_pem_public_key(
            pub_file.read(),
            backend=default_backend()
        )
    return private_key, public_key

# Saving AES key for reference
def save_aes_key(aes_key):
    with open("aes_key.bin", "wb") as aes_file:
        aes_file.write(aes_key)

# Load AES Key
def load_aes_key():
    with open("aes_key.bin", "rb") as aes_file:
        return aes_file.read()

# Person A encrypts the message using AES key
def encrypt_aes(message, aes_key, iv):
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# Decrypting message using AES key
def decrypt_aes(ciphertext, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_data) + unpadder.finalize()
    return message

# RSA Encrypt AES Key --> Encrypt the AES secret key using Person B's RSA public key.
def encrypt_rsa(public_key, aes_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# RSA Decrypt AES Key --> Decrypting AES key using the RSA private key.
def decrypt_rsa(private_key, encrypted_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

#  For the Main Function
def main():
    private_key, public_key = generate_rsa_keys()
    save_rsa_keys(private_key, public_key)
    aes_key = os.urandom(32)  # AES-256
    iv = os.urandom(16)       # 16 bytes IV for CBC mode

    save_aes_key(aes_key)

    user_message = input("Enter your message: ").encode()
    encrypted_message = encrypt_aes(user_message, aes_key, iv)
    encrypted_aes_key = encrypt_rsa(public_key, aes_key)
    loaded_private_key, loaded_public_key = load_rsa_keys()
    loaded_aes_key = load_aes_key()
    decrypted_aes_key = decrypt_rsa(private_key, encrypted_aes_key)
    decrypted_message = decrypt_aes(encrypted_message, decrypted_aes_key, iv)


    print("\n" + "="*50)
    print("🔒 ENCRYPTION RESULTS")
    print("="*50)
    print(f"📝 Original Message   : {user_message.decode()}")
    print(f"📝 Original AES Key   : {aes_key.hex()}")
    print(f"💾 Encrypted Message  : {encrypted_message.hex()}")
    print(f"🔑 Encrypted AES Key  : {encrypted_aes_key.hex()}")
    print(f"🔓 Decrypted AES Key  : {decrypted_aes_key.hex()}")
    print(f"✅ Decrypted Message  : {decrypted_message.decode()}")
    print("="*50)

if __name__ == "__main__":
    main()