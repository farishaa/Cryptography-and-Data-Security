from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# encryption for AES message
def encrypt_aes_cbc(message, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# decryption for AES message
def decrypt_aes_cbc(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    try:
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext
    except ValueError:
        return b"Decryption failed due to padding error."

# The effects of Bit Error in Ciphertext (single bits)
def effects_bit_error(ciphertext, byte_index, bit_position):
    corrupted = bytearray(ciphertext)
    corrupted[byte_index] ^= (1 << bit_position)  # Flip the specific bit
    return bytes(corrupted)

def highlight_bit_difference(original, corrupted):
    highlighted = ""
    for i, (o_byte, c_byte) in enumerate(zip(original, corrupted)):
        if o_byte != c_byte:
            highlighted += f"\033[91m{c_byte:02x}\033[0m "  # Red for changed bytes
        else:
            highlighted += f"{c_byte:02x} "
    return highlighted

def format_hex(data, block_size=16):
    hex_str = data.hex()
    return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

# Error Analysis table to show the difference between the original and corrupted version
def error_impact_analysis(byte_index, block_size, total_blocks):
    affected_block = byte_index // block_size
    print("\n" + "="*50)
    print("📊 Error Impact Analysis")
    print("="*50)
    print(f"Bit flipped at byte index: {byte_index}")
    print(f"Affected Ciphertext Block: {affected_block}")
    print("🔄 Impact on Plaintext:")
    print(f" - Block {affected_block}: Completely corrupted")
    if affected_block + 1 < total_blocks:
        print(f" - Block {affected_block + 1}: Single-bit error (due to CBC XOR)")
    else:
        print(" - No next block to be affected.")
    print("="*50)

def main():
    user_message = input("Enter the message to encrypt: ").encode()

    aes_key = os.urandom(32)  # AES-256
    iv = os.urandom(16)       # 16-byte IV for CBC

    
    encrypted_message = encrypt_aes_cbc(user_message, aes_key, iv)
    print(f"\nOriginal Encrypted Message (hex): {encrypted_message.hex()}")

    
    decrypted_message = decrypt_aes_cbc(encrypted_message, aes_key, iv)
    print(f"Decrypted Message: {decrypted_message.decode()}")

    
    byte_index = int(input("\nEnter byte index to modify (0-based): "))
    bit_position = int(input("Enter bit position to flip (0-7): "))

    formatted_hex = format_hex(encrypted_message)
    print(f"Original Encrypted Message (hex):\n{formatted_hex}")

    
    corrupted_ciphertext = effects_bit_error(encrypted_message, byte_index, bit_position)
    print(f"\nCorrupted Encrypted Message (hex): {highlight_bit_difference(encrypted_message, corrupted_ciphertext)}")

    
    corrupted_decrypted = decrypt_aes_cbc(corrupted_ciphertext, aes_key, iv)
    print(f"Corrupted Decrypted Message: {corrupted_decrypted.decode(errors='replace')}")


    block_size = 16  # AES block size in bytes
    total_blocks = len(encrypted_message) // block_size
    error_impact_analysis(byte_index, block_size, total_blocks)

if __name__ == "__main__":
    main()
