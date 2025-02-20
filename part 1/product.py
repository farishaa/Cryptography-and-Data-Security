import math
import time
from sympy import mod_inverse


# affine chipher (E(x) = (a⋅x + b) mod 26)
def affine_encrypt(text, a, b):
    cipher = ""
    m = 26  # abc...
    for char in text:
        if char.isalpha():
            x = ord(char.lower()) - ord('a')  # letter --> number
            cipher += chr(((a * x + b) % m) + ord('a'))
        else:
            cipher += char
    return cipher

def affine_decrypt(cipher, a, b):
    plain = ""
    m = 26
    a_inv = mod_inverse(a, m) 
    for char in cipher:
        if char.isalpha():
            y = ord(char.lower()) - ord('a')
            plain += chr(((a_inv * (y - b)) % m) + ord('a'))
        else:
            plain += char
    return plain

# columnar transposition 
def columnar_encrypt(text, key):
    num_cols = len(key)
    num_rows = math.ceil(len(text) / num_cols)
    
    text_list = list(text)
    pad_char = "X" # padding if needed
    pad_needed = (num_rows * num_cols) - len(text_list)
    
    if pad_needed > 0:
        text_list.extend([pad_char] * pad_needed)

    matrix = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    idx = 0
    for i in range(num_rows):
        for j in range(num_cols):
            if idx < len(text_list):
                matrix[i][j] = text_list[idx]
                idx += 1

    key_order = sorted(list(enumerate(key)), key=lambda x: x[1])
    cipher_text = ""
    for _, col_index in key_order:
        for row in range(num_rows):
            cipher_text += matrix[row][col_index]

    return cipher_text

def columnar_decrypt(cipher_text, key):
    num_cols = len(key)
    num_rows = math.ceil(len(cipher_text) / num_cols)

    matrix = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    key_order = sorted(list(enumerate(key)), key=lambda x: x[1])
    
    idx = 0
    for _, col_index in key_order:
        for row in range(num_rows):
            if idx < len(cipher_text):
                matrix[row][col_index] = cipher_text[idx]
                idx += 1

    plain_text = "".join(matrix[row][col] for row in range(num_rows) for col in range(num_cols))

    while plain_text.endswith("X"):
        plain_text = plain_text[:-1]

    return plain_text

# affine + double columnar transposition
def product_encrypt(text, a, b, key1, key2):
    start_time = time.time()

    affine_encrypted = affine_encrypt(text, a, b)   
    transposition_encrypted1 = columnar_encrypt(affine_encrypted, key1)
    transposition_encrypted2 = columnar_encrypt(transposition_encrypted1, key2)  

    end_time = time.time()
    encryption_time = end_time - start_time

    print(f"\nAffine Encryption = {affine_encrypted}")
    print(f"First Transposition = {transposition_encrypted1}")
    print(f"Second Transposition = {transposition_encrypted2}")
    print(f"Encryption Time: {encryption_time:.6f} seconds")

    return transposition_encrypted2, encryption_time

def product_decrypt(cipher_text, a, b, key1, key2):
    start_time = time.time()

    transposition_decrypted1 = columnar_decrypt(cipher_text, key2)  
    transposition_decrypted2 = columnar_decrypt(transposition_decrypted1, key1) 
    affine_decrypted = affine_decrypt(transposition_decrypted2, a, b)  

    end_time = time.time()
    decryption_time = end_time - start_time

    print(f"\nReverse Second Transposition = {transposition_decrypted1}")
    print(f"Reverse First Transposition = {transposition_decrypted2}")
    print(f"Affine Decryption = {affine_decrypted}")
    print(f"Decryption Time: {decryption_time:.6f} seconds")

    return affine_decrypted, decryption_time

# user input
plaintext = input("Enter plaintext: ")
a = int(input("Enter value for a (must be coprime with 26): "))
b = int(input("Enter value for b: "))
key1 = list(map(int, input("Enter first key (with space): ").split()))
key2 = list(map(int, input("Enter second key (with space): ").split()))

# encryption time 
encrypted_text, encryption_time = product_encrypt(plaintext, a, b, key1, key2)

# decryption time 
decrypted_text, decryption_time = product_decrypt(encrypted_text, a, b, key1, key2)

# output
print(f"\nOriginal Text:   {plaintext}")
print(f"Encrypted Text:  {encrypted_text}")
print(f"Decrypted Text:  {decrypted_text}")

