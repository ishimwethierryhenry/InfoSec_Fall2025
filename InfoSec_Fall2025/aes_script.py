#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_file_content(file_content):
    with open("secret_aes.key", "rb") as f:
        AES_KEY = f.read()
    
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pad_length = 16 - (len(file_content) % 16)
    padded_content = file_content + bytes([pad_length] * pad_length)
    ciphertext = cipher.encrypt(padded_content)
    return iv + ciphertext

def decrypt_file_content(encrypted_content):
    with open("secret_aes.key", "rb") as f:
        AES_KEY = f.read()
    
    iv = encrypted_content[:16]
    ciphertext = encrypted_content[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded_content = cipher.decrypt(ciphertext)
    pad_length = padded_content[-1]
    original_content = padded_content[:-pad_length]
    return original_content

def mod_pow(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

e = 17
d = 593
n = 899

print("=== Question 5: RSA + AES Hybrid Encryption ===")
print()

M = 82
print(f"Original message M: {M}")
print()

import random
random.seed(1128)
s = random.randint(1, n-1)
print(f"Step 1: Alice picks random number s: {s}")
print()

print("Step 2: RSA-like encryption to send s to Bob")
encrypted_s = mod_pow(s, e, n)
print(f"Alice encrypts s: {s}^{e} mod {n} = {encrypted_s}")
print(f"Alice sends encrypted s to Bob: {encrypted_s}")
print()

print("Step 3: Bob decrypts s using his private key")
decrypted_s = mod_pow(encrypted_s, d, n)
print(f"Bob decrypts: {encrypted_s}^{d} mod {n} = {decrypted_s}")
print(f"Verification: s = {s}, decrypted s = {decrypted_s}")
print(f"RSA step successful: {s == decrypted_s}")
print()

print("Step 4: Alice encrypts message M using AES with key s")
message_bytes = str(M).encode('utf-8')

try:
    with open("secret_aes.key", "rb") as f:
        original_key = f.read()
except:
    original_key = None

s_str = str(s)
s_key = (s_str * (32 // len(s_str) + 1))[:32].encode('utf-8')
with open("secret_aes.key", "wb") as f:
    f.write(s_key)

print(f"Chosen AES key (s): {s}")

aes_ciphertext = encrypt_file_content(message_bytes)
print(f"AES ciphertext: {aes_ciphertext.hex()}")
print()

print("Step 6: Bob decrypts with AES using shared key s")
decrypted_message_bytes = decrypt_file_content(aes_ciphertext)
decrypted_M = int(decrypted_message_bytes.decode('utf-8'))
print(f"Decrypted message M': {decrypted_M}")
print()

if original_key:
    with open("secret_aes.key", "wb") as f:
        f.write(original_key)

print("=== Final Results ===")
print(f"Original message M: {M}")
print(f"AES ciphertext: {aes_ciphertext.hex()}")
print(f"Decrypted message M': {decrypted_M}")
print(f"Success: M = M' ? {M == decrypted_M}")