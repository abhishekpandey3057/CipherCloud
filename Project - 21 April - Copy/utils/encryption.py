from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os

def generate_aes_key():
    return get_random_bytes(32)  # AES-256

def encrypt_file_aes(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(input_file, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(output_file, 'wb') as f:
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)

def decrypt_file_aes(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(output_file, 'wb') as f:
        f.write(data)

def load_rsa_public_key(filepath):
    with open(filepath, 'rb') as f:
        return RSA.import_key(f.read())

def load_rsa_private_key(filepath, passphrase=None):
    with open(filepath, 'rb') as f:
        return RSA.import_key(f.read(), passphrase=passphrase)

def encrypt_key_rsa(key_bytes, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(key_bytes)

def decrypt_key_rsa(encrypted_key_bytes, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_key_bytes)
