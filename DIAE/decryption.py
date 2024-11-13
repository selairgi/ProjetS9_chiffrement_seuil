#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: alex
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

def decrypt_file(encrypted_file_path, key):
    decrypted_file_path = encrypted_file_path.replace('_encrypted.txt', '_decrypted.txt')

    with open(encrypted_file_path, 'rb') as encrypted_file:
        iv = encrypted_file.read(12)  # Lit IV
        file_data = encrypted_file.read()
        ciphertext, tag = file_data[:-16], file_data[-16:]

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        try:
            decrypted_content = decryptor.update(ciphertext) + decryptor.finalize()
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_content)
            print(f"Fichier déchiffré sauvegardé sous: {decrypted_file_path}")
            print(f"IV utilisé pour le déchiffrement: {iv.hex()}")
            print(f"Tag vérifié pendant le déchiffrement: {tag.hex()}")
        
        except InvalidTag:
            print("Erreur : le tag est invalide.")

