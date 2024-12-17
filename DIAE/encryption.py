#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: alex
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(file_path, key):
    iv = os.urandom(12)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()

    encrypted_file_path = file_path.replace('.txt', '_encrypted.txt')
    with open(file_path, 'rb') as f, open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv)  # identification du taf
        while chunk := f.read(1024):  # lecture par blocs
            encrypted_file.write(encryptor.update(chunk))
        encrypted_file.write(encryptor.finalize())
        encrypted_file.write(encryptor.tag)  # signale la fin du tag

    print(f"Fichier chiffré sauvegardé sous: {encrypted_file_path}")
    print(f"IV utilisé pour le chiffrement: {iv.hex()}")
    print(f"Tag généré pour l'intégrité: {encryptor.tag.hex()}")

