#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: alex
"""

import os
import random
import string

def clean_directory(directory_path):
    for filename in os.listdir(directory_path):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory_path, filename)
            os.remove(file_path)
            print(f"Deleted file: {file_path}")

def create_random_file(file_path, file_size_kb=1024):
    """
    Crée un fichier aléatoire de taille spécifiée.
    :param file_path: Chemin complet du fichier.
    :param file_size_kb: Taille du fichier en kilo-octets (par défaut 1024 KB).
    """
    with open(file_path, 'wb') as f:
        f.write(os.urandom(file_size_kb * 1024))  # Écrit des données aléatoires
    print(f"Fichier créé : {file_path} ({file_size_kb} KB)")
