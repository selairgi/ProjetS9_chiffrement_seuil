#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: alex
"""

import tracemalloc
from file_operations import clean_directory, create_random_file
from key_management import generate_symmetric_key, generate_aes_key, share_key_among_nodes_threshold, reconstruct_key_from_shares_threshold
from encryption import encrypt_file
from decryption import decrypt_file
from memory_tracking import display_memory_usage

# Définition des paramètres
directory_path = '/home/alex/Desktop/T3/Projet S9/DIAE/'
file_path = directory_path + 'texte.txt'
n = 8  # Nombre total de nœuds
t = 5  # Seuil de nœuds requis pour reconstruire la clé

# Nettoyage du répertoire et création d'un fichier aléatoire
clean_directory(directory_path)
create_random_file(file_path)

# Génération des clés et partage de la clé AES avec un schéma de seuil
symmetric_key = generate_symmetric_key()
aes_key, iv, ciphertext, tag = generate_aes_key(symmetric_key)
nodes = share_key_among_nodes_threshold(aes_key, n, t)

# Reconstruire la clé en vérifiant les signatures des parts
reconstructed_key = reconstruct_key_from_shares_threshold(nodes, t)

# Si la clé a été reconstruite, effectuer le chiffrement et déchiffrement
if reconstructed_key:
    tracemalloc.start()
    encrypt_file(file_path, reconstructed_key)
    decrypt_file(file_path.replace('.txt', '_encrypted.txt'), reconstructed_key)
    display_memory_usage()
    tracemalloc.stop()



