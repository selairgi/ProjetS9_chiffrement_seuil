#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: alex
"""

import os
from shamir_secret_sharing import generate_shares, reconstruct_secret
from node_authentication import generate_key_pair, sign_part, verify_part, challenge_response  # Assurez-vous d'inclure challenge_response ici
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Génère une clé symétrique AES
def generate_symmetric_key():
    key = os.urandom(32)
    print("Clé symétrique générée:", key.hex())
    return key

# Chiffre la clé symétrique
def generate_aes_key(symmetric_key):
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(symmetric_key) + encryptor.finalize()
    print("Clé AES utilisée pour chiffrer la clé symétrique:", aes_key.hex())
    print(f"IV: {iv.hex()}")
    print("Clé symétrique chiffrée:", ciphertext.hex())
    print(f"Tag généré: {encryptor.tag.hex()}")
    return aes_key, iv, ciphertext, encryptor.tag

# Partage de la clé en utilisant le schéma de seuil
def share_key_among_nodes_threshold(key, n, t):
    shares = generate_shares(key, t, n)
    nodes = []

    for i, share in enumerate(shares):
        private_key, public_key = generate_key_pair()
        signature = sign_part(private_key, share[1].to_bytes((share[1].bit_length() + 7) // 8, byteorder="big"))

        nodes.append({
            "node_id": i + 1,
            "share": share,
            "public_key": public_key,
            "private_key": private_key,
            "signature": signature
        })
        print(f"Noeud {i + 1}: Part de la clé : {share} avec signature {signature.hex()}")
    
    return nodes

# Reconstruit la clé avec vérification de signature et interaction
def reconstruct_key_from_shares_threshold(nodes, threshold):
    verified_shares = []

    for node in nodes[:threshold]:
        part_data = node["share"][1].to_bytes((node["share"][1].bit_length() + 7) // 8, byteorder="big")
        # Authentification mutuelle
        if challenge_response(node["private_key"], node["public_key"]):
            # Vérification des signatures
            if verify_part(node["public_key"], part_data, node["signature"]):
                print(f"Signature vérifiée pour le noeud {node['node_id']}")
                verified_shares.append(node["share"])
            else:
                print(f"Signature invalide pour le noeud {node['node_id']}")
        else:
            print(f"Échec de l'authentification du noeud {node['node_id']}")

    if len(verified_shares) >= threshold:
        reconstructed_key = reconstruct_secret(verified_shares, threshold)
        print("\nClé AES reconstituée:", reconstructed_key.hex())
        return reconstructed_key
    else:
        print("Impossible de reconstruire la clé - certaines signatures sont invalides.")
        return None
  





