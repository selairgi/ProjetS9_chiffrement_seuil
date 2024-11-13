#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: alex
"""

import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_part(private_key, part_data):
    signature = private_key.sign(
        part_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_part(public_key, part_data, signature):
    try:
        public_key.verify(
            signature,
            part_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Fonction d'interaction pour authentifier les nœuds
def challenge_response(private_key, public_key):
    # Génère un nombre aléatoire comme "challenge"
    challenge = random.randint(1, 1000000)
    # Le nœud répond en signant le challenge avec sa clé privée
    response = private_key.sign(
        challenge.to_bytes((challenge.bit_length() + 7) // 8, byteorder="big"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Vérification de la réponse par les autres nœuds
    try:
        public_key.verify(
            response,
            challenge.to_bytes((challenge.bit_length() + 7) // 8, byteorder="big"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Nœud authentifié avec succès.")
        return True
    except Exception:
        print("Échec de l'authentification du nœud.")
        return False


