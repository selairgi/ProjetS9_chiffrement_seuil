import sys
import os

# Ajoutez le répertoire parent au chemin pour accéder aux modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encryption import encrypt_fragment, decrypt_fragment
from os import urandom

def test_encryption():
    # Fragment de données à chiffrer
    fragment = "Ceci est un fragment de données très important."
    print(f"Texte en clair : {fragment}")
    
    # Clé effective simulée (doit être générée via combine_prf_outputs dans dprf.py)
    effective_key = urandom(32)  # Clé simulée pour le test
    
    # Étape 1 : Chiffrement
    ciphertext = encrypt_fragment(effective_key, fragment)
    print(f"Texte chiffré : {ciphertext.hex()}")

    # Étape 2 : Déchiffrement
    decrypted_fragment = decrypt_fragment(effective_key, ciphertext)
    print(f"Fragment déchiffré : {decrypted_fragment}")

    # Validation
    assert fragment == decrypted_fragment, "Le fragment déchiffré ne correspond pas au fragment original."
    print("Test réussi : le fragment déchiffré correspond au fragment original.")

if __name__ == "__main__":
    test_encryption()
