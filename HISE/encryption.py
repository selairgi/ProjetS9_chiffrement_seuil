from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom

# ==========================================
# 1. Chiffrement d'un Fragment
# ==========================================

def encrypt_fragment(key, fragment):
    """
    Chiffre un fragment de données à l'aide d'une clé donnée en utilisant AES en mode CFB.

    Arguments :
    - key : Clé effective pour le chiffrement (bytes).
    - fragment : Fragment de données à chiffrer (string).

    Retour :
    - ciphertext : Texte chiffré concaténé avec le vecteur d'initialisation (IV) (bytes).
    """
    iv = urandom(16)  # Génère un vecteur d'initialisation aléatoire
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(fragment.encode()) + encryptor.finalize()
    return iv + ciphertext  # Retourne le texte chiffré avec l'IV

# ==========================================
# 2. Déchiffrement d'un Fragment
# ==========================================

def decrypt_fragment(key, ciphertext):
    """
    Déchiffre un fragment de données à l'aide d'une clé donnée et de l'IV contenu dans le texte chiffré.

    Arguments :
    - key : Clé effective pour le déchiffrement (bytes).
    - ciphertext : Texte chiffré concaténé avec l'IV (bytes).

    Retour :
    - fragment : Fragment de données déchiffré (string).
    """
    iv = ciphertext[:16]  # Extraire l'IV (les 16 premiers octets)
    encrypted_data = ciphertext[16:]  # Le reste est le texte chiffré
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_fragment = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_fragment.decode()
