from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

class DPRF:
    def __init__(self, master_key):
        self.master_key = master_key

    def compute_share(self, party_index, message):
        """
        Computes a pseudo-random share for a given party.
        """
        keys_for_party = self.master_key.key_structure[party_index]
        shares = []

        # Utilisation d'un IV unique pour chaque chiffrement
        for key_index in keys_for_party:
            key = self.master_key.keys[key_index]
            iv = os.urandom(AES.block_size)  # Générer un IV unique pour chaque part
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_message = cipher.encrypt(pad(message, AES.block_size))
            shares.append((encrypted_message, iv))  # Stocker l'IV pour la décryption
            print(f"Party {party_index} share (key index {key_index}): {encrypted_message.hex()}, IV: {iv.hex()}")  # Debugging

        return shares

