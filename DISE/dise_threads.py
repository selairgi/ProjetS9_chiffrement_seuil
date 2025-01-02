import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hmac
import hashlib
import numpy as np
import random
from concurrent.futures import ThreadPoolExecutor

class DistEncThreads:
    def __init__(self, master_key, threshold):
        self.master_key = master_key
        self.threshold = threshold

    def encrypt(self, message, parties):
        print("Encryption started...")

        # 1. Generate a nonce
        nonce = get_random_bytes(16)
        print("Generated Nonce:", nonce.hex())

        # 2. Calculate the DPRF parts using threads
        with ThreadPoolExecutor() as executor:
            prf_parts = list(executor.map(lambda idx: self.compute_prf(idx, nonce), parties))

        # 3. Combine the PRF parts to generate the encryption key
        combined_key = self.combine(prf_parts)
        print("Final encryption key derived with KDF:", combined_key.hex())

        # 4. Encrypt the message using the combined key
        iv = get_random_bytes(16)
        cipher = AES.new(combined_key, AES.MODE_CBC, iv)
        padded_message = pad(message, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)

        print("Encryption completed.")
        return ciphertext, iv, nonce

    def decrypt(self, ciphertext, iv, nonce, parties):
        print("Decryption started...")

        # 1. Calculate the DPRF parts using threads
        with ThreadPoolExecutor() as executor:
            prf_parts = list(executor.map(lambda idx: self.compute_prf(idx, nonce), parties))

        # 2. Combine the PRF parts to reconstruct the decryption key
        combined_key = self.combine(prf_parts)
        print("Final decryption key derived with KDF:", combined_key.hex())

        # 3. Decrypt the ciphertext using the combined key
        cipher = AES.new(combined_key, AES.MODE_CBC, iv)
        decrypted_message = cipher.decrypt(ciphertext)

        try:
            # Unpad the message
            unpadded_message = unpad(decrypted_message, AES.block_size)
            print("Decrypted message after unpadding (raw bytes):", unpadded_message)
            return unpadded_message.decode('utf-8')
        except ValueError as e:
            print("Padding error during unpadding. Ensure keys and message integrity.")
            raise e

    def compute_prf(self, party_index, x):
        ski = self.master_key.keys[party_index]
        zi = self.pseudo_random_function(ski, x)
        print(f"Party {party_index} PRF output: {zi.hex()}")
        return zi

    def pseudo_random_function(self, ski, x):
        # Calculate HMAC-SHA256 using the secret key and input data (x)
        hmac_key = hmac.new(ski, x, hashlib.sha256).digest()
        return hmac_key[:16]  # Take the first 16 bytes for AES-128

    def combine(self, prf_parts):
        # Combine the PRF parts using XOR to create the final key
        combined = np.bitwise_xor.reduce([int.from_bytes(part, 'big') for part in prf_parts])
        return combined.to_bytes(16, 'big')

class MasterKey:
    def __init__(self):
        self.keys = []  # Les clés secrètes des différentes parties

    def key_gen(self, n):
        # Générer 'n' clés secrètes (16 bytes chacun pour la compatibilité avec AES-128)
        self.keys = [secrets.token_bytes(16) for _ in range(n)]
        print(f"Generated {n} secret keys:")
        for i, key in enumerate(self.keys):
            print(f"Party {i}: Key = {key.hex()}")

def main():
    # Setup for 5 parties with a threshold of 3
    n = 10
    m = 7
    master_key = MasterKey()
    master_key.key_gen(n=n)

    # Distributed Encryption system with threshold-based decryption
    dist_enc = DistEncThreads(master_key, threshold=m)
    message = b"Confidential data"

    # Encrypt using at least m parties, randomly selected from n
    parties = random.sample(range(n), m)  # Choose m unique parties from n
    print("Selected parties for encryption and decryption:", parties)

    # Encrypt the message
    ciphertext, iv, nonce = dist_enc.encrypt(message, parties=parties)
    print("Encrypted ciphertext:", ciphertext.hex())

    # Attempt to decrypt (must have at least m shares for decryption)
    try:
        decrypted_message = dist_enc.decrypt(ciphertext, iv, nonce, parties)
        print("Decrypted Message:", decrypted_message)
    except ValueError as e:
        print("Error:", str(e))

if __name__ == "__main__":
    main()
