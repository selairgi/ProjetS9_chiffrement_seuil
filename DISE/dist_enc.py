from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hmac
import hashlib
import secrets
import numpy as np

class DistEnc:
    def __init__(self, master_key, threshold):
        self.master_key = master_key
        self.threshold = threshold

    def encrypt(self, message, parties):
        print("Encryption started...")

        # 1. Generate a nonce
        nonce = get_random_bytes(16)
        print("Generated Nonce:", nonce.hex())

        # 2. Calculate the DPRF parts using each party's secret key
        prf_parts = []
        for party_index in parties:
            ski = self.master_key.keys[party_index]
            x = nonce  # Nonce is used as input to generate pseudo-random parts
            zi = self.pseudo_random_function(ski, x)
            print(f"Party {party_index} PRF output: {zi.hex()}")
            prf_parts.append(zi)

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

        # 1. Calculate the DPRF parts using the same nonce
        prf_parts = []
        for party_index in parties:
            ski = self.master_key.keys[party_index]
            x = nonce  # Nonce must be the same as during encryption
            zi = self.pseudo_random_function(ski, x)
            print(f"Party {party_index} PRF output for decryption: {zi.hex()}")
            prf_parts.append(zi)

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

    def pseudo_random_function(self, ski, x):
        # Calculate HMAC-SHA256 using the secret key and input data (x)
        hmac_key = hmac.new(ski, x, hashlib.sha256).digest()
        return hmac_key[:16]  # Take the first 16 bytes for AES-128

    def combine(self, prf_parts):
        # Combine the PRF parts using XOR to create the final key
        combined = np.bitwise_xor.reduce([int.from_bytes(part, 'big') for part in prf_parts])
        return combined.to_bytes(16, 'big')
