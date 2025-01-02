from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hmac
import hashlib
import numpy as np
from concurrent.futures import ThreadPoolExecutor

class DistEncThreads:
    def __init__(self, master_key, threshold):
        self.master_key = master_key
        self.threshold = threshold

    def compute_prf_for_party(self, ski, nonce):
        return self.pseudo_random_function(ski, nonce)

    def encrypt(self, message, parties):
        print("Encryption started...")

        # 1. Generate a nonce
        nonce = get_random_bytes(16)
        print("Generated Nonce:", nonce.hex())

        # 2. Calculate the DPRF parts using threads
        prf_parts = []
        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(self.compute_prf_for_party, self.master_key.keys[party_index], nonce): party_index for party_index in parties}
            for future in futures:
                zi = future.result()
                prf_parts.append(zi)
                print(f"Party {futures[future]} PRF output: {zi.hex()}")

        # 3. Combine the PRF parts to generate the encryption key using threads
        combined_key = self.combine_with_threads(prf_parts)
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
        prf_parts = []
        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(self.compute_prf_for_party, self.master_key.keys[party_index], nonce): party_index for party_index in parties}
            for future in futures:
                zi = future.result()
                prf_parts.append(zi)
                print(f"Party {futures[future]} PRF output for decryption: {zi.hex()}")

        # 2. Combine the PRF parts to reconstruct the decryption key using threads
        combined_key = self.combine_with_threads(prf_parts)
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

    def combine_with_threads(self, prf_parts):
        # Combine the PRF parts using XOR with threads
        def xor_pairwise(parts):
            combined = int.from_bytes(parts[0], 'big') ^ int.from_bytes(parts[1], 'big')
            return combined.to_bytes(16, 'big')

        with ThreadPoolExecutor() as executor:
            while len(prf_parts) > 1:
                pairs = [(prf_parts[i], prf_parts[i + 1]) for i in range(0, len(prf_parts) - 1, 2)]
                futures = [executor.submit(xor_pairwise, pair) for pair in pairs]
                prf_parts = [future.result() for future in futures]
        return prf_parts[0]