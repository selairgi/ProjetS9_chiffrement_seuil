from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import secrets
from itertools import combinations

class DistEnc:
    def __init__(self, master_key, threshold):
        self.master_key = master_key
        self.threshold = threshold

    def encrypt(self, message, parties):
        print("Encryption started...")

        # 1. Generate a unique session key
        session_key = secrets.token_bytes(16)
        iv = get_random_bytes(16)
        
        # 2. Encrypt the message with the session key
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        padded_message = pad(message, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)

        # 3. Split the session key into shares
        shares = self.master_key.split_key(session_key, len(parties), self.threshold)

        encrypted_shares = [(shares[i], iv) for i in range(len(parties))]
        print("Encryption completed.")
        return ciphertext, encrypted_shares

    def decrypt(self, ciphertext, encrypted_shares):
        print("Decryption started...")

        # Check if we have enough shares
        if len(encrypted_shares) < self.threshold:
            raise ValueError("Insufficient shares to decrypt the message")

        # 1. Reconstruct the session key from shares
        shares_to_use = [share[0] for share in encrypted_shares[:self.threshold]]
        for share in shares_to_use:
            print(f"Using share: x = {share[0]}, y = {share[1].hex()}")
        
        session_key = self.master_key.reconstruct_key(shares_to_use)

        # 2. Debug: print the session key
        print("Reconstructed session key:", session_key.hex())

        # 3. Decrypt the ciphertext with the session key
        iv = encrypted_shares[0][1]
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted_message = cipher.decrypt(ciphertext)

        try:
            # Unpad the message
            unpadded_message = unpad(decrypted_message, AES.block_size)
            print("Decrypted message after unpadding (raw bytes):", unpadded_message)

            # Attempt to decode the message to text
            decoded_message = unpadded_message.decode('utf-8')
            print("Decoded message (UTF-8):", decoded_message)
            return decoded_message
        except ValueError as e:
            print("Padding error during unpadding. Ensure keys and message integrity.")
            raise e

