from master_key import MasterKey
from dict_enc_threads import DistEncThreads
import random

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
