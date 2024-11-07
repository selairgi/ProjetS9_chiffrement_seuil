from master_key import MasterKey
from dist_enc import DistEnc

def main():
    # Setup for 10 parties with a threshold of 7
    n = 100
    m = n-1
    master_key = MasterKey()
    master_key.key_gen(n=n, m=m)

    # Distributed Encryption system with threshold-based decryption
    dist_enc = DistEnc(master_key, threshold=m)
    message = b"Confidential data"

    # Encrypt using at least 7 parties
    parties = list(i for i in range(m))
    ciphertext, encrypted_shares = dist_enc.encrypt(message, parties=parties)
    print("Encrypted shares:", encrypted_shares)

    # Attempt to decrypt (must have at least m shares for decryption)
    try:
        decrypted_message = dist_enc.decrypt(ciphertext, encrypted_shares)
        print("Decrypted Message:", decrypted_message)
    except ValueError as e:
        print("Error:", str(e))

if __name__ == "__main__":
    main()

