from master_key import MasterKey
from dist_enc import DistEnc
import random

class RobustDistEnc(DistEnc):
    def __init__(self, master_key, threshold, delta):
        super().__init__(master_key, threshold)
        self.delta = delta

    def select_robust_subset(self, active_servers):
        """
        Select a robust subset of servers to ensure robustness against delta-adversary.
        """
        t = self.threshold
        delta = self.delta
        n = len(active_servers)

        # Ensure there are enough servers to handle delta adversaries
        if n < (t + delta):
            raise ValueError(f"Not enough servers to achieve robustness for the given delta ({delta}). "
                             f"Required: at least {t + delta}, but got {n}.")

        # Select a random (t + delta)-subset of the active servers
        robust_subset = random.sample(active_servers, t + delta)
        return robust_subset

    def robust_encrypt(self, message, active_servers):
        """
        Perform robust encryption using a selected robust subset of servers.
        """
        print("Robust encryption started...")
        
        # Select a robust subset of servers
        robust_subset = self.select_robust_subset(active_servers)
        print(f"Robust subset selected for encryption: {robust_subset}")

        # Proceed with the encryption using the robust subset
        return self.encrypt(message, robust_subset)

    def robust_decrypt(self, ciphertext, iv, nonce, active_servers):
        """
        Perform robust decryption using a selected robust subset of servers.
        """
        print("Robust decryption started...")
        
        # Select a robust subset of servers
        robust_subset = self.select_robust_subset(active_servers)
        print(f"Robust subset selected for decryption: {robust_subset}")

        # Proceed with the decryption using the robust subset
        return self.decrypt(ciphertext, iv, nonce, robust_subset)

def main():
    n = 50
    t = 45
    delta = 5  # Number of adversaries the system should tolerate

    master_key = MasterKey()
    master_key.key_gen(n=n)

    # Robust Distributed Encryption system with threshold-based decryption
    robust_dist_enc = RobustDistEnc(master_key, threshold=t, delta=delta)
    message = b"Confidential data"

    # Select active parties for encryption and decryption
    parties = random.sample(range(n), t + delta)  # Choose t + delta unique parties from n
    print("Selected parties for encryption and decryption:", parties)

    # Attempt robust encryption
    try:
        ciphertext, iv, nonce = robust_dist_enc.robust_encrypt(message, active_servers=parties)
        print("Encrypted ciphertext:", ciphertext.hex())
    except ValueError as e:
        print("Error during encryption:", str(e))
        return
    parties_decrypt = random.sample(range(n), t + delta)
    # Attempt robust decryption
    try:
        decrypted_message = robust_dist_enc.robust_decrypt(ciphertext, iv, nonce, active_servers=parties_decrypt)
        print("Decrypted Message:", decrypted_message)
    except ValueError as e:
        print("Error during decryption:", str(e))

if __name__ == "__main__":
    main()
