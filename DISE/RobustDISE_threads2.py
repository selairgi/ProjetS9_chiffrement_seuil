from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from DISE.master_key import MasterKey
from DISE.dist_enc import DistEnc
import random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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
        if len(active_servers) < (t + delta):
            raise ValueError(f"Not enough servers to achieve robustness for delta ({delta}). "
                             f"Required: {t + delta}, but got {len(active_servers)}.")
        return random.sample(active_servers, t + delta)

    def compute_prf_parallel(self, server, assigned_servers):
        """
        Compute PRF for a server in parallel threads.
        """
        prf_results = []
        for assigned_server in assigned_servers:
            ski = self.master_key.keys[assigned_server]
            zi = self.pseudo_random_function(ski, server.to_bytes(16, 'big'))
            prf_results.append(zi)
        return server, prf_results

    def robust_encrypt(self, message, parties):
        """
        Perform robust encryption using multithreading for partial computations.
        """
        print("Robust encryption started...")
        robust_subset = self.select_robust_subset(parties)
        print(f"Robust subset selected: {robust_subset}")

        assignments = {server: random.sample(robust_subset, self.delta + 1) for server in robust_subset}

        partial_results = {}
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.compute_prf_parallel, server, assigned_servers)
                       for server, assigned_servers in assignments.items()]
            for future in as_completed(futures):
                server, results = future.result()
                partial_results[server] = results

        prf_parts = []
        for server, results in partial_results.items():
            most_common_result = max(set(results), key=results.count)
            prf_parts.append(most_common_result)

        combined_key = self.combine(prf_parts)
        iv = get_random_bytes(16)
        cipher = AES.new(combined_key, AES.MODE_CBC, iv)
        padded_message = pad(message, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)

        print("Encryption completed.")
        return ciphertext, iv, robust_subset, assignments

    def robust_decrypt(self, ciphertext, iv, robust_subset, assignments):
        """
        Perform robust decryption using multithreading for partial computations.
        """
        print("Robust decryption started...")

        partial_results = {}
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.compute_prf_parallel, server, assigned_servers)
                       for server, assigned_servers in assignments.items()]
            for future in as_completed(futures):
                server, results = future.result()
                partial_results[server] = results

        prf_parts = []
        for server, results in partial_results.items():
            most_common_result = max(set(results), key=results.count)
            prf_parts.append(most_common_result)

        combined_key = self.combine(prf_parts)
        cipher = AES.new(combined_key, AES.MODE_CBC, iv)
        decrypted_message = cipher.decrypt(ciphertext)

        try:
            return unpad(decrypted_message, AES.block_size).decode('utf-8')
        except ValueError as e:
            raise ValueError("Decryption failed due to padding error.") from e

# Test principal
def main():
    n = 15
    t = 10
    delta = 3
    master_key = MasterKey()
    master_key.key_gen(n=n)

    robust_dist_enc = RobustDistEnc(master_key, threshold=t, delta=delta)
    message = b"Confidential data"
    parties = random.sample(range(n), t + delta)

    print("Selected parties:", parties)

    try:
        ciphertext, iv, robust_subset, assignments = robust_dist_enc.robust_encrypt(message, parties)
        print("Ciphertext:", ciphertext.hex())
    except Exception as e:
        print("Encryption error:", str(e))

    try:
        decrypted_message = robust_dist_enc.robust_decrypt(ciphertext, iv, robust_subset, assignments)
        print("Decrypted message:", decrypted_message)
    except Exception as e:
        print("Decryption error:", str(e))

if __name__ == "__main__":
    main()
