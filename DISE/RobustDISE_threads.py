import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from DISE.master_key import MasterKey
from DISE.dist_enc import DistEnc
import random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


class RobustDistEnc(DistEnc):
    def __init__(self, master_key, threshold, delta):
        super().__init__(master_key, threshold)
        self.delta = delta

    def select_robust_subset(self, active_servers):
        """
        Select a robust subset of servers to ensure robustness against delta-adversary.
        """
        if len(active_servers) < (self.threshold + self.delta):
            raise ValueError(f"Not enough servers to achieve robustness. Required: {self.threshold + self.delta}, "
                             f"but got {len(active_servers)}.")
        return random.sample(active_servers, self.threshold + self.delta)

    def assign_partial_computations(self, robust_subset):
        """
        Assign partial computations to servers in a load-balancing manner.
        """
        assignments = {}
        for server in robust_subset:
            assigned_servers = random.sample(robust_subset, self.delta + 1)
            assignments[server] = assigned_servers
        return assignments

    def compute_prf_threaded(self, server, assigned_servers):
        """
        Compute PRF outputs for a server using multiple threads.
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

        # Step 1: Select a robust subset of servers
        robust_subset = self.select_robust_subset(parties)
        print(f"Robust subset selected for encryption: {robust_subset}")

        # Step 2: Assign computations to servers with redundancy
        assignments = self.assign_partial_computations(robust_subset)
        print(f"Assigned partial computations: {assignments}")

        # Step 3: Parallel computation of PRFs
        partial_results = {}
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.compute_prf_threaded, server, assigned_servers)
                       for server, assigned_servers in assignments.items()]
            for future in as_completed(futures):
                server, results = future.result()
                partial_results[server] = results

        # Step 4: Verify consistency of partial results for each server
        prf_parts = []
        for server, results in partial_results.items():
            most_common_result = max(set(results), key=results.count)
            if results.count(most_common_result) < (self.delta + 1):
                print(f"Warning: Inconsistent PRF results for server {server}. Proceeding with majority value.")
            prf_parts.append(most_common_result)

        # Step 5: Combine PRF parts to generate the encryption key
        combined_key = self.combine(prf_parts)
        print("Final encryption key derived:", combined_key.hex())

        # Step 6: Encrypt the message
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

        # Step 3: Parallel computation of PRFs
        partial_results = {}
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.compute_prf_threaded, server, assigned_servers)
                       for server, assigned_servers in assignments.items()]
            for future in as_completed(futures):
                server, results = future.result()
                partial_results[server] = results

        # Step 4: Verify consistency of partial results
        prf_parts = []
        for server, results in partial_results.items():
            most_common_result = max(set(results), key=results.count)
            if results.count(most_common_result) < (self.delta + 1):
                print(f"Warning: Inconsistent PRF results for server {server}. Proceeding with majority value.")
            prf_parts.append(most_common_result)

        # Step 5: Combine PRF parts to reconstruct the decryption key
        combined_key = self.combine(prf_parts)
        print("Final decryption key derived:", combined_key.hex())

        # Step 6: Decrypt the ciphertext
        cipher = AES.new(combined_key, AES.MODE_CBC, iv)
        decrypted_message = cipher.decrypt(ciphertext)
        try:
            return unpad(decrypted_message, AES.block_size).decode('utf-8')
        except ValueError:
            raise ValueError("Decryption failed: Padding error or corrupted data.")


# Example usage
def main():
    n = 15
    t = 10
    delta = 3

    master_key = MasterKey()
    master_key.key_gen(n=n)

    robust_dist_enc = RobustDistEnc(master_key, threshold=t, delta=delta)
    message = b"Confidential data"

    # Select active servers
    parties = random.sample(range(n), t + delta)
    print("Selected parties for encryption:", parties)

    # Encryption
    try:
        ciphertext, iv, robust_subset, assignments = robust_dist_enc.robust_encrypt(message, parties)
        print("Encrypted ciphertext:", ciphertext.hex())
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return

    # Decryption
    try:
        decrypted_message = robust_dist_enc.robust_decrypt(ciphertext, iv, robust_subset, assignments)
        print("Decrypted message:", decrypted_message)
    except Exception as e:
        print(f"Decryption error: {str(e)}")


if __name__ == "__main__":
    main()