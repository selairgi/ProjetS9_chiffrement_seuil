from master_key import MasterKey
from dist_enc import DistEnc
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
        n = len(active_servers)

        # Ensure there are enough servers to handle delta adversaries
        if n < (t + delta):
            raise ValueError(f"Not enough servers to achieve robustness for the given delta ({delta}). "
                             f"Required: at least {t + delta}, but got {n}.")

        # Select a random (t + delta)-subset of the active servers
        robust_subset = random.sample(active_servers, t + delta)
        return robust_subset

    def assign_partial_computations(self, robust_subset):
        """
        Assign partial computations to servers in a load-balancing manner.
        """
        assignments = {}
        for i, server in enumerate(robust_subset):
            assigned_servers = random.sample(robust_subset, self.delta + 1)
            assignments[server] = assigned_servers
        return assignments

    def robust_encrypt(self, message, parties):
        """
        Perform robust encryption using a selected robust subset of servers.
        """
        print("Robust encryption started...")

        # Step 1: Select a robust subset of servers
        robust_subset = self.select_robust_subset(parties)
        print(f"Robust subset selected for encryption: {robust_subset}")

        # Step 2: Assign computations to servers with redundancy
        assignments = self.assign_partial_computations(robust_subset)
        print(f"Assigned partial computations: {assignments}")

        # Step 3: Each server calculates its partial result and sends back to the initiator
        partial_results = {}
        for server, assigned_servers in assignments.items():
            partial_results[server] = []
            for assigned_server in assigned_servers:
                ski = self.master_key.keys[assigned_server]
                zi = self.pseudo_random_function(ski, server.to_bytes(16, 'big'))  # Use server index as input
                partial_results[server].append(zi)
                print(f"Server {assigned_server} PRF output: {zi.hex()}")

        # Step 4: Verify consistency of partial results for each wi
        prf_parts = []
        for server, results in partial_results.items():
            # Check if at least (delta + 1) results are consistent
            results_counter = {}
            for res in results:
                if res in results_counter:
                    results_counter[res] += 1
                else:
                    results_counter[res] = 1

            most_common_result = max(results_counter, key=results_counter.get)
            if results_counter[most_common_result] < (self.delta + 1):
                print(f"Warning: Inconsistent partial results detected for server {server}. Proceeding with majority value.")
            prf_parts.append(most_common_result)

        # Step 5: Combine the PRF parts to generate the encryption key
        combined_key = self.combine(prf_parts)
        print("Final encryption key derived with KDF:", combined_key.hex())

        # Step 6: Encrypt the message using the combined key
        iv = get_random_bytes(16)
        cipher = AES.new(combined_key, AES.MODE_CBC, iv)
        padded_message = pad(message, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)

        print("Encryption completed.")
        return ciphertext, iv, robust_subset, assignments

    def robust_decrypt(self, ciphertext, iv, robust_subset, assignments):
        """
        Perform robust decryption using a selected robust subset of servers.
        """
        print("Robust decryption started...")

        print(f"Robust subset used for decryption: {robust_subset}")
        print(f"Assignments used for decryption: {assignments}")

        # Step 3: Each server calculates its partial result and sends back to the initiator
        partial_results = {}
        for server, assigned_servers in assignments.items():
            partial_results[server] = []
            for assigned_server in assigned_servers:
                ski = self.master_key.keys[assigned_server]
                zi = self.pseudo_random_function(ski, server.to_bytes(16, 'big'))  # Use server index as input
                partial_results[server].append(zi)
                print(f"Server {assigned_server} PRF output for decryption: {zi.hex()}")

        # Step 4: Verify consistency of partial results for each wi
        prf_parts = []
        for server, results in partial_results.items():
            # Check if at least (delta + 1) results are consistent
            results_counter = {}
            for res in results:
                if res in results_counter:
                    results_counter[res] += 1
                else:
                    results_counter[res] = 1

            most_common_result = max(results_counter, key=results_counter.get)
            if results_counter[most_common_result] < (self.delta + 1):
                print(f"Warning: Inconsistent partial results detected for server {server}. Proceeding with majority value.")
            prf_parts.append(most_common_result)

        # Step 5: Combine the PRF parts to reconstruct the decryption key
        combined_key = self.combine(prf_parts)
        print("Final decryption key derived with KDF:", combined_key.hex())

        # Step 6: Decrypt the ciphertext using the combined key
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

# Example usage
def main():
    n = 50
    t = 40
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
        ciphertext, iv, robust_subset, assignments = robust_dist_enc.robust_encrypt(message, parties)
        print("Encrypted ciphertext:", ciphertext.hex())
    except ValueError as e:
        print("Error during encryption:", str(e))
        return

    # Attempt robust decryption
    try:
        decrypted_message = robust_dist_enc.robust_decrypt(ciphertext, iv, robust_subset, assignments)
        print("Decrypted Message:", decrypted_message)
    except ValueError as e:
        print("Error during decryption:", str(e))

if __name__ == "__main__":
    main()
