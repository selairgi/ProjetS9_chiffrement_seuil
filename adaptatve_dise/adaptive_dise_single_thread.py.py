# Single-threaded Adaptive DiSE Implementation with Performance Tests
import random
import time
from hashlib import sha256
from functools import reduce
import os
import matplotlib.pyplot as plt
import pandas as pd

# Helper functions
def modular_exp(base, exp, mod):
    return pow(base, exp, mod)

def hash_to_group(value, prime):
    hashed = int(sha256(value.encode()).hexdigest(), 16)
    return hashed % prime

# Secret sharing: Shamir's Secret Sharing
class ShamirSecretSharing:
    def __init__(self, prime):
        self.prime = prime

    def split(self, secret, n, t):
        coefficients = [secret] + [random.randint(0, self.prime - 1) for _ in range(t - 1)]
        shares = [(i, self._evaluate_polynomial(coefficients, i)) for i in range(1, n + 1)]
        return shares

    def _evaluate_polynomial(self, coefficients, x):
        result = 0
        for i, coeff in enumerate(coefficients):
            result += coeff * (x ** i)
            result %= self.prime
        return result

# Commitment Scheme
class Commitment:
    def __init__(self, generator, prime):
        self.generator = generator
        self.prime = prime

    def commit(self, value):
        r = random.randint(1, self.prime - 1)
        commitment = (pow(self.generator, value, self.prime), pow(self.generator, r, self.prime))
        return commitment, r

# NIZK Proof for Commitment Correctness
class NIZK:
    def __init__(self, generator, prime):
        self.generator = generator
        self.prime = prime

    def prove(self, commitment, value, randomness):
        t = random.randint(1, self.prime - 1)
        t_commit = pow(self.generator, t, self.prime)
        challenge = hash_to_group(f"{commitment[0]}|{commitment[1]}|{t_commit}", self.prime)
        response = (t + challenge * value) % self.prime
        return t_commit, response

    def verify(self, commitment, proof):
        t_commit, response = proof
        challenge = hash_to_group(f"{commitment[0]}|{commitment[1]}|{t_commit}", self.prime)
        return pow(self.generator, response, self.prime) == (t_commit * pow(commitment[0], challenge, self.prime)) % self.prime

# Distributed Pseudo-Random Function (DPRF)
class AdaptiveDPRF:
    def __init__(self, prime, generator):
        self.prime = prime
        self.generator = generator
        self.party_keys = {}

    def setup(self, n, t):
        self.threshold = t
        sharing = ShamirSecretSharing(self.prime)
        secret_u = random.randint(1, self.prime - 1)
        secret_v = random.randint(1, self.prime - 1)
        shares_u = sharing.split(secret_u, n, t)
        shares_v = sharing.split(secret_v, n, t)
        for i in range(1, n + 1):
            self.party_keys[i] = {'u': shares_u[i - 1][1], 'v': shares_v[i - 1][1]}

    def evaluate(self, party_id, x):
        w1, w2 = self.hash_to_group(str(x))  # Convert to string
        key = self.party_keys[party_id]
        return pow(w1, key['u'], self.prime) * pow(w2, key['v'], self.prime) % self.prime

    def hash_to_group(self, x):
        h1 = int(sha256((x + "1").encode()).hexdigest(), 16) % self.prime
        h2 = int(sha256((x + "2").encode()).hexdigest(), 16) % self.prime
        return h1, h2

# Threshold Symmetric-key Encryption (TSE)
class AdaptiveTSE:
    def __init__(self, prime, generator):
        self.prime = prime
        self.generator = generator
        self.dprf = AdaptiveDPRF(prime, generator)
        self.commitments = {}
        self.nizk = NIZK(generator, prime)

    def setup(self, n, t):
        self.dprf.setup(n, t)
        self.generate_commitments()

    def update_setup(self, n, t):
        print(f"Updating setup with {n} parties and threshold {t}")
        self.setup(n, t)

    def generate_commitments(self):
        commitment = Commitment(self.generator, self.prime)
        for party_id, keys in self.dprf.party_keys.items():
            u_commit, u_random = commitment.commit(keys['u'])
            v_commit, v_random = commitment.commit(keys['v'])
            self.commitments[party_id] = {
                'u': (u_commit, u_random),
                'v': (v_commit, v_random)
            }

    def encrypt(self, message, parties):
        h = hash_to_group(message, self.prime)
        partials = [
            self.dprf.evaluate(party_id, message) for party_id in parties
        ]
        return reduce(lambda x, y: x * y % self.prime, partials, 1)

    def decrypt(self, ciphertext, parties):
        partials = [self.dprf.evaluate(party_id, str(ciphertext)) for party_id in parties]  # Convert to string
        return reduce(lambda x, y: x * y % self.prime, partials, 1)

# Test File Generation and Stress Test
def generate_file(filename, size_kb):
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_kb * 1024))

def stress_test():
    prime = 7919  # A prime number for modular arithmetic
    generator = 2  # A generator of the group

    tse = AdaptiveTSE(prime, generator)

    # Configurations for (n, t)
    configurations = [
        (8, 4), (12, 4), (24, 8), (40, 10)
    ]
    batch_sizes = [50, 100, 200, 400]  # Batch sizes in messages

    encryption_results = []
    decryption_results = []

    for n, t in configurations:
        tse.setup(n, t)
        parties = list(range(1, t + 1))  # Adaptive party selection

        for batch_size in batch_sizes:
            # Encryption Test
            start_time = time.time()
            batches = 0
            while time.time() - start_time < 60:  # Run for 60 seconds
                message = os.urandom(batch_size).hex()
                tse.encrypt(message, parties)
                batches += 1

            # Calculate encryption metrics
            batches_per_minute = batches
            messages_per_minute = batches * batch_size
            throughput = messages_per_minute / 60

            encryption_results.append((n, t, batch_size, batches_per_minute, messages_per_minute, throughput))

            # Decryption Test
            ciphertext = tse.encrypt(os.urandom(batch_size).hex(), parties)
            start_time = time.time()
            batches = 0
            while time.time() - start_time < 60:  # Run for 60 seconds
                tse.decrypt(ciphertext, parties)
                batches += 1

            # Calculate decryption metrics
            batches_per_minute = batches
            messages_per_minute = batches * batch_size
            throughput = messages_per_minute / 60

            decryption_results.append((n, t, batch_size, batches_per_minute, messages_per_minute, throughput))

    # Print results
    print("Encryption Results:")
    print("n\tt\tBatch Size\tBatches/min\tMsg/min\tThroughput (msg/s)")
    for result in encryption_results:
        print("\t".join(map(str, result)))

    print("\nDecryption Results:")
    print("n\tt\tBatch Size\tBatches/min\tMsg/min\tThroughput (msg/s)")
    for result in decryption_results:
        print("\t".join(map(str, result)))

    # Plot the results
    plt.figure(figsize=(12, 8))
    for (n, t) in configurations:
        subset = [res for res in encryption_results if res[0] == n and res[1] == t]
        plt.plot([res[2] for res in subset], [res[5] for res in subset], marker='o', label=f"Encryption n={n}, t={t}")

    for (n, t) in configurations:
        subset = [res for res in decryption_results if res[0] == n and res[1] == t]
        plt.plot([res[2] for res in subset], [res[5] for res in subset], marker='x', linestyle='--', label=f"Decryption n={n}, t={t}")

    plt.xscale('log')
    plt.yscale('log')
    plt.xlabel('Batch Size')
    plt.ylabel('Throughput (msg/s)')
    plt.title('Throughput vs Batch Size for Encryption and Decryption (Single-threaded)')
    plt.legend()
    plt.grid(True)
    plt.show()

# Run Stress Test
if __name__ == "__main__":
    stress_test()
