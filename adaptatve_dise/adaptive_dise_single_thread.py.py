# Single-threaded Adaptive DiSE Implementation with Performance Tests
import random
import time
from hashlib import sha256
from functools import reduce
import os
import matplotlib.pyplot as plt

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

# Test File Generation and Encryption Timing
def generate_file(filename, size_kb):
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_kb * 1024))

def encrypt_file(filename, tse):
    with open(filename, 'rb') as f:
        content = f.read()
    parties = list(range(1, tse.dprf.threshold + 1))  # Adaptive party selection
    start_time = time.perf_counter()
    ciphertext = tse.encrypt(content.hex(), parties)
    end_time = time.perf_counter()
    return ciphertext, end_time - start_time

def decrypt_file(ciphertext, tse):
    parties = list(range(1, tse.dprf.threshold + 1))  # Adaptive party selection
    start_time = time.perf_counter()
    plaintext = tse.decrypt(ciphertext, parties)
    end_time = time.perf_counter()
    return plaintext, end_time - start_time

# Performance Test with Varying File Sizes
def performance_test():
    prime = 7919  # A prime number for modular arithmetic
    generator = 2  # A generator of the group

    tse = AdaptiveTSE(prime, generator)
    tse.setup(5, 3)  # Initial setup with 5 parties, threshold 3

    file_sizes = [1, 10, 100, 1000]  # File sizes in KB
    encryption_times = []
    decryption_times = []

    for size in file_sizes:
        test_filename = f"test_file_{size}KB.bin"
        generate_file(test_filename, size)

        # Measure encryption time
        ciphertext, encryption_time = encrypt_file(test_filename, tse)
        encryption_times.append(encryption_time)

        # Measure decryption time
        _, decryption_time = decrypt_file(ciphertext, tse)
        decryption_times.append(decryption_time)

        print(f"File Size: {size} KB, Encryption Time: {encryption_time:.6f} s, Decryption Time: {decryption_time:.6f} s")

    # Plot results
    plt.figure(figsize=(10, 6))
    plt.plot(file_sizes, encryption_times, marker='o', label='Encryption Time')
    plt.plot(file_sizes, decryption_times, marker='s', label='Decryption Time')
    plt.xscale('log')
    plt.yscale('log')
    plt.xlabel('File Size (KB)')
    plt.ylabel('Time (s)')
    plt.title('Performance of Encryption and Decryption (Single-threaded)')
    plt.legend()
    plt.grid(True)
    plt.show()

# Run Performance Test
if __name__ == "__main__":
    performance_test()
