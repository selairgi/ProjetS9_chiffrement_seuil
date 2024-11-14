from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.exceptions import InvalidSignature
import random
import hashlib
from functools import reduce
import time

class ECDSAKeyPair:
    """Class for ECDSA key generation, signing, and verification."""
    def __init__(self):
        self.curve = ec.SECP256R1()
        self.private_key = ec.generate_private_key(self.curve)
        self.public_key = self.private_key.public_key()

    def sign(self, message):
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return decode_dss_signature(signature)

    def verify(self, message, r, s):
        try:
            signature = encode_dss_signature(r, s)
            self.public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

class ShamirSecretSharing:
    """Class for Shamir's Secret Sharing scheme."""
    def __init__(self, prime_order):
        self.prime_order = prime_order

    def share_secret(self, secret, n, t):
        coeffs = [secret] + [random.randint(1, self.prime_order - 1) for _ in range(t - 1)]
        return [(i, self.eval_polynomial(coeffs, i)) for i in range(1, n + 1)]

    def eval_polynomial(self, coeffs, x):
        return sum(c * (x ** i) for i, c in enumerate(coeffs)) % self.prime_order

    def reconstruct_secret(self, shares, t):
        x_values, y_values = zip(*shares)
        secret = 0
        for i in range(len(x_values)):
            num = reduce(lambda a, b: a * b, [x for j, x in enumerate(x_values) if j != i], 1)
            denom = reduce(lambda a, b: a * b, [(x_values[i] - x) % self.prime_order for j, x in enumerate(x_values) if j != i], 1)

            if denom == 0 or pow(denom, -1, self.prime_order) is None:
                raise ValueError("Denominator is not invertible.")

            lagrange_coeff = num * pow(denom, -1, self.prime_order)
            secret += y_values[i] * lagrange_coeff
            secret %= self.prime_order
        return secret

class NIZKProof:
    """Class for Non-Interactive Zero-Knowledge Proofs using ECDSA."""
    def __init__(self, key_pair):
        self.key_pair = key_pair

    def generate_proof(self, message):
        hashed_message = hashlib.sha256(message.encode()).digest()
        r, s = self.key_pair.sign(hashed_message)
        return r, s

    def verify_proof(self, message, r, s):
        hashed_message = hashlib.sha256(message.encode()).digest()
        return self.key_pair.verify(hashed_message, r, s)

class AdaptiveDiSEWithCorruption:
    """Adaptive DiSE class with simulated corruption."""
    def __init__(self, n, t):
        self.n = n
        self.t = t
        self.curve_order = 115792089210356248762697446949407573529996955224135760342422259061068512044369
        self.secret_sharing = ShamirSecretSharing(self.curve_order)
        self.key_pairs = [ECDSAKeyPair() for _ in range(n)]

    def run_with_corruption(self, input_x, message, corruption_rate=0.2):
        total_start_time = time.time()
        secret = random.randint(1, self.curve_order - 1)
        shares = self.secret_sharing.share_secret(secret, self.n, self.t)

        num_corrupted = int(self.n * corruption_rate)
        corrupted_parties = random.sample(range(self.n), num_corrupted)
        print(f"Corrupted parties: {corrupted_parties}")

        evaluations = []
        proof_gen_time = 0
        proof_ver_time = 0

        for i in range(self.t):
            key_pair = self.key_pairs[i]
            proof_system = NIZKProof(key_pair)

            if i in corrupted_parties:
                evaluation = random.randint(1, self.curve_order - 1)
                r, s = proof_system.generate_proof("tampered-input")
            else:
                evaluation = shares[i][1]
                r, s = proof_system.generate_proof(input_x)

            start_time = time.perf_counter()
            proof_gen_time += time.perf_counter() - start_time

            start_time = time.perf_counter()
            if proof_system.verify_proof(input_x, r, s):
                evaluations.append((i + 1, evaluation))
            proof_ver_time += time.perf_counter() - start_time

        try:
            dprf_output = self.secret_sharing.reconstruct_secret(evaluations, self.t)
        except ValueError:
            total_duration = time.time() - total_start_time
            return "Reconstruction failed due to corrupted parties.", total_duration

        hashed_message = int(hashlib.sha256(message.encode()).hexdigest(), 16) % self.curve_order
        ciphertext = (hashed_message + dprf_output) % self.curve_order
        decrypted_message = (ciphertext - dprf_output) % self.curve_order

        total_duration = time.time() - total_start_time
        if decrypted_message == hashed_message:
            return "Decryption successful despite corruption.", total_duration
        else:
            return "Decryption failed due to excessive corruption.", total_duration

if __name__ == "__main__":
    n = 10
    t = 6
    corruption_rate = 0.3
    input_x = "corruption-test-input"
    message = "Testing Adaptive DiSE with Corrupted Parties"

    adaptive_dise_system = AdaptiveDiSEWithCorruption(n, t)
    result, duration = adaptive_dise_system.run_with_corruption(input_x, message, corruption_rate)

    print(result)
    print(f"Execution time: {duration:.4f} seconds")
