import random
from hashlib import sha256
from typing import List, Tuple, Dict

# Cyclic Group Operations
class CyclicGroup:
    def __init__(self, prime: int, generator: int):
        self.p = prime
        self.g = generator

    def exp(self, base: int, exp: int) -> int:
        return pow(base, exp, self.p)

# Shamir's Secret Sharing
def shamir_secret_sharing(n: int, t: int, secret: int, prime: int) -> List[Tuple[int, int]]:
    coefficients = [secret] + [random.randint(1, prime - 1) for _ in range(t - 1)]
    shares = [(i, sum(c * (i ** e) for e, c in enumerate(coefficients)) % prime) for i in range(1, n + 1)]
    return shares

# Lagrange Interpolation
def lagrange_interpolation(x: int, points: List[Tuple[int, int]], prime: int) -> int:
    result = 0
    for i, (xi, yi) in enumerate(points):
        term = yi
        for j, (xj, _) in enumerate(points):
            if i != j:
                term *= (x - xj) * pow(xi - xj, -1, prime)
                term %= prime
        result += term
        result %= prime
    return result

# Adaptive DPRF
class AdaptiveDPRF:
    def __init__(self, group: CyclicGroup, n: int, t: int):
        self.group = group
        self.n = n
        self.t = t
        self.secret_u = random.randint(1, group.p - 1)
        self.secret_v = random.randint(1, group.p - 1)
        self.shares_u = shamir_secret_sharing(n, t, self.secret_u, group.p)
        self.shares_v = shamir_secret_sharing(n, t, self.secret_v, group.p)

    def eval(self, share_u: int, share_v: int, x: str) -> int:
        h1, h2 = self.hash_to_group(x)
        return (self.group.exp(h1, share_u) * self.group.exp(h2, share_v)) % self.group.p

    def combine(self, evaluations: List[Tuple[int, int]]) -> int:
        if len(evaluations) < self.t:
            return None  # Not enough shares
        return lagrange_interpolation(0, evaluations, self.group.p)

    def hash_to_group(self, x: str) -> Tuple[int, int]:
        hash_val = int(sha256(x.encode()).hexdigest(), 16) % self.group.p
        return (self.group.exp(self.group.g, hash_val), self.group.exp(self.group.g, hash_val + 1))

# Threshold Symmetric Encryption (TSE)
class ThresholdSymmetricEncryption:
    def __init__(self, group: CyclicGroup, dprf: AdaptiveDPRF):
        self.group = group
        self.dprf = dprf

    def encrypt(self, message: str, shares: List[Tuple[int, int]]) -> Tuple[int, int]:
        w = self.dprf.combine(shares)
        if w is None:
            raise ValueError("Not enough shares for encryption.")
        key = int(sha256(str(w).encode()).hexdigest(), 16)
        ciphertext = int(message.encode().hex(), 16) ^ key
        return ciphertext, w

    def decrypt(self, ciphertext: int, shares: List[Tuple[int, int]]) -> str:
        w = self.dprf.combine(shares)
        if w is None:
            raise ValueError("Not enough shares for decryption.")
        key = int(sha256(str(w).encode()).hexdigest(), 16)
        plaintext = ciphertext ^ key
        return bytes.fromhex(hex(plaintext)[2:]).decode()

if __name__ == "__main__":
    # Define a cyclic group (example parameters)
    prime = 104729  # Example large prime
    generator = 2   # Generator of the cyclic group
    group = CyclicGroup(prime, generator)

    # Setup DPRF
    n, t = 5, 3  # Total participants and threshold
    dprf = AdaptiveDPRF(group, n, t)
    tse = ThresholdSymmetricEncryption(group, dprf)

    # Encrypt a message
    message = "hello"
    shares = dprf.shares_u[:t]
    ciphertext, w = tse.encrypt(message, shares)
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the message
    decrypted_message = tse.decrypt(ciphertext, shares)
    print(f"Decrypted Message: {decrypted_message}")
