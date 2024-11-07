import secrets
from itertools import combinations
import numpy as np
import math
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from secrets import token_bytes
import random

class MasterKey:
    def __init__(self):
        self.keys = []

    def key_gen(self, n, m):
        subset_size = n - m + 1
        d = int(math.comb(n, subset_size))  # Number of sub-keys needed

        # Generate random sub-keys (16 bytes each for AES-128 compatibility)
        self.keys = [secrets.token_bytes(16) for _ in range(d)]
        print(f"Generated {d} sub-keys for threshold-based encryption.")
          # Debug

    def split_key(self, secret, n, threshold):
        """
        Splits the key into `n` shares with a threshold of `threshold`
        using Shamir's Secret Sharing.
        """
        if len(secret) != 16:
            raise ValueError("Secret must be 16 bytes long.")

        # Convert secret to an integer
        secret_int = int.from_bytes(secret, 'big')

        # Use a large prime modulus for Shamir's Secret Sharing
        prime_modulus = 2**128 -159  # A large Mersenne prime for safety

        # Generate coefficients for the polynomial
        coefficients = [secret_int] + [random.randint(0, prime_modulus - 1) for _ in range(threshold - 1)]

        # Generate shares (x, y), keeping y within the modulus to prevent overflow
        shares = []
        for i in range(1, n + 1):
            x = i
            y = self.evaluate_polynomial(coefficients, x) % prime_modulus  # Ensure y is within prime modulus
            shares.append((x, y.to_bytes(16, 'big')))  # Convert y to 16 bytes

        return shares

    def evaluate_polynomial(self, coefficients, x):
        """
        Evaluates a polynomial with the given coefficients at a specific x value.
        """
        result = 0
        for i, coef in enumerate(coefficients):
            result += coef * (x ** i)
        return result

    def reconstruct_key(self, shares):
        """
        Reconstructs the secret from the given shares using Lagrange interpolation.
        """
        x_s, y_s = zip(*shares)
        secret = self.lagrange_interpolation(0, x_s, y_s)
        return secret.to_bytes(16, 'big')

    def lagrange_interpolation(self, x, x_s, y_s):
        prime_modulus = 2**128 -159
        total = 0
        for i in range(len(y_s)):
            xi, yi = x_s[i], int.from_bytes(y_s[i], 'big')
            term = yi
            for j in range(len(x_s)):
                if i != j:
                    xj = x_s[j]
                    numerator = (x - xj) % prime_modulus
                    denominator = (xi - xj) % prime_modulus
                    try:
                        inverse_denominator = pow(denominator, -1, prime_modulus)
                    except ValueError:
                        print(f"Error: Denominator {denominator} has no inverse modulo {prime_modulus}")
                        return None  # Ou levez une exception

                    term = (term * numerator * inverse_denominator) % prime_modulus
            total = (total + term) % prime_modulus
        return total


