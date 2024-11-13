#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: alex
"""

import random
from functools import reduce

# Fonction d'évaluation d'un polynôme
def evaluate_polynomial(coefficients, x):
    result = 0
    for coefficient in reversed(coefficients):
        result = result * x + coefficient
    return result

def generate_shares(secret, threshold, n):
    """Génère n parts de la clé avec un seuil requis pour la reconstruction."""
    # Convertir le secret en entier si nécessaire
    secret_int = int.from_bytes(secret, byteorder="big")
    
    # Générer les coefficients aléatoires pour le polynôme
    coefficients = [secret_int] + [random.randint(0, 2**256) for _ in range(threshold - 1)]
    
    # Générer les parts
    shares = [(i, evaluate_polynomial(coefficients, i)) for i in range(1, n + 1)]
    return shares

def reconstruct_secret(shares, threshold):
    """Reconstruit le secret en utilisant les parts."""
    def lagrange_interpolate(x, x_s, y_s):
        def basis(j):
            num = reduce(lambda acc, m: acc * (x - x_s[m]), filter(lambda m: m != j, range(len(x_s))), 1)
            den = reduce(lambda acc, m: acc * (x_s[j] - x_s[m]), filter(lambda m: m != j, range(len(x_s))), 1)
            return y_s[j] * num // den

        return sum(basis(j) for j in range(len(x_s)))

    x_s, y_s = zip(*shares)
    secret_int = lagrange_interpolate(0, x_s, y_s)
    return secret_int.to_bytes((secret_int.bit_length() + 7) // 8, byteorder="big")
