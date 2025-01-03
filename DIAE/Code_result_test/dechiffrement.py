import matplotlib.pyplot as plt
import secrets
import time
from sympy import symbols, Poly
import hashlib


# === Fonction DPRF - Distributed Pseudorandom Function ===
def dprf_eval(secret_share: int, x: int) -> int:
    key = hashlib.sha256(str(secret_share).encode() + str(x).encode()).digest()
    return int.from_bytes(key, 'big') % (2**127)


# === Déchiffrement simulé (latence) ===
def decrypt_simulated(secret_share: int, node_id: int):
    start_time = time.time()
    dprf_key = dprf_eval(secret_share, x=node_id)
    end_time = time.time()
    return (end_time - start_time) * 1000.0  # Latence en millisecondes


# === Partage de secret avec Shamir ===
def shamir_secret_sharing(secret: int, n: int, t: int):
    x_sym = symbols('x', integer=True)
    coeffs = (secret,) + tuple(secrets.randbelow(2**127) for _ in range(t - 1))
    poly_expr = sum(coeffs[i] * x_sym**i for i in range(len(coeffs)))
    poly = Poly(poly_expr, x_sym)

    shares = []
    for i in range(1, n + 1):
        x_val = i
        y_val = poly.eval(x_val) % (2**127)
        shares.append((x_val, y_val))
    
    return shares


# === Simulation des tests DiAE ===
if __name__ == "__main__":
    n = 100  # Nombre total de nœuds disponibles
    t = 40   # Seuil de reconstruction

    # Tailles de fichier à tester (en KB)
    file_sizes = [1, 10, 100, 1000]

    # Liste de nœuds par incréments de 5 (jusqu'à 100)
    node_counts = list(range(5, 105, 5))

    # Stockage des résultats pour chaque taille de fichier
    results = {size: [] for size in file_sizes}

    print(f"=== Simulation de DiAE - Déchiffrement avec reconstruction de clé ===\n"
          f"n={n}, t={t}\n")

    # Générer un secret maître
    master_secret = secrets.randbelow(2**127 - 1)
    shares = shamir_secret_sharing(master_secret, n, t)

    # Simulation du déchiffrement
    for size in file_sizes:
        print(f"\n=== Tests de déchiffrement simulé pour {size} KB ===")
        for node_count in node_counts:
            start_time = time.time()

            # Simulation du déchiffrement par plusieurs nœuds
            total_dec_time_ms = 0
            for i in range(node_count):
                node_id = i % n
                secret_share = shares[node_id % len(shares)][1]
                total_dec_time_ms += decrypt_simulated(secret_share, node_id)

            end_time = time.time()
            total_time_s = end_time - start_time
            avg_lat_s = (total_dec_time_ms / node_count) / 1000.0

            print(f"[{size}KB, {node_count} nœuds] total_time={total_time_s:.2f}s, avg_lat={avg_lat_s:.4f}s")
            results[size].append((node_count, avg_lat_s, total_time_s))

    # === TRAÇAGE DU GRAPHIQUE ===
    plt.figure(figsize=(12, 6))
    markers = {1: 'o', 10: 's', 100: '^', 1000: 'd'}
    colors = ['blue', 'orange', 'green', 'red']

    for idx, size in enumerate(file_sizes):
        data_points = results[size]
        if not data_points:
            continue

        node_counts = [dp[0] for dp in data_points]
        avg_lats = [dp[1] for dp in data_points]
        plt.plot(node_counts, avg_lats, marker=markers[size], color=colors[idx], label=f"{size} KB")

    # Configuration du graphique
    plt.title("Latence moyenne (DiAE Déchiffrement) par nœud et taille de fichier")
    plt.xlabel("Nombre de nœuds")
    plt.ylabel("Latence (s)")
    plt.yscale("log")  # Échelle logarithmique pour la latence
    plt.grid(True, which="both", linestyle='--', linewidth=0.5)
    plt.legend()

    plt.tight_layout()
    plt.show()
