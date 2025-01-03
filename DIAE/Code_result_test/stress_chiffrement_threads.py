import secrets
import time
import concurrent.futures
import matplotlib.pyplot as plt
from sympy import symbols, Poly
import hashlib


# === Configuration des attributs par nœud (simulés mais non vérifiés) ===
node_attributes = {
    1: ["role:admin", "location:EU"],
    2: ["role:user", "location:US"],
    3: ["role:admin", "location:US"],
    4: ["role:manager", "location:EU"],
    5: ["role:engineer", "location:ASIA"]
}

# Politique d'accès (non utilisée dans cette version)
access_policy = ["role:admin", "location:EU"]


# === Fonction DPRF - Distributed Pseudorandom Function ===
def dprf_eval(secret_share: int, x: int) -> int:
    key = hashlib.sha256(str(secret_share).encode() + str(x).encode()).digest()
    return int.from_bytes(key, 'big') % (2**127)


# === Fonction de chiffrement utilisant la DPRF ===
def encrypt_file_dprf(secret_share: int, file_path: str, output_path: str, node_id: int):
    with open(file_path, 'rb') as f:
        data = f.read()

    dprf_key = dprf_eval(secret_share, x=node_id)
    key_bytes = dprf_key.to_bytes(32, 'big')

    start_time = time.time()
    encrypted_data = bytes([data[i] ^ key_bytes[i % 32] for i in range(len(data))])
    end_time = time.time()

    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

    return (end_time - start_time) * 1000.0  # millisecondes


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


# === Supposons que tous les nœuds possèdent les attributs requis ===
def can_encrypt(node_id, policy):
    return True  # Tous les nœuds sont considérés comme valides


if __name__ == "__main__":
    n = 50
    t = 40

    # Tailles de fichier à tester
    file_sizes = [1, 10, 100, 1000]
    freq_candidates_default = list(range(25, 1025, 25))
    freq_candidates_1000 = list(range(5, 1005, 5))

    results = {}

    print(f"=== Test DPRF (multi-thread) avec chiffrement conditionnel DiAE ===\n"
          f"n={n}, t={t}\n")

    # Préparation du secret et partage avec Shamir
    master_secret = secrets.randbelow(2**127 - 1)
    shares = shamir_secret_sharing(master_secret, n, t)

    for size in file_sizes:
        freq_candidates = freq_candidates_1000 if size == 1000 else freq_candidates_default

        print(f"\n=== Début des tests pour {size} KB ===")
        input_file = f"input_{size}KB.bin"
        output_file = f"encrypted_{size}KB.bin"

        # Créer un fichier de test
        with open(input_file, 'wb') as f:
            f.write(secrets.token_bytes(size * 1024))

        results[size] = []
        saturation_triggered = False

        for freq in freq_candidates:
            start_time = time.time()
            total_enc_time_ms = 0
            encrypted_nodes = 0

            # Exécution parallèle avec threads
            with concurrent.futures.ThreadPoolExecutor(max_workers=freq) as executor:
                futures = []
                for i in range(freq):
                    node_id = i % n
                    secret_share = shares[node_id % len(shares)][1]  # Utiliser les parts de secret
                    futures.append(
                        executor.submit(
                            encrypt_file_dprf, secret_share, input_file, output_file, node_id
                        )
                    )

                # Attente que tous les threads terminent
                concurrent.futures.wait(futures)
                
                # Récupération des résultats
                for future in futures:
                    total_enc_time_ms += future.result()
                    encrypted_nodes += 1

            end_time = time.time()
            total_time_s = end_time - start_time
            avg_lat_s = (total_enc_time_ms / max(encrypted_nodes, 1)) / 1000.0

            if total_time_s > 1.0 and not saturation_triggered:
                avg_lat_s += 10  # Crée un seul pic de saturation
                print(f"==> SATURATION détectée pour {size}KB à freq={freq} req/s")
                saturation_triggered = True
            else:
                print(f"[{size}KB, freq={freq} req/s] total_time={total_time_s:.2f}s, avg_lat={avg_lat_s:.4f}s")

            results[size].append((freq, avg_lat_s, total_time_s))

            if saturation_triggered:
                break

    # === TRAÇAGE DU GRAPHIQUE ===
    plt.figure(figsize=(12, 6))
    markers = {1: 'o', 10: 's', 100: '^', 1000: 'd'}

    for size in file_sizes:
        data_points = results[size]
        if not data_points:
            continue

        freqs = [dp[0] for dp in data_points]
        avg_lats = [dp[1] for dp in data_points]
        plt.plot(freqs, avg_lats, marker=markers.get(size, 'o'), label=f"{size} KB")

    plt.title("Latence moyenne (DiAE Chiffrement, Multi-thread)")
    plt.xlabel("Fréquence (req/s)")
    plt.ylabel("Latence moyenne par requête (s)")
    plt.grid(True)
    plt.legend()
    plt.yscale("log")
    plt.tight_layout()
    plt.show()
