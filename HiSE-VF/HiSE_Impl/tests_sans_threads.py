import time
from hise_sans_threads import Hise
from charm.toolbox.pairinggroup import PairingGroup

###########################################################################################################
# TESTS
###########################################################################################################

# Initialisation du groupe de pairings
group = PairingGroup('BN254')

def test_parallel_enc_latency(configs, batch_sizes):
    """
    Teste la latence du chiffrement pour différentes configurations (n, t) et tailles de batch.
    
    Args:
        configs (List[Tuple[int, int]]): Liste des configurations (n, t) à tester.
        batch_sizes (List[int]): Liste des tailles de batch à tester.
    
    Returns:
        List[dict]: Résultats des tests sous forme de dictionnaires contenant :
            - 'n': Nombre de nœuds.
            - 't': Seuil.
            - 'batch_size': Taille du batch.
            - 'latency_ms': Latence en millisecondes.
            - 'throughput': Débit en messages par seconde.
            - 'type': Type de test ('encryption').
    """
    print("\n=== Test de latence du chiffrement (sans threads) ===")

    results = []
    # Pour chaque configuration (n, t)
    for (nodes, threshold) in configs:
        # Générer un ensemble de messages suffisamment grand
        max_batch = max(batch_sizes)
        messages = [f"message{i}".encode() for i in range(max_batch)]
        
        # Pour chaque taille de batch
        for bs in batch_sizes:
            print(f"\nTesting configuration: n={nodes}, t={threshold}, {bs} messages")

            # Initialisation des paramètres HISE
            pp, keys, coms = Hise.setup(nodes, threshold)

            # Warmup run (pour éviter les effets de bord liés à la mise en cache)
            _ = Hise.dist_gr_enc(messages[:bs], pp, keys, coms, threshold)

            # Mesure du temps de chiffrement
            start_time = time.time()
            _ = Hise.dist_gr_enc(messages[:bs], pp, keys, coms, threshold)
            duration = time.time() - start_time

            # Calcul de la latence et du débit
            latency = duration * 1000  # Latence en millisecondes
            throughput = bs / duration  # Débit en messages par seconde

            # Stockage des résultats
            results.append({
                'n': nodes,
                't': threshold,
                'batch_size': bs,
                'latency_ms': latency,
                'throughput': throughput,
                'type': 'encryption'
            })

            print(f"Encryption latency: {latency:.2f} ms")
            print(f"Encryption throughput: {throughput:.2f} messages/second")

    return results

def test_parallel_dec_latency(configs, batch_sizes):
    """
    Teste la latence du déchiffrement pour différentes configurations (n, t) et tailles de batch.
    
    Args:
        configs (List[Tuple[int, int]]): Liste des configurations (n, t) à tester.
        batch_sizes (List[int]): Liste des tailles de batch à tester.
    
    Returns:
        List[dict]: Résultats des tests sous forme de dictionnaires contenant :
            - 'n': Nombre de nœuds.
            - 't': Seuil.
            - 'batch_size': Taille du batch.
            - 'latency_ms': Latence en millisecondes.
            - 'throughput': Débit en messages par seconde.
            - 'type': Type de test ('decryption').
    """
    print("\n=== Test de latence du déchiffrement (sans threads) ===")

    results = []
    # Pour chaque configuration (n, t)
    for (nodes, threshold) in configs:
        # Générer un ensemble de messages suffisamment grand
        max_batch = max(batch_sizes)
        messages = [f"message{i}".encode() for i in range(max_batch)]

        # Initialisation des paramètres HISE
        pp, keys, coms = Hise.setup(nodes, threshold)

        # Pour chaque taille de batch
        for bs in batch_sizes:
            print(f"\nTesting configuration: n={nodes}, t={threshold}, {bs} messages")

            # Chiffrer d'abord les messages pour obtenir un batch
            batch = Hise.dist_gr_enc(messages[:bs], pp, keys, coms, threshold)

            # Warmup run (pour éviter les effets de bord liés à la mise en cache)
            _ = Hise.dist_gr_dec(batch, pp, keys, coms, threshold, messages[:bs])

            # Mesure du temps de déchiffrement
            start_time = time.time()
            _ = Hise.dist_gr_dec(batch, pp, keys, coms, threshold, messages[:bs])
            duration = time.time() - start_time

            # Calcul de la latence et du débit
            latency = duration * 1000  # Latence en millisecondes
            throughput = bs / duration  # Débit en messages par seconde

            # Stockage des résultats
            results.append({
                'n': nodes,
                't': threshold,
                'batch_size': bs,
                'latency_ms': latency,
                'throughput': throughput,
                'type': 'decryption'
            })

            print(f"Decryption latency: {latency:.2f} ms")
            print(f"Decryption throughput: {throughput:.2f} messages/second")

    return results

def format_results(results, test_type):
    """
    Formate et affiche les résultats de performance sous forme de tableau.
    
    Args:
        results (List[dict]): Liste des résultats à afficher.
        test_type (str): Type de test ('encryption' ou 'decryption').
    """
    filtered = [r for r in results if r['type'] == test_type]

    print(f"\n=== Résultats de performance ({test_type.capitalize()}) ===")
    print(" n     t     Batch Size   Latency (ms)    Throughput (msg/s)")
    print("------------------------------------------------------------")
    # Tri des résultats par n, t, puis batch_size
    filtered.sort(key=lambda x: (x['n'], x['t'], x['batch_size']))
    for r in filtered:
        print(f"{r['n']:<5} {r['t']:<5} {r['batch_size']:<12} {r['latency_ms']:<15.2f} {r['throughput']:.2f}")

if __name__ == "__main__":
    print("Début des tests de performance (sans threads)...")

    # Configurations (n, t) à tester
    configs = [
        (8, 4),
        (12, 4),
        (24, 8),
        (40, 10)
    ]

    # Tailles de batch à tester
    batch_sizes = [50, 100, 200, 400]

    # Exécution des tests de chiffrement et déchiffrement
    enc_results = test_parallel_enc_latency(configs, batch_sizes)
    dec_results = test_parallel_dec_latency(configs, batch_sizes)

    # Combinaison des résultats
    all_results = enc_results + dec_results

    # Affichage des résultats formatés
    format_results(all_results, 'encryption')
    format_results(all_results, 'decryption')




###########################################################################################################
# RESULTS
###########################################################################################################


# Starting HISE threaded encryption and decryption tests...

# === Testing Encryption Latency with no Internal Parallelization ===

# Testing configuration: n=8, t=4, 50 messages
# Encryption latency: 1755.82 ms
# Encryption throughput: 28.48 messages/second

# Testing configuration: n=8, t=4, 100 messages
# Encryption latency: 3572.77 ms
# Encryption throughput: 27.99 messages/second

# Testing configuration: n=8, t=4, 200 messages
# Encryption latency: 6921.68 ms
# Encryption throughput: 28.89 messages/second

# Testing configuration: n=8, t=4, 400 messages
# Encryption latency: 13981.54 ms
# Encryption throughput: 28.61 messages/second

# Testing configuration: n=12, t=4, 50 messages
# Encryption latency: 1853.22 ms
# Encryption throughput: 26.98 messages/second

# Testing configuration: n=12, t=4, 100 messages
# Encryption latency: 3471.45 ms
# Encryption throughput: 28.81 messages/second

# Testing configuration: n=12, t=4, 200 messages
# Encryption latency: 6931.40 ms
# Encryption throughput: 28.85 messages/second

# Testing configuration: n=12, t=4, 400 messages
# Encryption latency: 14064.47 ms
# Encryption throughput: 28.44 messages/second

# Testing configuration: n=24, t=8, 50 messages
# Encryption latency: 1782.29 ms
# Encryption throughput: 28.05 messages/second

# Testing configuration: n=24, t=8, 100 messages
# Encryption latency: 3515.19 ms
# Encryption throughput: 28.45 messages/second

# Testing configuration: n=24, t=8, 200 messages
# Encryption latency: 6936.23 ms
# Encryption throughput: 28.83 messages/second

# Testing configuration: n=24, t=8, 400 messages
# Encryption latency: 14061.21 ms
# Encryption throughput: 28.45 messages/second

# Testing configuration: n=40, t=10, 50 messages
# Encryption latency: 1796.32 ms
# Encryption throughput: 27.83 messages/second

# Testing configuration: n=40, t=10, 100 messages
# Encryption latency: 3542.84 ms
# Encryption throughput: 28.23 messages/second

# Testing configuration: n=40, t=10, 200 messages
# Encryption latency: 6976.60 ms
# Encryption throughput: 28.67 messages/second

# Testing configuration: n=40, t=10, 400 messages
# Encryption latency: 14031.23 ms
# Encryption throughput: 28.51 messages/second

# === Testing Decryption Latency with Internal Parallelization ===

# Testing configuration: n=8, t=4, 50 messages
# Decryption latency: 1673.84 ms
# Decryption throughput: 29.87 messages/second

# Testing configuration: n=8, t=4, 100 messages
# Decryption latency: 3295.46 ms
# Decryption throughput: 30.34 messages/second

# Testing configuration: n=8, t=4, 200 messages
# Decryption latency: 6694.47 ms
# Decryption throughput: 29.88 messages/second

# Testing configuration: n=8, t=4, 400 messages
# Decryption latency: 13245.43 ms
# Decryption throughput: 30.20 messages/second

# Testing configuration: n=12, t=4, 50 messages
# Decryption latency: 1737.60 ms
# Decryption throughput: 28.78 messages/second

# Testing configuration: n=12, t=4, 100 messages
# Decryption latency: 3333.26 ms
# Decryption throughput: 30.00 messages/second

# Testing configuration: n=12, t=4, 200 messages
# Decryption latency: 6610.66 ms
# Decryption throughput: 30.25 messages/second

# Testing configuration: n=12, t=4, 400 messages
# Decryption latency: 13030.51 ms
# Decryption throughput: 30.70 messages/second

# Testing configuration: n=24, t=8, 50 messages
# Decryption latency: 1732.20 ms
# Decryption throughput: 28.87 messages/second

# Testing configuration: n=24, t=8, 100 messages
# Decryption latency: 3393.02 ms
# Decryption throughput: 29.47 messages/second

# Testing configuration: n=24, t=8, 200 messages
# Decryption latency: 6697.92 ms
# Decryption throughput: 29.86 messages/second

# Testing configuration: n=24, t=8, 400 messages
# Decryption latency: 13397.22 ms
# Decryption throughput: 29.86 messages/second

# Testing configuration: n=40, t=10, 50 messages
# Decryption latency: 1878.73 ms
# Decryption throughput: 26.61 messages/second

# Testing configuration: n=40, t=10, 100 messages
# Decryption latency: 3530.05 ms
# Decryption throughput: 28.33 messages/second

# Testing configuration: n=40, t=10, 200 messages
# Decryption latency: 6920.73 ms
# Decryption throughput: 28.90 messages/second

# Testing configuration: n=40, t=10, 400 messages
# Decryption latency: 13689.52 ms
# Decryption throughput: 29.22 messages/second

# === Performance Results (Encryption) ===
#  n     t     Batch Size   Latency (ms)    Throughput (msg/s)
# ------------------------------------------------------------
# 8     4     50           1755.82         28.48
# 8     4     100          3572.77         27.99
# 8     4     200          6921.68         28.89
# 8     4     400          13981.54        28.61
# 12    4     50           1853.22         26.98
# 12    4     100          3471.45         28.81
# 12    4     200          6931.40         28.85
# 12    4     400          14064.47        28.44
# 24    8     50           1782.29         28.05
# 24    8     100          3515.19         28.45
# 24    8     200          6936.23         28.83
# 24    8     400          14061.21        28.45
# 40    10    50           1796.32         27.83
# 40    10    100          3542.84         28.23
# 40    10    200          6976.60         28.67
# 40    10    400          14031.23        28.51

# === Performance Results (Decryption) ===
#  n     t     Batch Size   Latency (ms)    Throughput (msg/s)
# ------------------------------------------------------------
# 8     4     50           1673.84         29.87
# 8     4     100          3295.46         30.34
# 8     4     200          6694.47         29.88
# 8     4     400          13245.43        30.20
# 12    4     50           1737.60         28.78
# 12    4     100          3333.26         30.00
# 12    4     200          6610.66         30.25
# 12    4     400          13030.51        30.70
# 24    8     50           1732.20         28.87
# 24    8     100          3393.02         29.47
# 24    8     200          6697.92         29.86
# 24    8     400          13397.22        29.86
# 40    10    50           1878.73         26.61
# 40    10    100          3530.05         28.33
# 40    10    200          6920.73         28.90
# 40    10    400          13689.52        29.22