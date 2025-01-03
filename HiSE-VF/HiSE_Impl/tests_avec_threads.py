import time
from hise_avec_threads import Hise
from charm.toolbox.pairinggroup import PairingGroup

###########################################################################################################
# TESTS
###########################################################################################################

# Initialisation du groupe (si nécessaire)
group = PairingGroup('BN254')

def test_parallel_enc_latency(configs, batch_sizes):
    """Test encryption latency with internal parallelization for given configs and batch sizes."""
    print("\n=== Testing Encryption Latency with Internal Parallelization ===")

    results = []
    # Pour chaque configuration (n,t)
    for (nodes, threshold) in configs:
        # Générer un ensemble de messages suffisamment grand
        max_batch = max(batch_sizes)
        messages = [f"message{i}".encode() for i in range(max_batch)]
        
        # Pour chaque taille de batch
        for bs in batch_sizes:
            print(f"\nTesting configuration: n={nodes}, t={threshold}, {bs} messages")

            pp, keys, coms = Hise.setup(nodes, threshold)

            # Warmup run
            _ = Hise.dist_gr_enc(messages[:bs], pp, keys, coms, threshold)

            start_time = time.time()
            _ = Hise.dist_gr_enc(messages[:bs], pp, keys, coms, threshold)
            duration = time.time() - start_time

            latency = duration * 1000
            throughput = bs / duration

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
    """Test decryption latency with internal parallelization for given configs and batch sizes."""
    print("\n=== Testing Decryption Latency with Internal Parallelization ===")

    results = []
    # Pour chaque configuration (n,t)
    for (nodes, threshold) in configs:
        # Générer un ensemble de messages suffisamment grand
        max_batch = max(batch_sizes)
        messages = [f"message{i}".encode() for i in range(max_batch)]

        pp, keys, coms = Hise.setup(nodes, threshold)
        # On fait une seule fois le setup par config, mais on le refera pour chaque batch size.
        # (Optionnel: On pourrait refaire pp, keys, coms à chaque fois, mais pas obligatoire.)

        for bs in batch_sizes:
            print(f"\nTesting configuration: n={nodes}, t={threshold}, {bs} messages")

            # Chiffrer d'abord les messages pour obtenir un batch
            batch = Hise.dist_gr_enc(messages[:bs], pp, keys, coms, threshold)

            # Warmup run
            _ = Hise.dist_gr_dec(batch, pp, keys, coms, threshold, messages[:bs])

            start_time = time.time()
            _ = Hise.dist_gr_dec(batch, pp, keys, coms, threshold, messages[:bs])
            duration = time.time() - start_time

            latency = duration * 1000
            throughput = bs / duration
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
    Format and display performance results in a table.
    Filters results by test_type = 'encryption' or 'decryption'.
    Expected `results` format: a list of dicts with keys: 'n', 't', 'batch_size', 'latency_ms', 'throughput', 'type'
    """
    filtered = [r for r in results if r['type'] == test_type]

    print(f"\n=== Performance Results ({test_type.capitalize()}) ===")
    print(" n     t     Batch Size   Latency (ms)    Throughput (msg/s)")
    print("------------------------------------------------------------")
    # On trie par n, t, puis batch_size
    filtered.sort(key=lambda x: (x['n'], x['t'], x['batch_size']))
    for r in filtered:
        print(f"{r['n']:<5} {r['t']:<5} {r['batch_size']:<12} {r['latency_ms']:<15.2f} {r['throughput']:.2f}")

if __name__ == "__main__":
    print("Starting HISE threaded encryption and decryption tests...")

    # Configurations (n, t)
    configs = [
        (8,4),
        (12,4),
        (24,8),
        (40,10)
    ]

    batch_sizes = [50, 100, 200, 400]

    enc_results = test_parallel_enc_latency(configs, batch_sizes)
    dec_results = test_parallel_dec_latency(configs, batch_sizes)

    # Combiner les résultats
    all_results = enc_results + dec_results

    # Afficher les résultats formatés
    format_results(all_results, 'encryption')
    format_results(all_results, 'decryption')




###########################################################################################################
# RESULTS
###########################################################################################################


# Starting HISE threaded encryption and decryption tests...

# === Testing Encryption Latency with Internal Parallelization ===

# Testing configuration: n=8, t=4, 50 messages
# Encryption latency: 1751.77 ms
# Encryption throughput: 28.54 messages/second

# Testing configuration: n=8, t=4, 100 messages
# Encryption latency: 3514.57 ms
# Encryption throughput: 28.45 messages/second

# Testing configuration: n=8, t=4, 200 messages
# Encryption latency: 6929.08 ms
# Encryption throughput: 28.86 messages/second

# Testing configuration: n=8, t=4, 400 messages
# Encryption latency: 13822.65 ms
# Encryption throughput: 28.94 messages/second

# Testing configuration: n=12, t=4, 50 messages
# Encryption latency: 1755.95 ms
# Encryption throughput: 28.47 messages/second

# Testing configuration: n=12, t=4, 100 messages
# Encryption latency: 3453.12 ms
# Encryption throughput: 28.96 messages/second

# Testing configuration: n=12, t=4, 200 messages
# Encryption latency: 6883.60 ms
# Encryption throughput: 29.05 messages/second

# Testing configuration: n=12, t=4, 400 messages
# Encryption latency: 13854.93 ms
# Encryption throughput: 28.87 messages/second

# Testing configuration: n=24, t=8, 50 messages
# Encryption latency: 1774.74 ms
# Encryption throughput: 28.17 messages/second

# Testing configuration: n=24, t=8, 100 messages
# Encryption latency: 3507.08 ms
# Encryption throughput: 28.51 messages/second

# Testing configuration: n=24, t=8, 200 messages
# Encryption latency: 6955.56 ms
# Encryption throughput: 28.75 messages/second

# Testing configuration: n=24, t=8, 400 messages
# Encryption latency: 14049.97 ms
# Encryption throughput: 28.47 messages/second

# Testing configuration: n=40, t=10, 50 messages
# Encryption latency: 1795.07 ms
# Encryption throughput: 27.85 messages/second

# Testing configuration: n=40, t=10, 100 messages
# Encryption latency: 3519.59 ms
# Encryption throughput: 28.41 messages/second

# Testing configuration: n=40, t=10, 200 messages
# Encryption latency: 7140.87 ms
# Encryption throughput: 28.01 messages/second

# Testing configuration: n=40, t=10, 400 messages
# Encryption latency: 14137.58 ms
# Encryption throughput: 28.29 messages/second

# === Testing Decryption Latency with Internal Parallelization ===

# Testing configuration: n=8, t=4, 50 messages
# Decryption latency: 1688.27 ms
# Decryption throughput: 29.62 messages/second

# Testing configuration: n=8, t=4, 100 messages
# Decryption latency: 3321.74 ms
# Decryption throughput: 30.10 messages/second

# Testing configuration: n=8, t=4, 200 messages
# Decryption latency: 6616.47 ms
# Decryption throughput: 30.23 messages/second

# Testing configuration: n=8, t=4, 400 messages
# Decryption latency: 13246.54 ms
# Decryption throughput: 30.20 messages/second

# Testing configuration: n=12, t=4, 50 messages
# Decryption latency: 1739.04 ms
# Decryption throughput: 28.75 messages/second

# Testing configuration: n=12, t=4, 100 messages
# Decryption latency: 3349.57 ms
# Decryption throughput: 29.85 messages/second

# Testing configuration: n=12, t=4, 200 messages
# Decryption latency: 6695.06 ms
# Decryption throughput: 29.87 messages/second

# Testing configuration: n=12, t=4, 400 messages
# Decryption latency: 15898.54 ms
# Decryption throughput: 25.16 messages/second

# Testing configuration: n=24, t=8, 50 messages
# Decryption latency: 2134.55 ms
# Decryption throughput: 23.42 messages/second

# Testing configuration: n=24, t=8, 100 messages
# Decryption latency: 4102.71 ms
# Decryption throughput: 24.37 messages/second

# Testing configuration: n=24, t=8, 200 messages
# Decryption latency: 8043.38 ms
# Decryption throughput: 24.87 messages/second

# Testing configuration: n=24, t=8, 400 messages
# Decryption latency: 16269.79 ms
# Decryption throughput: 24.59 messages/second

# Testing configuration: n=40, t=10, 50 messages
# Decryption latency: 2158.95 ms
# Decryption throughput: 23.16 messages/second

# Testing configuration: n=40, t=10, 100 messages
# Decryption latency: 4116.37 ms
# Decryption throughput: 24.29 messages/second

# Testing configuration: n=40, t=10, 200 messages
# Decryption latency: 8079.75 ms
# Decryption throughput: 24.75 messages/second

# Testing configuration: n=40, t=10, 400 messages
# Decryption latency: 14340.14 ms
# Decryption throughput: 27.89 messages/second

# === Performance Results (Encryption) ===
#  n     t     Batch Size   Latency (ms)    Throughput (msg/s)
# ------------------------------------------------------------
# 8     4     50           1751.77         28.54
# 8     4     100          3514.57         28.45
# 8     4     200          6929.08         28.86
# 8     4     400          13822.65        28.94
# 12    4     50           1755.95         28.47
# 12    4     100          3453.12         28.96
# 12    4     200          6883.60         29.05
# 12    4     400          13854.93        28.87
# 24    8     50           1774.74         28.17
# 24    8     100          3507.08         28.51
# 24    8     200          6955.56         28.75
# 24    8     400          14049.97        28.47
# 40    10    50           1795.07         27.85
# 40    10    100          3519.59         28.41
# 40    10    200          7140.87         28.01
# 40    10    400          14137.58        28.29

# === Performance Results (Decryption) ===
#  n     t     Batch Size   Latency (ms)    Throughput (msg/s)
# ------------------------------------------------------------
# 8     4     50           1688.27         29.62
# 8     4     100          3321.74         30.10
# 8     4     200          6616.47         30.23
# 8     4     400          13246.54        30.20
# 12    4     50           1739.04         28.75
# 12    4     100          3349.57         29.85
# 12    4     200          6695.06         29.87
# 12    4     400          15898.54        25.16
# 24    8     50           2134.55         23.42
# 24    8     100          4102.71         24.37
# 24    8     200          8043.38         24.87
# 24    8     400          16269.79        24.59
# 40    10    50           2158.95         23.16
# 40    10    100          4116.37         24.29
# 40    10    200          8079.75         24.75
# 40    10    400          14340.14        27.89