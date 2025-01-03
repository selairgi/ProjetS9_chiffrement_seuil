import time
from hise_sans_threads import Hise
from charm.toolbox.pairinggroup import PairingGroup

# Initialisation du groupe de pairings
group = PairingGroup('BN254')

###########################################################################################################
# TESTS
###########################################################################################################

def generate_message(size_in_kb):
    """
    Génère un message de taille donnée en kilo-octets.
    
    Args:
        size_in_kb (int): Taille du message en kilo-octets.
    
    Returns:
        bytes: Message généré.
    """
    return b'a' * (size_in_kb * 1024)

def run_stress_test(pp, keys, coms, t, messages, duration=60):
    """
    Exécute un test de stress en chiffrant un batch de messages autant de fois que possible pendant une durée donnée.
    
    Args:
        pp: Paramètres publics HISE.
        keys: Clés des serveurs.
        coms: Engagements des serveurs.
        t (int): Seuil.
        messages (List[bytes]): Messages à chiffrer.
        duration (int): Durée du test en secondes (par défaut 60).
    
    Returns:
        Tuple[int, int, float]: Nombre de batchs chiffrés, nombre total de messages, et débit en messages par seconde.
    """
    start_time = time.time()
    end_time = start_time + duration
    count = 0
    batch_size = len(messages)
    
    # Chiffrement répété pendant la durée du test
    while time.time() < end_time:
        Hise.dist_gr_enc(messages, pp, keys, coms, t)
        count += 1

    # Calcul du nombre total de messages et du débit
    total_msgs = count * batch_size
    actual_duration = time.time() - start_time
    throughput = total_msgs / actual_duration if actual_duration > 0 else 0

    return count, total_msgs, throughput

def test_stress_batch_size_nt():
    """
    Teste la robustesse du système pour différentes configurations (n, t) et tailles de batch.
    """
    # Configurations (n, t) à tester
    configs = [
        (8, 4),   # n=8, t=4 (la moitié)
        (12, 4),  # n=12, t=4 (t constant, n augmente)
        (24, 8),  # n=24, t=8 (~n/3)
        (40, 10)  # n=40, t=10 (~n/4)
    ]

    # Taille du message fixée à 100 Ko
    msg_size_kb = 100
    single_msg = generate_message(msg_size_kb)

    # Différentes tailles de batch à tester
    batch_sizes = [50, 100, 200, 400]

    # Durée du test en secondes
    duration = 60

    # Stockage des résultats
    results = {}

    # Pour chaque configuration (n, t)
    for (n, t) in configs:
        # Initialisation des paramètres HISE
        pp, keys, coms = Hise.setup(n, t)
        config_results = []

        # Pour chaque taille de batch
        for bs in batch_sizes:
            messages = [single_msg for _ in range(bs)]
            print(f"\n=== Testing (n={n}, t={t}, size={msg_size_kb}Ko, batch={bs}) for {duration}s ===")

            # Exécution du test de stress
            count, total_msgs, throughput = run_stress_test(pp, keys, coms, t, messages, duration)
            config_results.append((bs, count, total_msgs, throughput))

            print(f"Completed {count} batches ({total_msgs} msgs) in {duration}s, ~{throughput:.2f} msg/s")

        # Stockage des résultats pour cette configuration
        results[(n, t)] = config_results

    # Affichage des résultats sous forme de tableau
    print("\n=== Résultats des tests de stress par (n, t) et taille de batch ===")
    print("n     t     | Batch Size | Batches/min | Msg/min    | Throughput (msg/s)")
    print("-----------------------------------------------------------------------")

    for (n, t), conf_res in results.items():
        for (bs, count, total_msgs, throughput) in conf_res:
            print(f"{n:<5} {t:<5} | {bs:<10} | {count:<11} | {total_msgs:<10} | {throughput:.2f}")

if __name__ == "__main__":
    test_stress_batch_size_nt()



###########################################################################################################
# RESULTS
###########################################################################################################

# === Testing (n=8, t=4, size=100Ko, batch=50) for 60s ===
# Completed 36 batches (1800 msgs) in 60s, ~29.26 msg/s

# === Testing (n=8, t=4, size=100Ko, batch=100) for 60s ===
# Completed 18 batches (1800 msgs) in 60s, ~29.47 msg/s

# === Testing (n=8, t=4, size=100Ko, batch=200) for 60s ===
# Completed 9 batches (1800 msgs) in 60s, ~29.06 msg/s

# === Testing (n=8, t=4, size=100Ko, batch=400) for 60s ===
# Completed 5 batches (2000 msgs) in 60s, ~28.81 msg/s

# === Testing (n=12, t=4, size=100Ko, batch=50) for 60s ===
# Completed 35 batches (1750 msgs) in 60s, ~28.47 msg/s

# === Testing (n=12, t=4, size=100Ko, batch=100) for 60s ===
# Completed 18 batches (1800 msgs) in 60s, ~28.72 msg/s

# === Testing (n=12, t=4, size=100Ko, batch=200) for 60s ===
# Completed 9 batches (1800 msgs) in 60s, ~28.45 msg/s

# === Testing (n=12, t=4, size=100Ko, batch=400) for 60s ===
# Completed 5 batches (2000 msgs) in 60s, ~28.81 msg/s

# === Testing (n=24, t=8, size=100Ko, batch=50) for 60s ===
# Completed 34 batches (1700 msgs) in 60s, ~27.78 msg/s

# === Testing (n=24, t=8, size=100Ko, batch=100) for 60s ===
# Completed 17 batches (1700 msgs) in 60s, ~27.26 msg/s

# === Testing (n=24, t=8, size=100Ko, batch=200) for 60s ===
# Completed 9 batches (1800 msgs) in 60s, ~28.55 msg/s

# === Testing (n=24, t=8, size=100Ko, batch=400) for 60s ===
# Completed 5 batches (2000 msgs) in 60s, ~28.83 msg/s

# === Testing (n=40, t=10, size=100Ko, batch=50) for 60s ===
# Completed 34 batches (1700 msgs) in 60s, ~27.74 msg/s

# === Testing (n=40, t=10, size=100Ko, batch=100) for 60s ===
# Completed 18 batches (1800 msgs) in 60s, ~28.58 msg/s

# === Testing (n=40, t=10, size=100Ko, batch=200) for 60s ===
# Completed 9 batches (1800 msgs) in 60s, ~29.03 msg/s

# === Testing (n=40, t=10, size=100Ko, batch=400) for 60s ===
# Completed 5 batches (2000 msgs) in 60s, ~29.18 msg/s

# === Stress Test Results by (n,t) and Batch Size ===
# n     t     | Batch Size | Batches/min | Msg/min    | Throughput (msg/s)
# -----------------------------------------------------------------------
# 8     4     | 50         | 36          | 1800       | 29.26
# 8     4     | 100        | 18          | 1800       | 29.47
# 8     4     | 200        | 9           | 1800       | 29.06
# 8     4     | 400        | 5           | 2000       | 28.81
# 12    4     | 50         | 35          | 1750       | 28.47
# 12    4     | 100        | 18          | 1800       | 28.72
# 12    4     | 200        | 9           | 1800       | 28.45
# 12    4     | 400        | 5           | 2000       | 28.81
# 24    8     | 50         | 34          | 1700       | 27.78
# 24    8     | 100        | 17          | 1700       | 27.26
# 24    8     | 200        | 9           | 1800       | 28.55
# 24    8     | 400        | 5           | 2000       | 28.83
# 40    10    | 50         | 34          | 1700       | 27.74
# 40    10    | 100        | 18          | 1800       | 28.58
# 40    10    | 200        | 9           | 1800       | 29.03
# 40    10    | 400        | 5           | 2000       | 29.18