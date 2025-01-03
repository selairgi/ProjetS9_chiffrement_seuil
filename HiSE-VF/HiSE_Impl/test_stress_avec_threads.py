import time
from hise_avec_threads import Hise
from charm.toolbox.pairinggroup import PairingGroup

group = PairingGroup('BN254')


###########################################################################################################
# TESTS
###########################################################################################################

def generate_message(size_in_kb):
    """Génère un message de 'size_in_kb' kilo-octets environ."""
    return b'a' * (size_in_kb * 1024)

def run_stress_test(pp, keys, coms, t, messages, duration=60):
    """
    Tente de chiffrer un batch de messages autant de fois que possible pendant 'duration' secondes.
    Retourne le nombre de batchs chiffrés, le nombre total de messages, et le throughput en messages/s.
    """
    start_time = time.time()
    end_time = start_time + duration
    count = 0
    batch_size = len(messages)
    
    while time.time() < end_time:
        Hise.dist_gr_enc(messages, pp, keys, coms, t)
        count += 1

    total_msgs = count * batch_size
    actual_duration = time.time() - start_time
    throughput = total_msgs / actual_duration if actual_duration > 0 else 0

    return count, total_msgs, throughput

def test_stress_batch_size_nt():
    # Configurations (n, t)
    # Par exemple, on teste plusieurs (n,t) comme suit :
    #  - (8,4) : n=8, t=4 (la moitié)
    #  - (12,4) : n=12, t=4 (t reste constant, n augmente)
    #  - (24,8) : n=24, t=8 (~n/3)
    #  - (40,10) : n=40, t=10 (~n/4)
    configs = [
        (8, 4),
        (12, 4),
        (24, 8),
        (40, 10)
    ]

    # Taille du message fixée (100 Ko)
    msg_size_kb = 100
    single_msg = generate_message(msg_size_kb)

    # Différentes tailles de batch
    batch_sizes = [50, 100, 200, 400]

    # Durée du test en secondes
    duration = 60

    # Stockage des résultats dans une structure:
    # results[(n,t)] = liste des tuples (batch_size, count, total_msgs, throughput)
    results = {}

    for (n, t) in configs:
        pp, keys, coms = Hise.setup(n, t)
        config_results = []
        for bs in batch_sizes:
            messages = [single_msg for _ in range(bs)]
            print(f"\n=== Testing (n={n}, t={t}, size={msg_size_kb}Ko, batch={bs}) for {duration}s ===")
            count, total_msgs, throughput = run_stress_test(pp, keys, coms, t, messages, duration)
            config_results.append((bs, count, total_msgs, throughput))
            print(f"Completed {count} batches ({total_msgs} msgs) in {duration}s, ~{throughput:.2f} msg/s")
        results[(n,t)] = config_results

    # Affichage des résultats
    # On veut un tableau qui pour chaque (n,t) affiche les batch_sizes et les stats
    print("\n=== Stress Test Results by (n,t) and Batch Size ===")
    print("n     t     | Batch Size | Batches/min | Msg/min    | Throughput (msg/s)")
    print("-----------------------------------------------------------------------")

    # Pour le calcul des batches/min et msg/min : le test dure 60s donc count = nb batch/min directement
    # total_msgs = nb msg/min également
    # throughput est déjà en msg/s
    for (n,t), conf_res in results.items():
        for (bs, count, total_msgs, throughput) in conf_res:
            print(f"{n:<5} {t:<5} | {bs:<10} | {count:<11} | {total_msgs:<10} | {throughput:.2f}")

if __name__ == "__main__":
    test_stress_batch_size_nt()


###########################################################################################################
# RESULTS
###########################################################################################################

# === Testing (n=8, t=4, size=100Ko, batch=50) for 60s ===
# Completed 35 batches (1750 msgs) in 60s, ~28.86 msg/s

# === Testing (n=8, t=4, size=100Ko, batch=100) for 60s ===
# Completed 18 batches (1800 msgs) in 60s, ~29.09 msg/s

# === Testing (n=8, t=4, size=100Ko, batch=200) for 60s ===
# Completed 9 batches (1800 msgs) in 60s, ~29.41 msg/s

# === Testing (n=8, t=4, size=100Ko, batch=400) for 60s ===
# Completed 5 batches (2000 msgs) in 60s, ~29.34 msg/s

# === Testing (n=12, t=4, size=100Ko, batch=50) for 60s ===
# Completed 35 batches (1750 msgs) in 60s, ~28.85 msg/s

# === Testing (n=12, t=4, size=100Ko, batch=100) for 60s ===
# Completed 18 batches (1800 msgs) in 60s, ~29.08 msg/s

# === Testing (n=12, t=4, size=100Ko, batch=200) for 60s ===
# Completed 9 batches (1800 msgs) in 60s, ~28.85 msg/s

# === Testing (n=12, t=4, size=100Ko, batch=400) for 60s ===
# Completed 5 batches (2000 msgs) in 60s, ~29.04 msg/s

# === Testing (n=24, t=8, size=100Ko, batch=50) for 60s ===
# Completed 34 batches (1700 msgs) in 60s, ~28.09 msg/s

# === Testing (n=24, t=8, size=100Ko, batch=100) for 60s ===
# Completed 18 batches (1800 msgs) in 60s, ~28.41 msg/s

# === Testing (n=24, t=8, size=100Ko, batch=200) for 60s ===
# Completed 9 batches (1800 msgs) in 60s, ~28.48 msg/s

# === Testing (n=24, t=8, size=100Ko, batch=400) for 60s ===
# Completed 5 batches (2000 msgs) in 60s, ~28.39 msg/s

# === Testing (n=40, t=10, size=100Ko, batch=50) for 60s ===
# Completed 33 batches (1650 msgs) in 60s, ~27.00 msg/s

# === Testing (n=40, t=10, size=100Ko, batch=100) for 60s ===
# Completed 14 batches (1400 msgs) in 60s, ~23.22 msg/s

# === Testing (n=40, t=10, size=100Ko, batch=200) for 60s ===
# Completed 8 batches (1600 msgs) in 60s, ~23.41 msg/s

# === Testing (n=40, t=10, size=100Ko, batch=400) for 60s ===
# Completed 4 batches (1600 msgs) in 60s, ~23.65 msg/s

# === Stress Test Results by (n,t) and Batch Size ===
# n     t     | Batch Size | Batches/min | Msg/min    | Throughput (msg/s)
# -----------------------------------------------------------------------
# 8     4     | 50         | 35          | 1750       | 28.86
# 8     4     | 100        | 18          | 1800       | 29.09
# 8     4     | 200        | 9           | 1800       | 29.41
# 8     4     | 400        | 5           | 2000       | 29.34
# 12    4     | 50         | 35          | 1750       | 28.85
# 12    4     | 100        | 18          | 1800       | 29.08
# 12    4     | 200        | 9           | 1800       | 28.85
# 12    4     | 400        | 5           | 2000       | 29.04
# 24    8     | 50         | 34          | 1700       | 28.09
# 24    8     | 100        | 18          | 1800       | 28.41
# 24    8     | 200        | 9           | 1800       | 28.48
# 24    8     | 400        | 5           | 2000       | 28.39
# 40    10    | 50         | 33          | 1650       | 27.00
# 40    10    | 100        | 14          | 1400       | 23.22
# 40    10    | 200        | 8           | 1600       | 23.41
# 40    10    | 400        | 4           | 1600       | 23.65