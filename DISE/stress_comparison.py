import time
import random
import os
import sys
import matplotlib.pyplot as plt
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from concurrent.futures import ThreadPoolExecutor
from DISE.master_key import MasterKey
from DISE.dist_enc import DistEnc
from DISE.RobustDise import RobustDistEnc
from DISE.RobustDISE_threads import RobustDistEnc as RobustDistEncThreads

# Initialisation
TEST_DURATION = 60  # Durée fixe d'une minute
MAX_FREQUENCY = 20  # Fréquence maximale des requêtes (messages/seconde)
STEP_FREQUENCY = 2  # Incrément de fréquence par étape
MESSAGE_SIZE = 1024  # Taille d'un message en octets

# Fonctions de chiffrement pour chaque protocole
def encrypt_dise(message, key, n, m):
    dist_enc = DistEnc(key, threshold=m)
    parties = random.sample(range(n), m)
    dist_enc.encrypt(message, parties)

def encrypt_robust_dise(message, key, n, t, delta):
    robust_enc = RobustDistEnc(key, threshold=t, delta=delta)
    parties = random.sample(range(n), t + delta)
    robust_enc.robust_encrypt(message, parties)

def encrypt_robust_threads(message, key, n, t, delta):
    robust_threads = RobustDistEncThreads(key, threshold=t, delta=delta)
    parties = random.sample(range(n), t + delta)
    robust_threads.robust_encrypt(message, parties)

# Début des tests pour chaque protocole
def stress_test(protocol_name, encrypt_function, n, threshold, delta=None):
    print(f"--- Début des tests pour {protocol_name} ---")
    master_key = MasterKey()
    master_key.key_gen(n=n)
    message = os.urandom(MESSAGE_SIZE)
    results = {"frequency": [], "latency": [], "throughput": [], "critical_points": []}

    for freq in range(1, MAX_FREQUENCY + 1, STEP_FREQUENCY):
        latencies = []
        start_time = time.time()
        total_operations = 0

        while time.time() - start_time < TEST_DURATION:
            start_op = time.perf_counter()
            if delta is not None:
                encrypt_function(message, master_key, n, threshold, delta)
            else:
                encrypt_function(message, master_key, n, threshold)
            end_op = time.perf_counter()
            latencies.append(end_op - start_op)
            total_operations += 1

        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        throughput = total_operations / TEST_DURATION

        results["frequency"].append(freq)
        results["latency"].append(avg_latency)
        results["throughput"].append(throughput)

        print(f"Fréquence: {freq}/s - Latence: {avg_latency:.4f}s - Débit: {throughput:.2f} msg/s")

        # Arrêter si latence dépasse un seuil critique (double la latence initiale)
        if len(results["latency"]) > 1 and avg_latency > min(results["latency"]) * 1.5:
            critical_point = {"protocol": protocol_name, "frequency": freq, "latency": avg_latency}
            results["critical_points"].append(critical_point)
            break

    return results

# Comparaison et affichage des résultats avec points critiques
# Comparaison et affichage des résultats avec points critiques
def compare_protocols():
    n, threshold, delta = 50, 40, 4
    all_critical_points = []

    dise_results = stress_test("DISE", encrypt_dise, n, threshold)
    all_critical_points.extend(dise_results["critical_points"])

    robust_dise_results = stress_test("RobustDISE", encrypt_robust_dise, n, threshold, delta)
    all_critical_points.extend(robust_dise_results["critical_points"])

    robust_threads_results = stress_test("RobustDISE_threads", encrypt_robust_threads, n, threshold, delta)
    all_critical_points.extend(robust_threads_results["critical_points"])

    # Imprimer tous les points critiques à la fin
    print("\n--- FIN de simulation ---")
    if all_critical_points:
        print("Points critiques atteints :")
        for point in all_critical_points:
            print(f"Protocole: {point['protocol']}, Fréquence: {point['frequency']} req/s, Latence: {point['latency']:.4f}s")
    else:
        print("Aucun point critique atteint.")

    # Affichage graphique
    plt.figure(figsize=(18, 18))

    # Latence moyenne en fonction de la fréquence
    plt.subplot(3, 1, 1)
    plt.plot(dise_results["frequency"], dise_results["latency"], marker='o', label="DISE")
    plt.plot(robust_dise_results["frequency"], robust_dise_results["latency"], marker='x', label="RobustDISE")
    plt.plot(robust_threads_results["frequency"], robust_threads_results["latency"], marker='s', label="RobustDISE_threads")
    plt.xlabel("Fréquence d'entrée (req/s)")
    plt.ylabel("Latence moyenne (s)")
    plt.title("Latence moyenne en fonction de la fréquence d'entrée")
    plt.legend()
    plt.grid()

    # Débit en fonction de la fréquence
    plt.subplot(3, 1, 2)
    plt.plot(dise_results["frequency"], dise_results["throughput"], marker='o', label="DISE")
    plt.plot(robust_dise_results["frequency"], robust_dise_results["throughput"], marker='x', label="RobustDISE")
    plt.plot(robust_threads_results["frequency"], robust_threads_results["throughput"], marker='s', label="RobustDISE_threads")
    plt.xlabel("Fréquence d'entrée (req/s)")
    plt.ylabel("Débit (msg/s)")
    plt.title("Débit en fonction de la fréquence d'entrée")
    plt.legend()
    plt.grid()

    # Latence en fonction du débit
    plt.subplot(3, 1, 3)
    plt.plot(dise_results["throughput"], dise_results["latency"], marker='o', label="DISE")
    plt.plot(robust_dise_results["throughput"], robust_dise_results["latency"], marker='x', label="RobustDISE")
    plt.plot(robust_threads_results["throughput"], robust_threads_results["latency"], marker='s', label="RobustDISE_threads")
    plt.xlabel("Débit (msg/s)")
    plt.ylabel("Latence moyenne (s)")
    plt.title("Latence en fonction du débit")
    plt.legend()
    plt.grid()

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    compare_protocols()


if __name__ == "__main__":
    compare_protocols()
