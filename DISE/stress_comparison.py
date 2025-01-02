import time
import random
import os
import sys
import matplotlib.pyplot as plt
import time
import psutil
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from concurrent.futures import ThreadPoolExecutor
from DISE.master_key import MasterKey
from DISE.dist_enc import DistEnc
from DISE.dise_threads import DistEncThreads
from DISE.RobustDise import RobustDistEnc
from DISE.RobustDISE_threads import RobustDistEnc as RobustDistEncThreads

# Initialisation
TEST_DURATION = 10  # Durée fixe d'une minute
MAX_FREQUENCY = 100  # Fréquence maximale des requêtes (messages/seconde)
STEP_FREQUENCY = 1  # Incrément de fréquence par étape
MESSAGE_SIZE = 100  # Taille d'un message en octets

# Fonctions de chiffrement pour chaque protocole
def encrypt_dise(message, key, n, m):
    dist_enc = DistEnc(key, threshold=m)
    parties = random.sample(range(n), m)
    dist_enc.encrypt(message, parties)

def encrypt_dise_threads(message, key, n, m):
    dist_enc_threads = DistEncThreads(key, threshold=m)
    parties = random.sample(range(n), m)
    dist_enc_threads.encrypt(message, parties)

def encrypt_robust_dise(message, key, n, t, delta):
    robust_enc = RobustDistEnc(key, threshold=t, delta=delta)
    parties = random.sample(range(n), t + delta)
    robust_enc.robust_encrypt(message, parties)

def encrypt_robust_threads(message, key, n, t, delta):
    robust_threads = RobustDistEncThreads(key, threshold=t, delta=delta)
    parties = random.sample(range(n), t + delta)
    robust_threads.robust_encrypt(message, parties)

# Début des tests pour chaque protocole
def stress_test(protocol_name, encrypt_function, n, threshold, delta=None,ram_cpu_threshold=71):
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
            ram_usage = psutil.virtual_memory().percent
            #cpu_usage = psutil.cpu_percent(interval=0.1)
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
        if (len(results["latency"]) > 1 and avg_latency > min(results["latency"]) * 1.35) :
            critical_point = {"protocol": protocol_name, "frequency": freq, "latency": avg_latency}
            results["critical_points"].append(critical_point)
            
            print("machi cpu/ram")
            time.sleep(5)
            break

        if ram_usage > ram_cpu_threshold:
            critical_point = {"protocol": protocol_name, "frequency": freq, "latency": avg_latency}
            results["critical_points"].append(critical_point)
            print("cpu/ram")
            time.sleep(5)

            break

    return results

# Comparaison et affichage des résultats
def compare_protocols1():
    n, threshold, delta = 50, 40, 5
    all_critical_points = []

    dise_results = stress_test("DISE", encrypt_dise, n, threshold)
    #all_critical_points.extend(dise_results["critical_points"])

    dise_threads_results = stress_test("DISE_threads", encrypt_dise_threads, n, threshold)
    #all_critical_points.extend(dise_threads_results["critical_points"])

    robust_dise_results = stress_test("RobustDISE", encrypt_robust_dise, n, threshold, delta)
    #all_critical_points.extend(robust_dise_results["critical_points"])

    robust_threads_results = stress_test("RobustDISE_threads", encrypt_robust_threads, n, threshold, delta)
    #all_critical_points.extend(robust_threads_results["critical_points"])

    # Affichage des résultats

    # Latence moyenne en fonction de la fréquence
    plt.plot(dise_results["frequency"], dise_results["latency"], marker='o', label="DISE")
    plt.plot(dise_threads_results["frequency"], dise_threads_results["latency"], marker='^', label="DISE_threads")
    plt.plot(robust_dise_results["frequency"], robust_dise_results["latency"], marker='x', label="RobustDISE")
    plt.plot(robust_threads_results["frequency"], robust_threads_results["latency"], marker='s', label="RobustDISE_threads")
    plt.xlabel("Fréquence d'entrée (req/s)")
    plt.ylabel("Latence moyenne (s)")
    plt.title("Latence moyenne en fonction de la fréquence d'entrée")
    plt.legend()
    plt.grid()
    plt.tight_layout()
    plt.savefig("latence_vs_frequence.png")
    plt.close()

    # Débit en fonction de la fréquence (Saved separately)
    plt.plot(dise_results["frequency"], dise_results["throughput"], marker='o', label="DISE")
    plt.plot(dise_threads_results["frequency"], dise_threads_results["throughput"], marker='^', label="DISE_threads")
    plt.plot(robust_dise_results["frequency"], robust_dise_results["throughput"], marker='x', label="RobustDISE")
    plt.plot(robust_threads_results["frequency"], robust_threads_results["throughput"], marker='s', label="RobustDISE_threads")
    plt.xlabel("Fréquence d'entrée (req/s)")
    plt.ylabel("Débit (msg/s)")
    plt.title("Débit en fonction de la fréquence d'entrée")
    plt.legend()
    plt.grid()
    plt.tight_layout()
    plt.savefig("throughput_vs_frequence.png")
    plt.close()

def compare_protocols():
    n, threshold, delta = 50, 40, 5

    # DISE vs DISE Threads
    dise_results = stress_test("DISE", encrypt_dise, n, threshold)
    dise_threads_results = stress_test("DISE Threads", encrypt_dise_threads, n, threshold)

    # Plot DISE comparison
    plt.figure()
    plt.plot(dise_results["frequency"], dise_results["latency"], label="DISE")
    plt.plot(dise_threads_results["frequency"], dise_threads_results["latency"], label="DISE Threads")
    plt.xlabel("Fréquence d'entrée (req/s)")
    plt.ylabel("Latence moyenne (s)")
    plt.title("Latence moyenne en fonction de la fréquence d'entrée : DISE vs DISEThreads")
    plt.legend()
    plt.grid()
    plt.tight_layout()
    plt.savefig("disestress.png")
    plt.close()

    # RobustDISE vs RobustDISE Threads
    robust_dise_results = stress_test("RobustDISE", encrypt_robust_dise, n, threshold, delta)
    robust_threads_results = stress_test("RobustDISE Threads", encrypt_robust_threads, n, threshold, delta)

    # Plot RobustDISE comparison
    plt.figure()
    plt.plot(robust_dise_results["frequency"], robust_dise_results["latency"], label="RobustDISE")
    plt.plot(robust_threads_results["frequency"], robust_threads_results["latency"], label="RobustDISE Threads")
    plt.xlabel("Fréquence d'entrée (req/s)")
    plt.ylabel("Latence moyenne (s)")
    plt.title("Latence moyenne en fonction de la fréquence d'entrée : RobustDISE vs RobustDISE_threads")
    plt.legend()
    plt.grid()
    plt.tight_layout()
    plt.savefig("robuststress.png")
    plt.close()


if __name__ == "__main__":
    compare_protocols()
