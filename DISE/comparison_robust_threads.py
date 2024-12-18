import time
import random
import os
import sys
import matplotlib.pyplot as plt
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from DISE.master_key import MasterKey
from DISE.dist_enc import DistEnc
from DISE.RobustDise import RobustDistEnc
from DISE.RobustDISE_threads import RobustDistEnc as RobustDistEncThreads

# Variables globales
temp_dir = "temp"
file_path = os.path.join(temp_dir, "temp_file.txt")

# Créer un fichier de test commun
def create_test_file(size_kb):
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    with open(file_path, "wb") as f:
        f.write(os.urandom(size_kb * 1024))  # Fichier de `size_kb` Ko

# Fonction de mesure pour RobustDistEnc
def measure_performance_robust_dist_enc(max_documents, threshold, delta):
    n = 50
    master_key = MasterKey()
    master_key.key_gen(n=n)

    robust_dist_enc = RobustDistEnc(master_key, threshold=threshold, delta=delta)
    with open(file_path, "rb") as f:
        message = f.read()

    latencies = []
    throughputs = []
    for _ in range(max_documents):
        parties = random.sample(range(n), threshold + delta)
        start_time = time.perf_counter()
        robust_dist_enc.robust_encrypt(message, parties)
        latency = time.perf_counter() - start_time
        latencies.append(latency)
    throughput = len(latencies) / sum(latencies)
    return latencies, throughput

# Fonction de mesure pour RobustDistEnc_threads
def measure_performance_robust_threads(max_documents, threshold, delta):
    n = 50
    master_key = MasterKey()
    master_key.key_gen(n=n)

    robust_threads = RobustDistEncThreads(master_key, threshold=threshold, delta=delta)
    with open(file_path, "rb") as f:
        message = f.read()

    latencies = []
    throughputs = []
    for _ in range(max_documents):
        parties = random.sample(range(n), threshold + delta)
        start_time = time.perf_counter()
        robust_threads.robust_encrypt(message, parties)
        latency = time.perf_counter() - start_time
        latencies.append(latency)
    throughput = len(latencies) / sum(latencies)
    return latencies, throughput

# Comparaison des deux algorithmes
def plot_comparison(latencies1, throughput1, latencies2, throughput2, file_size_kb):
    plt.figure(figsize=(12, 6))

    plt.subplot(1, 2, 1)
    plt.plot(range(len(latencies1)), latencies1, label='RobustDistEnc (séquentiel)')
    plt.plot(range(len(latencies2)), latencies2, label='RobustDistEnc_threads (multi-threads)')
    plt.xlabel('Nombre d\'itérations')
    plt.ylabel('Latence (secondes)')
    plt.title(f'Comparaison de la latence pour un fichier de {file_size_kb} Ko')
    plt.legend()
    plt.grid(True)

    plt.subplot(1, 2, 2)
    plt.bar(['RobustDistEnc', 'RobustDistEnc_threads'], [throughput1, throughput2], color=['blue', 'orange'])
    plt.ylabel('Débit (opérations par seconde)')
    plt.title(f'Comparaison du débit pour un fichier de {file_size_kb} Ko')
    plt.grid(True)

    plt.tight_layout()
    plt.show()

# Fonction principale
def main():
    file_sizes = [10, 100, 1000]  # Taille des fichiers en Ko
    max_documents = 100
    threshold = 40
    delta = 4

    for size_kb in file_sizes:
        print(f"Création d'un fichier de {size_kb} Ko...")
        create_test_file(size_kb)

        print("Exécution de RobustDistEnc (séquentiel)...")
        latencies_seq, throughput_seq = measure_performance_robust_dist_enc(max_documents, threshold, delta)

        print("Exécution de RobustDistEnc_threads (multi-threads)...")
        latencies_threads, throughput_threads = measure_performance_robust_threads(max_documents, threshold, delta)

        print("Comparaison des résultats...")
        plot_comparison(latencies_seq, throughput_seq, latencies_threads, throughput_threads, size_kb)

if __name__ == "__main__":
    main()
