import time
import random
import os
import sys
import os
import matplotlib.pyplot as plt
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from DISE.master_key import MasterKey
from DISE.dist_enc import DistEnc
from DISE.RobustDise import RobustDistEnc
from DIAE.encryption import encrypt_file

# Variables globales
temp_dir = "temp"
file_path = os.path.join(temp_dir, "temp_file.txt")

# Créer le fichier commun de test
def create_test_file(size_kb):
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    with open(file_path, "wb") as f:
        f.write(os.urandom(size_kb * 1024))  # fichier de `size_kb` Ko
# Fonction de mesure de performance pour DIAE avec condition d'arrêt
def measure_performance_diae(max_files, key, interval_decrement=0.00005, min_interval=0.001):
    latencies = []
    throughputs = []
    intervals = []  # Liste pour stocker les intervalles courants

    current_interval = 0.01

    for file_number in range(max_files):
        iteration_latencies = []
        start_iteration = time.perf_counter()

        # Exécuter les opérations dans l'intervalle courant
        while time.perf_counter() - start_iteration < current_interval:
            encrypted_file_path = os.path.join(temp_dir, f"temp_file_encrypted_{file_number}.txt")
            start_time = time.perf_counter()

            # Chiffre le fichier
            encrypt_file(file_path, key)

            # Calcul de la latence pour chaque opération
            op_latency = time.perf_counter() - start_time
            iteration_latencies.append(op_latency)

            # Supprimez le fichier chiffré après chaque itération pour éviter les conflits
            if os.path.exists(encrypted_file_path):
                os.remove(encrypted_file_path)

        # Calcul des métriques pour cet intervalle
        total_time = time.perf_counter() - start_iteration
        throughput = len(iteration_latencies) / total_time if total_time > 0 else 0
        avg_latency = sum(iteration_latencies) / len(iteration_latencies) if iteration_latencies else 0

        throughputs.append(throughput)
        latencies.append(avg_latency)
        intervals.append(current_interval)

        # Réduire l'intervalle pour la prochaine itération
        current_interval = max(min_interval, current_interval - interval_decrement)

        # Condition d'arrêt si la latence moyenne dépasse trois fois la latence minimale
        if len(latencies) > 1 and avg_latency > min(latencies) * 2:
            print(f"DIAE atteint saturation à l'intervalle {current_interval:.5f}.")
            break

    return intervals, latencies, throughputs


# Fonction pour DistEnc avec condition d'arrêt et chiffrement du fichier
def measure_performance_dist_enc(max_documents, interval_decrement=0.00005, min_interval=0.001):
    n = 50
    m = 40
    master_key = MasterKey()
    master_key.key_gen(n=n)

    dist_enc = DistEnc(master_key, threshold=m)

    # Lire le contenu du fichier
    with open(file_path, "rb") as f:
        message = f.read()

    latencies = []
    throughputs = []
    intervals = []  # Liste pour stocker les intervalles courants

    current_interval = 0.01

    for document_number in range(max_documents):
        iteration_latencies = []
        start_time = time.perf_counter()
        
        start_iteration = time.perf_counter()
        while time.perf_counter() - start_iteration < current_interval:
            parties = random.sample(range(n), m)
            op_start_time = time.perf_counter()
            dist_enc.encrypt(message, parties=parties)
            op_end_time = time.perf_counter()
            
            latency = op_end_time - op_start_time
            iteration_latencies.append(latency)

        total_time = time.perf_counter() - start_time
        if total_time == 0:
            total_time = 1e-6

        throughput = len(iteration_latencies) / total_time
        avg_latency = sum(iteration_latencies) / len(iteration_latencies) if iteration_latencies else 0

        throughputs.append(throughput)
        latencies.append(avg_latency)
        intervals.append(current_interval)  # Stockage de l'intervalle courant

        current_interval = max(min_interval, current_interval - interval_decrement)

        # Condition d'arrêt si la latence moyenne dépasse deux fois la latence minimale
        if len(latencies) > 1 and avg_latency > min(latencies) * 2:
            print(f"DistEnc atteint saturation à l'itération {document_number}.")
            break

    return intervals, latencies, throughputs

# Fonction pour RobustDistEnc avec condition d'arrêt et chiffrement du fichier
def measure_performance_robust_dist_enc(max_documents, interval_decrement=0.00005, min_interval=0.001):
    n = 50
    t = 40
    delta = 4
    master_key = MasterKey()
    master_key.key_gen(n=n)

    robust_dist_enc = RobustDistEnc(master_key, threshold=t, delta=delta)

    # Lire le contenu du fichier
    with open(file_path, "rb") as f:
        message = f.read()

    latencies = []
    throughputs = []
    intervals = []  # Liste pour stocker les intervalles courants

    current_interval = 0.01

    for document_number in range(max_documents):
        iteration_latencies = []
        start_iteration = time.perf_counter()
        
        # Exécuter les opérations dans l'intervalle courant
        while time.perf_counter() - start_iteration < current_interval:
            parties = random.sample(range(n), t + delta)
            op_start_time = time.perf_counter()
            robust_dist_enc.robust_encrypt(message, parties)
            op_end_time = time.perf_counter()
            
            latency = op_end_time - op_start_time
            iteration_latencies.append(latency)

        # Calcul des métriques pour cet intervalle
        total_time = time.perf_counter() - start_iteration
        throughput = len(iteration_latencies) / total_time if total_time > 0 else 0
        avg_latency = sum(iteration_latencies) / len(iteration_latencies) if iteration_latencies else 0

        throughputs.append(throughput)
        latencies.append(avg_latency)
        intervals.append(current_interval)

        # Réduire l'intervalle pour la prochaine itération
        current_interval = max(min_interval, current_interval - interval_decrement)

        # Condition d'arrêt si la latence moyenne dépasse trois fois la latence minimale
        if len(latencies) > 1 and avg_latency > min(latencies) * 2:
            print(f"RobustDistEnc atteint saturation à l'intervalle {current_interval:.5f}.")
            break

    return intervals, latencies, throughputs


def plot_comparison(results1, results2, results3, labels, file_size_kb):
    intervals1, latencies1, throughputs1 = results1
    intervals2, latencies2, throughputs2 = results2
    intervals3, latencies3, throughputs3 = results3

    plt.figure(figsize=(18, 12))

    # Ajouter la taille du fichier comme sous-titre global
    plt.suptitle(f"Performance des algorithmes pour un fichier de {file_size_kb} Ko", fontsize=16)

    # Latence moyenne par intervalle courant
    plt.subplot(2, 2, 1)
    plt.plot(intervals1, latencies1, marker='o', linestyle='-', label=labels[0])
    plt.plot(intervals2, latencies2, marker='x', linestyle='--', label=labels[1])
    plt.plot(intervals3, latencies3, marker='s', linestyle=':', label=labels[2])
    plt.xlabel('Intervalle courant (secondes)')
    plt.ylabel('Latence moyenne (secondes)')
    plt.title('Latence moyenne en fonction de l\'intervalle courant')
    plt.legend()
    plt.grid(True)
    plt.gca().invert_xaxis()  # Inverser l'axe des intervalles

    # Débit par intervalle courant
    plt.subplot(2, 2, 2)
    plt.plot(intervals1, throughputs1, marker='o', linestyle='-', label=labels[0])
    plt.plot(intervals2, throughputs2, marker='x', linestyle='--', label=labels[1])
    plt.plot(intervals3, throughputs3, marker='s', linestyle=':', label=labels[2])
    plt.xlabel('Intervalle courant (secondes)')
    plt.ylabel('Débit (opérations par seconde)')
    plt.title('Débit en fonction de l\'intervalle courant')
    plt.legend()
    plt.grid(True)
    plt.gca().invert_xaxis()  # Inverser l'axe des intervalles

    # Latence en fonction du débit
    plt.subplot(2, 1, 2)
    plt.plot(throughputs1, latencies1, marker='o', linestyle='-', color='g', label=labels[0])
    plt.plot(throughputs2, latencies2, marker='x', linestyle='--', color='brown', label=labels[1])
    plt.plot(throughputs3, latencies3, marker='s', linestyle=':', color='purple', label=labels[2])
    plt.xlabel('Débit (opérations par seconde)')
    plt.ylabel('Latence moyenne (secondes)')
    plt.title('Latence en fonction du débit')
    plt.legend()
    plt.grid(True)

    plt.tight_layout(rect=[0, 0, 1, 0.95])  # Ajuster pour laisser de la place au titre global
    plt.show()


def run_all_tests_and_plot():
    file_sizes = [10, 100, 1000]  # Taille des fichiers en Ko
    labels = ["DistEnc", "RobustDistEnc", "DIAE"]

    for size_kb in file_sizes:
        print(f"Création du fichier de {size_kb} Ko...")
        create_test_file(size_kb)

        max_documents = 500
        key = os.urandom(32)  # Clé aléatoire pour AES-GCM

        # Exécution des trois algorithmes
        print("Exécution de DistEnc...")
        results_dist_enc = measure_performance_dist_enc(max_documents)
        
        print("Exécution de RobustDistEnc...")
        results_robust_dist_enc = measure_performance_robust_dist_enc(max_documents)
        
        print("Exécution de DIAE...")
        results_diae = measure_performance_diae(max_documents, key)
        
        # Comparaison des résultats
        print(f"Tracé des résultats pour un fichier de {size_kb} Ko...")
        plot_comparison(results_dist_enc, results_robust_dist_enc, results_diae, labels=labels, file_size_kb=size_kb)


if __name__ == "__main__":
    # Exécuter les tests pour différentes tailles de fichier
    run_all_tests_and_plot()
