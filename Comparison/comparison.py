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
def create_test_file():
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    with open(file_path, "wb") as f:
        f.write(os.urandom(1024 * 10))  # fichier de 10 Ko

# Fonction de mesure de performance pour DIAE avec condition d'arrêt
def measure_performance_diae(max_files, key):
    latencies = []
    throughputs = []
    file_counts = []

    for file_number in range(max_files):
        encrypted_file_path = os.path.join(temp_dir, f"temp_file_encrypted_{file_number}.txt")
        start_time = time.perf_counter()

        # Chiffre le fichier
        encrypt_file(file_path, key)

        # Calcul des métriques
        total_time = time.perf_counter() - start_time
        latency = total_time
        throughput = 1 / total_time if total_time > 0 else 0

        latencies.append(latency)
        throughputs.append(throughput)
        file_counts.append(file_number)

        # Condition d'arrêt si la latence double par rapport à la latence minimale
        if len(latencies) > 1 and latency > min(latencies) * 2:
            print(f"DIAE atteint saturation à l'itération {file_number}.")
            break

        # Supprimez le fichier chiffré après chaque itération pour éviter les conflits
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)

    return file_counts, latencies, throughputs

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
    document_counts = []

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
        document_counts.append(document_number)

        current_interval = max(min_interval, current_interval - interval_decrement)

        # Condition d'arrêt si la latence moyenne dépasse deux fois la latence minimale
        if len(latencies) > 1 and avg_latency > min(latencies) * 2:
            print(f"DistEnc atteint saturation à l'itération {document_number}.")
            break

    return document_counts, latencies, throughputs

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
    document_counts = []

    current_interval = 0.01

    for document_number in range(max_documents):
        iteration_latencies = []
        start_time = time.perf_counter()
        
        start_iteration = time.perf_counter()
        while time.perf_counter() - start_iteration < current_interval:
            parties = random.sample(range(n), t + delta)
            op_start_time = time.perf_counter()
            robust_dist_enc.robust_encrypt(message, parties)
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
        document_counts.append(document_number)

        current_interval = max(min_interval, current_interval - interval_decrement)

        # Condition d'arrêt si la latence moyenne dépasse deux fois la latence minimale
        if len(latencies) > 1 and avg_latency > min(latencies) * 2:
            print(f"RobustDistEnc atteint saturation à l'itération {document_number}.")
            break

    return document_counts, latencies, throughputs

# Fonction pour tracer la comparaison
def plot_comparison(results1, results2, results3, labels):
    document_counts1, latencies1, throughputs1 = results1
    document_counts2, latencies2, throughputs2 = results2
    file_counts3, latencies3, throughputs3 = results3

    plt.figure(figsize=(18, 12))

    # Latence moyenne par document
    plt.subplot(2, 2, 1)
    plt.plot(document_counts1, latencies1, marker='o', linestyle='-', color='b', label=labels[0])
    plt.plot(document_counts2, latencies2, marker='o', linestyle='--', color='orange', label=labels[1])
    plt.plot(file_counts3, latencies3, marker='o', linestyle=':', color='purple', label=labels[2])
    plt.xlabel('Nombre de documents/fichiers chiffrés')
    plt.ylabel('Latence moyenne (secondes)')
    plt.title('Latence moyenne en fonction du nombre de documents/fichiers chiffrés')
    plt.legend()
    plt.grid(True)

    # Débit par document
    plt.subplot(2, 2, 2)
    plt.plot(document_counts1, throughputs1, marker='o', linestyle='-', color='r', label=labels[0])
    plt.plot(document_counts2, throughputs2, marker='o', linestyle='--', color='green', label=labels[1])
    plt.plot(file_counts3, throughputs3, marker='o', linestyle=':', color='purple', label=labels[2])
    plt.xlabel('Nombre de documents/fichiers chiffrés')
    plt.ylabel('Débit (opérations par seconde)')
    plt.title('Débit en fonction du nombre de documents/fichiers chiffrés')
    plt.legend()
    plt.grid(True)

    # Latence en fonction du débit
    plt.subplot(2, 2, (3, 4))
    plt.plot(throughputs1, latencies1, marker='o', linestyle='-', color='g', label=labels[0])
    plt.plot(throughputs2, latencies2, marker='o', linestyle='--', color='brown', label=labels[1])
    plt.plot(throughputs3, latencies3, marker='o', linestyle=':', color='purple', label=labels[2])
    plt.xlabel('Débit (opérations par seconde)')
    plt.ylabel('Latence moyenne (secondes)')
    plt.title('Latence en fonction du débit')
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    # Création du fichier de test avant d'exécuter les algorithmes
    create_test_file()
    
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
    plot_comparison(results_dist_enc, results_robust_dist_enc, results_diae, labels=["DistEnc", "RobustDistEnc", "DIAE"])
