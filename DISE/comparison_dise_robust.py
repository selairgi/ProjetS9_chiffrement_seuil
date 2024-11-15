import time
import random
import matplotlib.pyplot as plt
from master_key import MasterKey
from dist_enc import DistEnc
from RobustDise import RobustDistEnc

def measure_performance_dist_enc(max_documents, interval_decrement=0.00005, min_interval=0.001):
    n = 50
    m = 40
    master_key = MasterKey()
    master_key.key_gen(n=n)

    dist_enc = DistEnc(master_key, threshold=m)
    message = b"Confidential data"

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

        if len(latencies) > 1 and avg_latency > latencies[-2] * 5:
            print(f"DistEnc atteint saturation à l'itération {document_number}.")
            break

    return document_counts, latencies, throughputs

def measure_performance_robust_dist_enc(max_documents, interval_decrement=0.00005, min_interval=0.001):
    n = 50
    t = 40
    delta = 4
    master_key = MasterKey()
    master_key.key_gen(n=n)

    robust_dist_enc = RobustDistEnc(master_key, threshold=t, delta=delta)
    message = b"Confidential data"

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

        if len(latencies) > 1 and avg_latency > latencies[-2] * 2:
            print(f"RobustDistEnc atteint saturation à l'itération {document_number}.")
            break

    return document_counts, latencies, throughputs

def plot_comparison(results1, results2, labels):
    document_counts1, latencies1, throughputs1 = results1
    document_counts2, latencies2, throughputs2 = results2

    plt.figure(figsize=(18, 12))

    # Latence moyenne par document
    plt.subplot(2, 2, 1)
    plt.plot(document_counts1, latencies1, marker='o', linestyle='-', color='b', label=labels[0])
    plt.plot(document_counts2, latencies2, marker='o', linestyle='--', color='orange', label=labels[1])
    plt.xlabel('Nombre de documents chiffrés')
    plt.ylabel('Latence moyenne (secondes)')
    plt.title('Latence moyenne en fonction du nombre de documents chiffrés')
    plt.legend()
    plt.grid(True)

    # Débit par document
    plt.subplot(2, 2, 2)
    plt.plot(document_counts1, throughputs1, marker='o', linestyle='-', color='r', label=labels[0])
    plt.plot(document_counts2, throughputs2, marker='o', linestyle='--', color='purple', label=labels[1])
    plt.xlabel('Nombre de documents chiffrés')
    plt.ylabel('Débit (opérations par seconde)')
    plt.title('Débit en fonction du nombre de documents chiffrés')
    plt.legend()
    plt.grid(True)

    # Latence en fonction du débit
    plt.subplot(2, 2, (3, 4))
    plt.plot(throughputs1, latencies1, marker='o', linestyle='-', color='g', label=labels[0])
    plt.plot(throughputs2, latencies2, marker='o', linestyle='--', color='brown', label=labels[1])
    plt.xlabel('Débit (opérations par seconde)')
    plt.ylabel('Latence moyenne (secondes)')
    plt.title('Latence en fonction du débit')
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    max_documents = 500

    # Exécution des deux algorithmes
    print("Exécution de DistEnc...")
    results_dist_enc = measure_performance_dist_enc(max_documents)
    
    print("Exécution de RobustDistEnc...")
    results_robust_dist_enc = measure_performance_robust_dist_enc(max_documents)
    
    # Comparaison des résultats
    plot_comparison(results_dist_enc, results_robust_dist_enc, labels=["DistEnc", "RobustDistEnc"])
