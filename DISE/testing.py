import time
import random
import matplotlib.pyplot as plt
from master_key import MasterKey
from dist_enc import DistEnc

def measure_performance_with_stress(max_documents, interval_decrement=0.00005, min_interval=0.001):
    n = 50
    m = 40
    master_key = MasterKey()
    master_key.key_gen(n=n)

    dist_enc = DistEnc(master_key, threshold=m)
    message = b"Confidential data"

    latencies = []  # Liste pour stocker la latence moyenne par document
    throughputs = []  # Liste pour stocker les débits par document
    document_counts = []

    current_interval = 0.01  # 10 ms intervalle initial

    for document_number in range(max_documents):
        iteration_latencies = []
        start_time = time.perf_counter()

        # Effectuer des opérations pendant une période donnée
        start_iteration = time.perf_counter()
        while time.perf_counter() - start_iteration < current_interval:
            parties = random.sample(range(n), m)
            op_start_time = time.perf_counter()
            dist_enc.encrypt(message, parties=parties)
            op_end_time = time.perf_counter()

            # Calcul de la latence pour cette opération
            latency = op_end_time - op_start_time
            iteration_latencies.append(latency)

        # Calcul des métriques
        total_time = time.perf_counter() - start_time

        # Vérifier que total_time est différent de zéro
        if total_time == 0:
            total_time = 1e-6  # Remplacer par une très petite valeur non nulle

        throughput = len(iteration_latencies) / total_time
        avg_latency = sum(iteration_latencies) / len(iteration_latencies) if iteration_latencies else 0

        throughputs.append(throughput)
        latencies.append(avg_latency)
        document_counts.append(document_number)

        # Diminuer l'intervalle de stress pour le prochain document (mais ne jamais aller en dessous de min_interval)
        current_interval = max(min_interval, current_interval - interval_decrement)

        # Condition d'arrêt si la latence double par rapport à la précédente (indicateur de saturation)
        if len(latencies) > 1 and avg_latency > latencies[-2] * 5:
            print(f"Le système a atteint son seuil de saturation à l'itération {document_number}.")
            break

    return document_counts, latencies, throughputs

def plot_results(document_counts, latencies, throughputs):
    # Graphique de la latence moyenne par document
    plt.figure(figsize=(18, 12))

    plt.subplot(2, 2, 1)
    plt.plot(document_counts, latencies, marker='o', linestyle='-', color='b')
    plt.xlabel('Nombre de documents chiffrés')
    plt.ylabel('Latence moyenne (secondes)')
    plt.title('Latence moyenne en fonction du nombre de documents chiffrés')
    plt.grid(True)

    # Graphique du débit par document
    plt.subplot(2, 2, 2)
    plt.plot(document_counts, throughputs, marker='o', linestyle='-', color='r')
    plt.xlabel('Nombre de documents chiffrés')
    plt.ylabel('Débit (opérations par seconde)')
    plt.title('Débit en fonction du nombre de documents chiffrés')
    plt.grid(True)

    # Graphique de la latence en fonction du débit
    plt.subplot(2, 2, (3, 4))
    plt.plot(throughputs, latencies, marker='o', linestyle='-', color='g')
    plt.xlabel('Débit (opérations par seconde)')
    plt.ylabel('Latence moyenne (secondes)')
    plt.title('Latence en fonction du débit')
    plt.grid(True)

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    max_documents = 500  # Nombre de documents à chiffrer
    document_counts, latencies, throughputs = measure_performance_with_stress(max_documents)
    plot_results(document_counts, latencies, throughputs)