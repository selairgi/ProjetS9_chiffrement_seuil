import time
import random
import os
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor
from master_key import MasterKey
from dise_threads import DistEncThreads
from dist_enc import DistEnc
from concurrent.futures import ThreadPoolExecutor

# Répertoire temporaire pour les fichiers de test
temp_dir = "temp"
file_path = os.path.join(temp_dir, "temp_file.txt")

# Créer un fichier de test commun
def create_test_file(size_kb):
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    with open(file_path, "wb") as f:
        f.write(os.urandom(size_kb * 1024))  # Fichier de `size_kb` Ko

# Fonction de mesure pour DistEnc (séquentiel)
def measure_performance_dist_enc(max_documents, threshold):
    n = 50
    master_key = MasterKey()
    master_key.key_gen(n=n)

    dist_enc = DistEnc(master_key, threshold=threshold)
    with open(file_path, "rb") as f:
        message = f.read()

    latencies = []
    for _ in range(max_documents):
        parties = random.sample(range(n), threshold)
        start_time = time.perf_counter()
        dist_enc.encrypt(message, parties)
        latency = time.perf_counter() - start_time
        latencies.append(latency)

    throughput = len(latencies) / sum(latencies)
    return latencies, throughput

# Fonction de mesure pour DistEncThreads (multi-threads)
def measure_performance_dist_enc_threads(max_documents, threshold):
    n = 50
    master_key = MasterKey()
    master_key.key_gen(n=n)

    dist_enc_threads = DistEncThreads(master_key, threshold=threshold)
    with open(file_path, "rb") as f:
        message = f.read()

    latencies = []
    num_threads = os.cpu_count()

    with ThreadPoolExecutor(max_workers=num_threads) as thread_pool:  # Crée un pool de threads local
        for _ in range(max_documents):
            parties = random.sample(range(n), threshold)

            start_time = time.perf_counter()
            chunk_size = max(1, len(parties) // num_threads)

            # Crée les threads avec des groupes
            futures = []
            for i in range(0, len(parties), chunk_size):
                subset = parties[i:i + chunk_size]
                futures.extend([
                    thread_pool.submit(
                        dist_enc_threads.pseudo_random_function,
                        dist_enc_threads.master_key.keys[party],
                        message
                    )
                    for party in subset
                ])

            results = [future.result() for future in futures]
            dist_enc_threads.combine(results)  # Combine les résultats
            latency = time.perf_counter() - start_time
            latencies.append(latency)

    throughput = len(latencies) / sum(latencies)
    return latencies, throughput

# Comparaison des deux algorithmes (plot classique)
def plot_comparison(latencies1, throughput1, latencies2, throughput2, file_size_kb):
    plt.figure(figsize=(12, 6))

    # Latence moyenne
    plt.subplot(1, 2, 1)
    plt.plot(range(len(latencies1)), latencies1, label='DistEnc (séquentiel)')
    plt.plot(range(len(latencies2)), latencies2, label='DistEnc_threads (multi-threads)')
    plt.xlabel("Nombre d'itérations")
    plt.ylabel("Latence (secondes)")
    plt.title(f"Comparaison de la latence pour un fichier de {file_size_kb} Ko")
    plt.legend()
    plt.grid(True)

    # Débit
    plt.subplot(1, 2, 2)
    plt.bar(['DistEnc', 'DistEnc_threads'], [throughput1, throughput2], color=['blue', 'orange'])
    plt.ylabel("Débit (opérations par seconde)")
    plt.title(f"Comparaison du débit pour un fichier de {file_size_kb} Ko")
    plt.grid(True)

    plt.tight_layout()
    plt.savefig(f"comparison_{file_size_kb}kb.png")  # Enregistre le graphique
    print(f"Graphique sauvegardé sous comparison_{file_size_kb}kb.png")

# ----------------------------------------------------------------------
# NOUVELLE PARTIE : Test de stress sur la fréquence (requests/second)
# ----------------------------------------------------------------------
def stress_test_dist_enc(threshold, initial_latency, freq_step=2, max_freq=50):
    """
    Teste DistEnc (séquentiel) pour différentes fréquences de chiffrement.
    Retourne deux listes : freqs, avg_latencies
    """
    print("\n=== Début du stress test DistEnc (séquentiel) ===")
    
    # Listes pour stocker les mesures
    freqs = []
    avg_latencies = []

    freq = 1
    best_freq = 0

    while freq <= max_freq:
        nb_documents = freq * 60
        print(f"\nTest avec fréquence = {freq} req/s --> {nb_documents} documents à chiffrer")

        start_time = time.perf_counter()
        latencies, _ = measure_performance_dist_enc(nb_documents, threshold)
        total_time = time.perf_counter() - start_time

        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        print(f"  - Temps total = {total_time:.2f} s pour {nb_documents} opérations")
        print(f"  - Latence moyenne = {avg_latency:.6f} s (initiale={initial_latency:.6f} s)")

        # On enregistre la fréquence et la latence moyenne
        freqs.append(freq)
        avg_latencies.append(avg_latency)

        # Critère d'arrêt 1 : dépassement des 60 s
        if total_time > 60:
            print("  => STOP : on dépasse 1 minute pour traiter ce batch.")
            break

        # Critère d'arrêt 2 : latence moyenne > 2 × latence initiale
        if avg_latency > 2 * initial_latency:
            print("  => STOP : la latence moyenne dépasse 2 fois la latence initiale.")
            break

        best_freq = freq
        freq += freq_step

    print(f"==> La plus haute fréquence soutenable pour DistEnc (séquentiel) est {best_freq} requests/s\n")
    
    # On retourne les listes pour pouvoir les tracer
    return freqs, avg_latencies


def stress_test_dist_enc_threads(threshold, initial_latency, freq_step=2, max_freq=20):
    """
    Teste DistEncThreads (multi-threads) pour différentes fréquences de chiffrement.
    Retourne deux listes : freqs, avg_latencies
    """
    print("\n=== Début du stress test DistEnc (multi-threads) ===")

    freqs = []
    avg_latencies = []

    freq = 1
    best_freq = 0

    while freq <= max_freq:
        nb_documents = freq * 60
        print(f"\nTest avec fréquence = {freq} req/s --> {nb_documents} documents à chiffrer")

        start_time = time.perf_counter()
        latencies, _ = measure_performance_dist_enc_threads(nb_documents, threshold)
        total_time = time.perf_counter() - start_time

        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        print(f"  - Temps total = {total_time:.2f} s pour {nb_documents} opérations")
        print(f"  - Latence moyenne = {avg_latency:.6f} s (initiale={initial_latency:.6f} s)")

        freqs.append(freq)
        avg_latencies.append(avg_latency)

        if total_time > 60:
            print("  => STOP : on dépasse 1 minute pour traiter ce batch.")
            break
            
        if avg_latency > 2 * min(avg_latencies):
            print("  => STOP : la latence moyenne dépasse 2 fois la latence initiale.")
            break

        best_freq = freq
        freq += freq_step

    print(f"==> La plus haute fréquence soutenable pour DistEnc (multi-threads) est {best_freq} requests/s\n")

    return freqs, avg_latencies

# ----------------------------------------------------------------------
# FONCTION PRINCIPALE
# ----------------------------------------------------------------------
def main():
    """
    Exemple d'utilisation :
    1) On crée des fichiers de différentes tailles (1, 10, 100, 1000 Ko).
    2) On fait un test classique (plot) avec un nombre fixe de documents.
    3) On fait ensuite un test de stress sur 1 seule taille de fichier (par ex. 10 Ko).
       - Pour DistEnc (séquentiel) et DistEncThreads (multi-threads).
    """
    file_sizes = [1, 10, 100, 1000]  # Taille des fichiers en Ko
    max_documents = 100
    threshold = 49

    # 1) Comparison classique (comme avant)
    """
    for size_kb in file_sizes:
        print(f"Création d'un fichier de {size_kb} Ko...")
        create_test_file(size_kb)

        print("Exécution de DistEnc (séquentiel)...")
        latencies_seq, throughput_seq = measure_performance_dist_enc(max_documents, threshold)

        print("Exécution de DistEnc_threads (multi-threads)...")
        latencies_threads, throughput_threads = measure_performance_dist_enc_threads(max_documents, threshold)

        print("Comparaison des résultats...")
        plot_comparison(latencies_seq, throughput_seq, latencies_threads, throughput_threads, size_kb)
"""
    # ------------------------------------------------------------------
    # --- 2) Test de stress sur 10 Ko (par exemple) ---

    chosen_size = 1
    print(f"\n=== Test de stress sur un fichier de {chosen_size} Ko ===")
    create_test_file(chosen_size)

    # On récupère la latence initiale avec un faible nombre de documents
    print("\nMesure de la latence initiale DistEnc (séquentiel)...")
    latencies_seq_init, _ = measure_performance_dist_enc(10, threshold)
    initial_latency_seq = sum(latencies_seq_init) / len(latencies_seq_init)

    print("Mesure de la latence initiale DistEnc_threads (multi-threads)...")
    latencies_threads_init, _ = measure_performance_dist_enc_threads(10, threshold)
    initial_latency_threads = sum(latencies_threads_init) / len(latencies_threads_init)

    # Stress test DistEnc
    freqs_seq, latencies_seq = stress_test_dist_enc(threshold, initial_latency_seq, freq_step=2, max_freq=20)
    # Stress test DistEncThreads
    freqs_thr, latencies_thr = stress_test_dist_enc_threads(threshold, initial_latency_threads, freq_step=2, max_freq=20)

    # --- 3) Plot du résultat du stress test ---
    plt.figure(figsize=(6, 4))
    plt.plot(freqs_seq, latencies_seq, '-o', label='DISE')
    plt.plot(freqs_thr, latencies_thr, '-o', label='DISE Threads')
    plt.xlabel("Fréquence d'entrée (req/s)")
    plt.ylabel("Latence moyenne (s)")
    plt.title("Latence moyenne en fonction de la fréquence d'entrée : DISE vs DISE Threads")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig("stress_test_comparison.png")
    print("Graphique de stress test sauvegardé sous stress_test_comparison.png")

if __name__ == "__main__":
    main()
