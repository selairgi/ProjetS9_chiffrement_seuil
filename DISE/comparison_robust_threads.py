import time
import random
import os
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor
import os
import sys
import csv  # Pour l'export CSV
import matplotlib.pyplot as plt
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# On importe vos 2 classes "RobustDistEnc" et "RobustDistEncThreads"
# (Assurez-vous d'importer le bon chemin selon votre structure de dossiers)
from RobustDise import RobustDistEnc       # le fichier "robust_dise.py"
from RobustDISE_threads import RobustDistEnc as RobustDistEncThreads  # le fichier "robust_dise_threads.py"

# Pour la génération de clés
from master_key import MasterKey


# ----------------------------------------------------------------------
#             1) Fonctions de mesure de performance
# ----------------------------------------------------------------------
def measure_performance_robust_dist_enc(max_documents, threshold, delta):
    """
    Mesure les latences (et throughput) pour la version séquentielle de RobustDistEnc.
    """
    n = 50
    master_key = MasterKey()
    master_key.key_gen(n=n)

    # On crée l'instance robustDistEnc
    robust_dist_enc = RobustDistEnc(master_key, threshold=threshold, delta=delta)

    # On suppose un fichier temp, comme précédemment
    file_path = "temp_file.txt"
    with open(file_path, "rb") as f:
        message = f.read()

    latencies = []
    for _ in range(max_documents):
        # On choisit (threshold + delta) serveurs pour chaque opération
        parties = random.sample(range(n), threshold + delta)

        start_time = time.perf_counter()
        robust_dist_enc.robust_encrypt(message, parties)
        latency = time.perf_counter() - start_time

        latencies.append(latency)

    throughput = len(latencies) / sum(latencies) if latencies else 0
    return latencies, throughput


def measure_performance_robust_dist_enc_threads(max_documents, threshold, delta):
    """
    Mesure les latences (et throughput) pour la version multithreadée de RobustDistEnc.
    """
    n = 50
    master_key = MasterKey()
    master_key.key_gen(n=n)

    # On crée l'instance robustDistEnc "multi-threads"
    robust_dist_enc_threads = RobustDistEncThreads(master_key, threshold=threshold, delta=delta)

    file_path = "temp_file.txt"
    with open(file_path, "rb") as f:
        message = f.read()

    latencies = []
    for _ in range(max_documents):
        parties = random.sample(range(n), threshold + delta)

        start_time = time.perf_counter()
        robust_dist_enc_threads.robust_encrypt(message, parties)
        latency = time.perf_counter() - start_time

        latencies.append(latency)

    throughput = len(latencies) / sum(latencies) if latencies else 0
    return latencies, throughput


# ----------------------------------------------------------------------
#         2) Fonctions de STRESS pour robust_dist_enc
# ----------------------------------------------------------------------
def stress_test_robust_dist_enc(threshold, delta, initial_latency, freq_step=2, max_freq=50):
    """
    Teste la version séquentielle de RobustDistEnc pour différentes fréquences de chiffrement.
    Retourne (freqs, avg_latencies) pour tracer un graphe si besoin.
    """
    print("\n=== Début du stress test RobustDistEnc (séquentiel) ===")

    freqs = []
    avg_latencies = []

    freq = 1
    best_freq = 0

    while freq <= max_freq:
        nb_documents = freq * 60  # f requêtes/s, sur 60s = f*60
        print(f"\nTest avec fréquence = {freq} req/s --> {nb_documents} documents")

        start_time = time.perf_counter()
        latencies, _ = measure_performance_robust_dist_enc(nb_documents, threshold, delta)
        total_time = time.perf_counter() - start_time

        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        print(f"  - Temps total = {total_time:.2f} s")
        print(f"  - Latence moyenne = {avg_latency:.6f} s (initiale={initial_latency:.6f} s)")

        # On enregistre dans nos listes
        freqs.append(freq)
        avg_latencies.append(avg_latency)

        # Critères d'arrêt
        if total_time > 60:
            print("  => STOP : on dépasse 1 minute pour traiter ce batch.")
            break

        if avg_latency > 1.5 * initial_latency:
            print("  => STOP : latence moyenne dépasse 2 fois la latence initiale.")
            break

        best_freq = freq
        freq += freq_step

    print(f"==> La plus haute fréquence soutenable (RobustDistEnc - séquentiel) : {best_freq} req/s\n")
    return freqs, avg_latencies


def stress_test_robust_dist_enc_threads(threshold, delta, initial_latency, freq_step=2, max_freq=50):
    """
    Teste la version multi-threads de RobustDistEnc pour différentes fréquences de chiffrement.
    Retourne (freqs, avg_latencies).
    """
    print("\n=== Début du stress test RobustDistEnc (multi-threads) ===")

    freqs = []
    avg_latencies = []

    freq = 1
    best_freq = 0

    while freq <= max_freq:
        nb_documents = freq * 60
        print(f"\nTest avec fréquence = {freq} req/s --> {nb_documents} documents")

        start_time = time.perf_counter()
        latencies, _ = measure_performance_robust_dist_enc_threads(nb_documents, threshold, delta)
        total_time = time.perf_counter() - start_time

        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        print(f"  - Temps total = {total_time:.2f} s")
        print(f"  - Latence moyenne = {avg_latency:.6f} s (initiale={initial_latency:.6f} s)")

        freqs.append(freq)
        avg_latencies.append(avg_latency)

        if total_time > 60:
            print("  => STOP : on dépasse 1 minute pour traiter ce batch.")
            break

        if avg_latency > 2 * initial_latency:
            print("  => STOP : latence moyenne dépasse 2 fois la latence initiale.")
            break

        best_freq = freq
        freq += freq_step

    print(f"==> La plus haute fréquence soutenable (RobustDistEnc - multi-threads) : {best_freq} req/s\n")
    return freqs, avg_latencies


# ----------------------------------------------------------------------
#         3) Exemple d'utilisation (main)
# ----------------------------------------------------------------------
def main():
    """
    Dans cet exemple :
      - On crée un "fichier" d'une certaine taille pour avoir un message à chiffrer.
      - On calcule la latence initiale pour robustDistEnc et robustDistEncThreads.
      - On lance ensuite un stress test sur chacune des deux versions.
      - On trace enfin un graphe comparatif des latences.
    """

    # On crée un fichier de test simple
    file_path = "temp_file.txt"
    with open(file_path, "wb") as f:
        f.write(os.urandom(1024))  # 1 Ko par exemple

    threshold = 10
    delta = 3

    # --- 1) Latence initiale (petit volume) ---
    print("Mesure de la latence initiale (RobustDistEnc - séquentiel)...")
    latencies_seq_init, _ = measure_performance_robust_dist_enc(10, threshold, delta)
    initial_latency_seq = sum(latencies_seq_init) / len(latencies_seq_init) if latencies_seq_init else 0

    print("Mesure de la latence initiale (RobustDistEnc - multi-threads)...")
    latencies_thr_init, _ = measure_performance_robust_dist_enc_threads(10, threshold, delta)
    initial_latency_thr = sum(latencies_thr_init) / len(latencies_thr_init) if latencies_thr_init else 0

    # --- 2) Stress test (RobustDistEnc) ---
    freqs_seq, latencies_seq = stress_test_robust_dist_enc(threshold, delta, initial_latency_seq, freq_step=2, max_freq=100)

    # --- 3) Stress test (RobustDistEncThreads) ---
    freqs_thr, latencies_thr = stress_test_robust_dist_enc_threads(threshold, delta, initial_latency_thr, freq_step=2, max_freq=100)

    # --- 4) Plot pour comparer ---
    plt.figure(figsize=(6, 4))
    plt.plot(freqs_seq, latencies_seq, '-o', label='RobustDISE')
    plt.plot(freqs_thr, latencies_thr, '-o', label='RobustDISE threads')
    plt.xlabel("Fréquence d'entrée (req/s)")
    plt.ylabel("Latence moyenne (s)")
    plt.title("Latence moyenne en fonction de la fréquence (RobustDISE)")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig("robust_stress_test_comparison.png")
    print("\nGraphique de stress test sauvegardé sous robust_stress_test_comparison.png")


if __name__ == "__main__":
    main()
