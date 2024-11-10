import random
import matplotlib.pyplot as plt
from master_key import MasterKey
from dist_enc import DistEnc
from RobustDise import RobustDistEnc

def find_max_delta(n, t):
    max_delta = 0
    while True:
        try:
            # Créer une instance de RobustDistEnc avec le delta actuel
            master_key = MasterKey()
            master_key.key_gen(n=n)
            robust_dist_enc = RobustDistEnc(master_key, threshold=t, delta=max_delta)

            # Tenter de sélectionner un sous-ensemble robuste
            parties = random.sample(range(n), t + max_delta)
            robust_dist_enc.select_robust_subset(parties)
            max_delta += 1
        except ValueError:
            # Lorsque nous ne pouvons plus augmenter delta, nous arrêtons
            break
    return max_delta - 1

def measure_max_delta_vs_threshold(n, max_threshold):
    thresholds = list(range(1, max_threshold + 1))
    max_deltas = []

    for t in thresholds:
        max_delta = find_max_delta(n, t)
        max_deltas.append(max_delta)
        print(f"Threshold {t}: Max Delta = {max_delta}")

    return thresholds, max_deltas

def plot_max_delta_vs_threshold(thresholds, max_deltas):
    plt.figure(figsize=(10, 6))
    plt.plot(thresholds, max_deltas, marker='o', linestyle='-', color='b')
    plt.xlabel('Seuil (t)')
    plt.ylabel('Maximum Delta Toléré')
    plt.title('Maximum Delta Toléré en fonction du Seuil (t)')
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    n = 50  # Nombre total de serveurs
    max_threshold = 45  # Seuil maximum à tester

    thresholds, max_deltas = measure_max_delta_vs_threshold(n, max_threshold)
    plot_max_delta_vs_threshold(thresholds, max_deltas)
