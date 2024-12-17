import tracemalloc
import time
import matplotlib
matplotlib.use('Agg')  # Utilise un backend sans affichage pour éviter les erreurs graphiques
import matplotlib.pyplot as plt
from file_operations import clean_directory, create_random_file
from key_management import generate_symmetric_key, generate_aes_key, share_key_among_nodes_threshold, reconstruct_key_from_shares_threshold
from encryption import encrypt_file
from decryption import decrypt_file
from memory_tracking import display_memory_usage
from multiprocessing import Pool

# Définition des paramètres
directory_path = '/home/alex/Desktop/T3/Projet S9/DIAE/'
n = 48  # Nombre total de nœuds
t = 24   # Seuil de nœuds requis pour reconstruire la clé
file_size_kb = 1024  # Taille des fichiers (en kilo-octets)


def process_node(file_path, reconstructed_key):
    """
    Fonction pour traiter le chiffrement et le déchiffrement d'un fichier sur un nœud.
    :param file_path: Chemin du fichier à traiter.
    :param reconstructed_key: Clé reconstruite pour le chiffrement et déchiffrement.
    :return: Tuple (encryption_latency, decryption_latency)
    """
    # Mesurer la latence du chiffrement
    start_time = time.time()
    encrypt_file(file_path, reconstructed_key)
    encryption_latency = time.time() - start_time

    # Mesurer la latence du déchiffrement
    start_time = time.time()
    decrypt_file(file_path.replace('.txt', '_encrypted.txt'), reconstructed_key)
    decryption_latency = time.time() - start_time

    return encryption_latency, decryption_latency


def stress_system(file_count, initial_interval):
    """
    Fonction pour stresser le système en chiffrant et déchiffrant des fichiers à intervalles réduits.
    :param file_count: Nombre de fichiers à traiter.
    :param initial_interval: Intervalle initial entre les itérations (en secondes).
    """
    interval = initial_interval
    encryption_latencies = []
    decryption_latencies = []
    file_sizes = []

    for iteration in range(1, 6):  # Répète le test pour 5 itérations
        print(f"\n--- Itération {iteration}: Intervalle = {interval:.6f} secondes ---")

        # Nettoyage du répertoire
        clean_directory(directory_path)

        # Génération des fichiers aléatoires
        file_paths = []
        for i in range(file_count):
            file_path = f"{directory_path}file_{i}.txt"
            create_random_file(file_path, file_size_kb)
            file_paths.append(file_path)
            file_sizes.append(file_size_kb)  # Ajoute la taille du fichier pour chaque fichier créé

        # Génération de la clé AES et partage
        symmetric_key = generate_symmetric_key()
        aes_key, iv, ciphertext, tag = generate_aes_key(symmetric_key)
        nodes = share_key_among_nodes_threshold(aes_key, n, t)
        reconstructed_key = reconstruct_key_from_shares_threshold(nodes, t)

        # Liste des processus
        if reconstructed_key:
            tracemalloc.start()

            # Utilisation de Pool pour paralléliser les tâches
            with Pool() as pool:
                results = pool.starmap(process_node, [(file_path, reconstructed_key) for file_path in file_paths])

            # Collecte des résultats
            for encryption_latency, decryption_latency in results:
                encryption_latencies.append(encryption_latency)
                decryption_latencies.append(decryption_latency)

            display_memory_usage()
            tracemalloc.stop()

        # Réduction de l'intervalle pour l'itération suivante
        time.sleep(interval)
        interval /= 2  # Divise l'intervalle par 2

    # Génération des graphiques
    plt.figure(figsize=(10, 6))

    # Graphique pour le chiffrement
    plt.subplot(1, 2, 1)
    plt.plot(file_sizes, encryption_latencies, marker='o', color='b', label="Chiffrement")
    plt.xlabel("Taille des fichiers (KB)")
    plt.ylabel("Latence (secondes)")
    plt.title("Latence du chiffrement")
    plt.grid(True)
    plt.legend()

    # Graphique pour le déchiffrement
    plt.subplot(1, 2, 2)
    plt.plot(file_sizes, decryption_latencies, marker='o', color='r', label="Déchiffrement")
    plt.xlabel("Taille des fichiers (KB)")
    plt.ylabel("Latence (secondes)")
    plt.title("Latence du déchiffrement")
    plt.grid(True)
    plt.legend()

    # Affichage du graphique
    plt.tight_layout()
    plt.show()  # Affiche le graphique à l'écran

    # Affichage des résultats
    print(f"\nLe système n'arrive plus à chiffrer des fichiers de {file_size_kb} KB à partir de {encryption_latencies[-1]} secondes.")
    print(f"Le système n'arrive plus à déchiffrer des fichiers de {file_size_kb} KB à partir de {decryption_latencies[-1]} secondes.")


# Programme principal
if __name__ == "__main__":
    file_count = 10        # Nombre de fichiers à traiter par itération
    initial_interval = 1.0 # Intervalle initial en secondes

    # Nettoyage initial du répertoire
    clean_directory(directory_path)

    # Exécution du stress test
    stress_system(file_count, initial_interval)
