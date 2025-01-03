#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: alex
"""

import os
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

# Définition des paramètres
directory_path = '/home/alex/Desktop/T3/Projet S9/DIAE/'
n = 8  # Nombre total de nœuds
t = int(n/4)  # Seuil de nœuds requis pour reconstruire la clé (au moins 1)
file_size_kb = 0.03125  # Taille des fichiers (en kilo-octets)

def create_random_file(file_path, file_size_kb):
    """
    Crée un fichier avec des données aléatoires de la taille spécifiée en kilo-octets.
    :param file_path: Chemin du fichier à créer.
    :param file_size_kb: Taille du fichier en kilo-octets.
    """
    with open(file_path, 'wb') as f:
        f.write(os.urandom(int(file_size_kb * 1024)))  # Écrit des données aléatoires

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

        # Mesure du temps de partage de la clé
        start_sharing_time = time.time()
        nodes = share_key_among_nodes_threshold(aes_key, n, t)
        sharing_latency = time.time() - start_sharing_time
        print(f"Temps de partage de la clé parmi {n} nœuds avec un seuil de {t} nœuds : {sharing_latency:.6f} secondes.")

        # Reconstruction de la clé
        start_reconstruction_time = time.time()
        reconstructed_key = reconstruct_key_from_shares_threshold(nodes, t)
        reconstruction_latency = time.time() - start_reconstruction_time
        print(f"Temps de reconstruction de la clé : {reconstruction_latency:.6f} secondes.")

        # Chiffrement et déchiffrement
        if reconstructed_key:
            tracemalloc.start()

            total_encryption_time = 0
            total_decryption_time = 0
            
            # Mesurer la latence du chiffrement pour chaque fichier
            for file_path in file_paths:
                start_time = time.time()
                encrypt_file(file_path, reconstructed_key)
                encryption_latency = time.time() - start_time
                total_encryption_time += encryption_latency
                encryption_latencies.append(encryption_latency)

            # Mesurer la latence du déchiffrement pour chaque fichier
            for file_path in file_paths:
                start_time = time.time()
                decrypt_file(file_path.replace('.txt', '_encrypted.txt'), reconstructed_key)
                decryption_latency = time.time() - start_time
                total_decryption_time += decryption_latency
                decryption_latencies.append(decryption_latency)

            display_memory_usage()
            tracemalloc.stop()

            avg_encryption_latency = total_encryption_time / file_count
            avg_decryption_latency = total_decryption_time / file_count
            print(f"Latence moyenne de chiffrement pour cette itération : {avg_encryption_latency:.6f} secondes.")
            print(f"Latence moyenne de déchiffrement pour cette itération : {avg_decryption_latency:.6f} secondes.")

        # Réduction de l'intervalle pour l'itération suivante
        time.sleep(interval)
        interval /= 2  # Divise l'intervalle par 2

    # Génération des graphiques
    plt.figure(figsize=(10, 6))

    # Graphique pour le chiffrement
    plt.subplot(1, 2, 1)
    plt.plot(range(len(encryption_latencies)), encryption_latencies, marker='o', color='b', label="Chiffrement")
    plt.xlabel("Fichiers traités")
    plt.ylabel("Latence (secondes)")
    plt.title("Latence du chiffrement")
    plt.grid(True)
    plt.legend()

    # Graphique pour le déchiffrement
    plt.subplot(1, 2, 2)
    plt.plot(range(len(decryption_latencies)), decryption_latencies, marker='o', color='r', label="Déchiffrement")
    plt.xlabel("Fichiers traités")
    plt.ylabel("Latence (secondes)")
    plt.title("Latence du déchiffrement")
    plt.grid(True)
    plt.legend()

    # Affichage du graphique
    plt.tight_layout()
    plt.savefig(f"{directory_path}/latency_plot.png")  # Enregistre le graphique dans un fichier

    # Affichage des résultats
    print(f"\nLe système n'arrive plus à chiffrer des fichiers de {file_size_kb} KB à partir de {encryption_latencies[-1]*1000:.2f} millisecondes.")
    print(f"Le système n'arrive plus à déchiffrer des fichiers de {file_size_kb} KB à partir de {decryption_latencies[-1]*1000:.2f} millisecondes.")


# Programme principal
if __name__ == "__main__":
    file_count = 10        # Nombre de fichiers à traiter par itération
    initial_interval = 1.0 # Intervalle initial en secondes

    # Nettoyage initial du répertoire
    clean_directory(directory_path)

    # Exécution du stress test
    stress_system(file_count, initial_interval)
