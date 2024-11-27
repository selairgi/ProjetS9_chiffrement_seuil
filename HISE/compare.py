# import matplotlib.pyplot as plt

# # # Data for t=2
# # messages_t2 = [50, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000]
# # latency_encrypt_t2 = [0.063, 0.125, 0.334, 0.723, 1.623, 3.443, 5.521, 7.025]
# # latency_decrypt_t2 = [0.048, 0.085, 0.187, 0.371, 0.733, 1.464, 2.586, 3.698]
# # throughput_encrypt_t2 = [3550.03, 3873.762, 4220.1763, 4371.5493, 4410.354, 4359.593, 4427.654, 4292.406]
# # throughput_decrypt_t2 = [2723.1301, 2482.7139, 2392.9072, 2216.6226, 2017.2406, 1887.38, 2026.877, 2289.1414]

# # Data for t = 2
# messages_t2 = [50, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000]
# latency_encrypt_t2 = [0.309, 0.990, 1.313, 1.881, 2.064, 2.387, 2.765, 3.099, 3.426, 4.344, 4.872, 5.227, 4.608, 4.993, 5.262, 5.566, 5.888, 6.228, 6.612]
# throughput_encrypt_t2 = [2606.2236, 2421.66, 2433.5586, 2143.5193, 2323.1714, 2360.0452, 2324.0232, 2319.8523, 2348.2134, 2022.489, 1981.0052, 1997.0848, 2413.5354, 2409.6033, 2445.2395, 2436.277, 2449.4324, 2443.7253, 2422.5383]

# latency_decrypt_t2  = [0.176, 0.478, 0.609, 0.767, 0.905, 1.271, 1.240, 1.333, 1.463, 1.651, 1.778, 1.931, 2.086, 2.209, 2.392, 2.853, 2.865, 3.228, 3.296]
# throughput_decrypt_t2 = [4584.8247, 5023.6, 5301.6006, 5201.1797, 5310.111, 4416.783, 5166.1255, 5421.408, 5458.239, 5326.7847, 5416.2603, 5402.119, 5382.2026, 5438.3013, 5353.107, 4781.9126, 5051.2275, 4720.786, 4901.9395]


# # First graph: Latency vs Number of Messages for t=2
# plt.figure(figsize=(10, 6))
# plt.plot(messages_t2, latency_encrypt_t2, label="Encryption Latency (t=2)", marker='o')
# plt.plot(messages_t2, latency_decrypt_t2, label="Decryption Latency (t=2)", marker='o')
# plt.title("Latency vs Number of Messages (t=2)")
# plt.xlabel("Number of Messages")
# plt.ylabel("Latency (s)")
# plt.grid(True)
# plt.legend()
# plt.show()

# # Second graph: Throughput vs Number of Messages for t=2
# plt.figure(figsize=(10, 6))
# plt.plot(messages_t2, throughput_encrypt_t2, label="Encryption Throughput (t=2)", marker='o')
# plt.plot(messages_t2, throughput_decrypt_t2, label="Decryption Throughput (t=2)", marker='o')
# plt.title("Throughput vs Number of Messages (t=2)")
# plt.xlabel("Number of Messages")
# plt.ylabel("Throughput (enc/s)")
# plt.grid(True)
# plt.legend()
# plt.show()

# # Third graph: Latency vs Throughput for t=2
# plt.figure(figsize=(10, 6))
# plt.plot(throughput_encrypt_t2, latency_encrypt_t2, label="Encryption (t=2)", marker='o')
# # plt.plot(throughput_decrypt_t2, latency_decrypt_t2, label="Decryption (t=2)", marker='o')
# plt.title("Latency vs Throughput (t=2)")
# plt.xlabel("Throughput (enc/s)")
# plt.ylabel("Latency (s)")
# plt.grid(True)
# plt.legend()
# plt.show()

import matplotlib.pyplot as plt
import numpy as np

# Data preparation for encryption
messages = [50, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000]
latency_encryption = {
    2: [0.315, 1.134, 1.523, 1.651, 2.118, 2.447, 2.860, 3.149, 3.471, 4.110, 4.412, 4.818, 5.176, 5.578, 5.941, 6.356, 6.711, 7.030, 7.526],
    # 4: [0.290, 1.004, 1.326, 1.701, 2.179, 2.562, 2.868, 3.228, 3.623, 4.234, 4.700, 5.393, 5.653, 6.068, 6.320, 5.883, 6.032, 6.374, 6.761],
    # 6: [0.266, 0.892, 1.187, 1.486, 1.894, 2.211, 2.598, 2.891, 3.161, 3.687, 4.067, 4.354, 5.660, 5.462, 5.441, 5.898, 6.217, 6.374, 6.698],
    # 8: [0.268, 0.895, 1.187, 1.490, 1.905, 2.294, 2.529, 2.857, 3.538, 3.912, 4.061, 4.598, 4.720, 5.030, 5.398, 5.893, 6.121, 6.383, 6.610]
}
throughput_encryption = {
    2: [2612.164, 2149.3032, 2129.6292, 2486.6042, 2322.8657, 2347.9248, 2297.8977, 2351.068, 2346.1167, 2202.8965, 2223.3389, 2207.69, 2224.8242, 2199.0156, 2203.109, 2191.6829, 2194.1199, 2212.4534, 2183.9167],
#     4: [2898.2813, 2509.8774, 2498.8184, 2460.2905, 2275.6675, 2273.5745, 2237.4636, 2294.596, 2286.2373, 2105.348, 2138.7522, 1967.9813, 2072.9678, 2017.4735, 2060.3418, 2186.97, 2429.0654, 2446.847, 2434.9902],
#     6: [3127.5073, 2756.343, 2750.9292, 2707.5298, 2594.2095, 2591.005, 2598.892, 2534.8376, 2564.3748, 2430.3984, 2445.1914, 2419.118, 2438.0325, 2044.7151, 2265.4524, 2392.0183, 2374.2903, 2390.5583, 2444.433],
#     8: [3081.4373, 2753.6523, 2760.6472, 2769.6633, 2585.45, 2599.4622, 2586.1897, 2522.0503, 2603.7925, 2288.673, 2234.89, 2420.9063, 2340.2131, 2411.8242, 2444.698, 2429.0784, 2363.0422, 2409.546, 2438.144]
}


import matplotlib.pyplot as plt
import numpy as np

# Configuration
colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728']
markers = ['o', 's', '^', 'D']

# Création de la figure avec une disposition personnalisée (2 lignes)
fig = plt.figure(figsize=(15, 12))
# Définir la grille : 2 lignes, 2 colonnes
gs = fig.add_gridspec(2, 2, height_ratios=[1, 1.2])

# Créer les trois axes
ax1 = fig.add_subplot(gs[0, 0])  # Première ligne, première colonne
ax2 = fig.add_subplot(gs[0, 1])  # Première ligne, deuxième colonne
ax3 = fig.add_subplot(gs[1, :])  # Deuxième ligne, toute la largeur

# Graphique 1: Latence vs Nombre de messages
for i, nodes in enumerate([2]):
    ax1.plot(messages, latency_encryption[nodes], 
             label=f'{nodes} nodes',
             color=colors[i],
             marker=markers[i],
             markersize=5,
             linewidth=2)

ax1.set_xlabel('Number of Messages')
ax1.set_ylabel('Latency (seconds)')
ax1.set_title('Latency vs Number of Messages')
ax1.grid(True, linestyle='--', alpha=0.7)
ax1.legend()

# Graphique 2: Débit vs Nombre de messages
for i, nodes in enumerate([2]):
    ax2.plot(messages, throughput_encryption[nodes], 
             label=f'{nodes} nodes',
             color=colors[i],
             marker=markers[i],
             markersize=5,
             linewidth=2)

ax2.set_xlabel('Number of Messages')
ax2.set_ylabel('Throughput (enc/sec)')
ax2.set_title('Throughput vs Number of Messages')
ax2.grid(True, linestyle='--', alpha=0.7)
ax2.legend()

# Graphique 3: Latence vs Débit (graphique plus large en bas)
for i, nodes in enumerate([2]):
    ax3.plot(throughput_encryption[nodes], latency_encryption[nodes], 
             label=f'{nodes} nodes',
             color=colors[i],
             marker=markers[i],
             markersize=5,
             linewidth=2)

ax3.set_xlabel('Throughput (enc/sec)')
ax3.set_ylabel('Latency (seconds)')
ax3.set_title('Latency vs Throughput')
ax3.grid(True, linestyle='--', alpha=0.7)
ax3.legend()

# Ajuster l'espacement
plt.tight_layout()
plt.show()