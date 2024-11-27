import time
import os
import matplotlib.pyplot as plt
from main import CyclicGroup, AdaptiveDPRF, ThresholdSymmetricEncryption  # Import your algorithm

# Global variables
temp_dir = "temp"
file_path = os.path.join(temp_dir, "temp_file.txt")

# Create a test file
def create_test_file(size_kb):
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    with open(file_path, "wb") as f:
        f.write(os.urandom(size_kb * 1024))  # Create a file of `size_kb` KB

# Measure performance for your algorithm
def measure_performance_your_algo(max_documents, interval_decrement=0.00005, min_interval=0.001):
    # Initialize cyclic group and your algorithm
    prime = 104729  # Example large prime
    generator = 2   # Generator of the cyclic group
    group = CyclicGroup(prime, generator)
    n, t = 5, 3  # Total participants and threshold
    dprf = AdaptiveDPRF(group, n, t)
    tse = ThresholdSymmetricEncryption(group, dprf)

    # Read the test file
    with open(file_path, "rb") as f:
        message = f.read().decode("latin1")  # Decode to a string for encryption

    latencies = []
    throughputs = []
    intervals = []

    current_interval = 0.01

    for document_number in range(max_documents):
        iteration_latencies = []
        start_iteration = time.perf_counter()

        # Perform operations within the current interval
        while time.perf_counter() - start_iteration < current_interval:
            start_time = time.perf_counter()

            # Encrypt and decrypt using your algorithm
            shares = dprf.shares_u[:t]
            ciphertext, _ = tse.encrypt(message, shares)
            tse.decrypt(ciphertext, shares)

            op_latency = time.perf_counter() - start_time
            iteration_latencies.append(op_latency)

        # Calculate metrics for this interval
        total_time = time.perf_counter() - start_iteration
        throughput = len(iteration_latencies) / total_time if total_time > 0 else 0
        avg_latency = sum(iteration_latencies) / len(iteration_latencies) if iteration_latencies else 0

        throughputs.append(throughput)
        latencies.append(avg_latency)
        intervals.append(current_interval)

        # Decrease the interval for the next iteration
        current_interval = max(min_interval, current_interval - interval_decrement)

        # Stop if the average latency exceeds twice the minimum latency
        if len(latencies) > 1 and avg_latency > min(latencies) * 2:
            print(f"Your algorithm reaches saturation at interval {current_interval:.5f}.")
            break

    return intervals, latencies, throughputs

# Plotting results
def plot_results(intervals, latencies, throughputs, file_size_kb):
    plt.figure(figsize=(12, 8))

    # Add the file size as a title
    plt.suptitle(f"Performance de l'algorithme pour un fichier de {file_size_kb} Ko", fontsize=16)

    # Average latency vs interval
    plt.subplot(2, 1, 1)
    plt.plot(intervals, latencies, marker='o', linestyle='-', label="Latence moyenne")
    plt.xlabel('Intervalle courant (secondes)')
    plt.ylabel('Latence moyenne (secondes)')
    plt.title('Latence moyenne en fonction de l\'intervalle courant')
    plt.legend()
    plt.grid(True)
    plt.gca().invert_xaxis()

    # Throughput vs interval
    plt.subplot(2, 1, 2)
    plt.plot(intervals, throughputs, marker='x', linestyle='--', label="Débit")
    plt.xlabel('Intervalle courant (secondes)')
    plt.ylabel('Débit (opérations par seconde)')
    plt.title('Débit en fonction de l\'intervalle courant')
    plt.legend()
    plt.grid(True)
    plt.gca().invert_xaxis()

    plt.tight_layout(rect=[0, 0, 1, 0.95])  # Adjust for global title
    plt.show()

# Run test and plot results
def run_test_and_plot():
    file_sizes = [1000]  # File sizes in KB

    for size_kb in file_sizes:
        print(f"Creating a {size_kb} KB file...")
        create_test_file(size_kb)

        max_documents = 500

        # Run your algorithm
        print("Running your algorithm...")
        results = measure_performance_your_algo(max_documents)

        # Plot results
        print(f"Plotting results for a {size_kb} KB file...")
        intervals, latencies, throughputs = results
        plot_results(intervals, latencies, throughputs, file_size_kb=size_kb)

if __name__ == "__main__":
    run_test_and_plot()
