import time
import random
import matplotlib.pyplot as plt
from main import AdaptiveDiSEWithCorruption

def stress_test_with_corruption(n, t, max_documents, corruption_rate, interval_decrement=0.00005, min_interval=0.001):
    """Stress test the Adaptive DiSE implementation with corruption and measure performance."""
    adaptive_dise_system = AdaptiveDiSEWithCorruption(n, t)
    message = "Confidential data for performance testing"
    input_x = "performance-test-input"

    latencies = []
    throughputs = []
    document_counts = []

    current_interval = 0.01  # Initial interval (10 ms)

    for document_number in range(max_documents):
        iteration_latencies = []
        start_time = time.perf_counter()

        # Perform operations within the given interval
        start_iteration = time.perf_counter()
        while time.perf_counter() - start_iteration < current_interval:
            parties = random.sample(range(n), t)

            # Measure latency for a single operation
            op_start_time = time.perf_counter()
            adaptive_dise_system.run_with_corruption(input_x, message, corruption_rate)
            op_end_time = time.perf_counter()

            latency = op_end_time - op_start_time
            iteration_latencies.append(latency)

        # Calculate metrics
        total_time = time.perf_counter() - start_time
        if total_time == 0:
            total_time = 1e-6  # Avoid division by zero

        throughput = len(iteration_latencies) / total_time
        avg_latency = sum(iteration_latencies) / len(iteration_latencies) if iteration_latencies else 0

        latencies.append(avg_latency)
        throughputs.append(throughput)
        document_counts.append(document_number)

        # Decrease the interval for the next iteration
        current_interval = max(min_interval, current_interval - interval_decrement)

        # Stop if latency doubles (saturation)
        if len(latencies) > 1 and avg_latency > latencies[-2] * 2:
            print(f"Saturation detected at document {document_number}. Stopping stress test.")
            break

    return document_counts, latencies, throughputs

def measure_impact_of_corruption(n, t, max_documents, corruption_rates):
    """Measure the impact of different corruption rates on performance."""
    corruption_results = []

    for corruption_rate in corruption_rates:
        print(f"\nTesting with corruption rate: {corruption_rate}")
        document_counts, latencies, throughputs = stress_test_with_corruption(n, t, max_documents, corruption_rate)
        corruption_results.append((corruption_rate, latencies, throughputs))

    return corruption_results

def plot_stress_test_results(document_counts, latencies, throughputs):
    """Plot the results of the stress test."""
    plt.figure(figsize=(18, 12))

    # Plot average latency
    plt.subplot(2, 2, 1)
    plt.plot(document_counts, latencies, marker='o', linestyle='-', color='b')
    plt.xlabel('Number of Encrypted Documents')
    plt.ylabel('Average Latency (seconds)')
    plt.title('Average Latency per Document')
    plt.grid(True)

    # Plot throughput
    plt.subplot(2, 2, 2)
    plt.plot(document_counts, throughputs, marker='o', linestyle='-', color='r')
    plt.xlabel('Number of Encrypted Documents')
    plt.ylabel('Throughput (operations per second)')
    plt.title('Throughput per Document')
    plt.grid(True)

    # Plot latency vs throughput
    plt.subplot(2, 2, (3, 4))
    plt.plot(throughputs, latencies, marker='o', linestyle='-', color='g')
    plt.xlabel('Throughput (operations per second)')
    plt.ylabel('Average Latency (seconds)')
    plt.title('Latency vs Throughput')
    plt.grid(True)

    plt.tight_layout()
    plt.show()

def plot_corruption_impact(corruption_rates, avg_latencies, avg_throughputs):
    """Plot the impact of corruption rates on performance."""
    plt.figure(figsize=(12, 6))

    # Plot average latency vs corruption rate
    plt.subplot(1, 2, 1)
    plt.plot(corruption_rates, avg_latencies, marker='o', linestyle='-', color='b')
    plt.xlabel('Corruption Rate')
    plt.ylabel('Average Latency (seconds)')
    plt.title('Impact of Corruption Rate on Latency')
    plt.grid(True)

    # Plot throughput vs corruption rate
    plt.subplot(1, 2, 2)
    plt.plot(corruption_rates, avg_throughputs, marker='o', linestyle='-', color='r')
    plt.xlabel('Corruption Rate')
    plt.ylabel('Throughput (operations per second)')
    plt.title('Impact of Corruption Rate on Throughput')
    plt.grid(True)

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    # Test configurations
    n = 50
    t = 40
    max_documents = 100
    corruption_rates = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5]

    # Run stress test with a default corruption rate
    document_counts, latencies, throughputs = stress_test_with_corruption(n, t, max_documents, corruption_rate=0.2)
    plot_stress_test_results(document_counts, latencies, throughputs)

    # Measure the impact of different corruption rates
    corruption_results = measure_impact_of_corruption(n, t, max_documents, corruption_rates)
    avg_latencies = [sum(latencies) / len(latencies) for _, latencies, _ in corruption_results]
    avg_throughputs = [sum(throughputs) / len(throughputs) for _, _, throughputs in corruption_results]

    # Plot the impact of corruption rates
    plot_corruption_impact(corruption_rates, avg_latencies, avg_throughputs)
