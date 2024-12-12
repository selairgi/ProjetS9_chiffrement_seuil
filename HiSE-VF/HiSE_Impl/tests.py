# source /Users/mohammedhanna/Desktop/HISE_VF2/charm/charm_env/bin/activate

from typing import List
import time
import multiprocessing

from hise import Hise


from charm.toolbox.pairinggroup import PairingGroup


###########################################################################################################
# TEST FUNCTIONS
###########################################################################################################


# Initialize the pairing group
group = PairingGroup('BN254')

def test_enc_latency():
    """Test encryption latency for different configurations"""
    print("\n=== Testing Encryption Latency ===")
    
    rows = [[2,4,6,8]]  # Server configurations
    message_sizes = [50, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000]
    
    results = []
    for row in rows:
        for t in row:
            n = t  # Number of nodes equals threshold
            
            # Generate random messages for testing
            messages = [f"message{i}".encode() for i in range(max(message_sizes))]
            
            for m in message_sizes:
                # Setup
                print(f"\nTesting configuration: {t} nodes, {m} messages")
                pp, keys, coms = Hise.setup(n, t)
                
                # Warmup run
                _ = Hise.dist_gr_enc(messages[:m], pp, keys, coms, t)
                
                # Measure encryption time
                start_time = time.time()
                batch = Hise.dist_gr_enc(messages[:m], pp, keys, coms, t)
                duration = time.time() - start_time
                
                latency = duration * 1000  # Convert to milliseconds
                messages_per_second = m / duration
                
                results.append({
                    'nodes': t,
                    'messages': m,
                    'latency_ms': latency,
                    'throughput': messages_per_second
                })
                
                print(f"Encryption latency for {t} nodes and {m} messages: {latency:.2f} ms")
                print(f"Encryption throughput: {messages_per_second:.2f} messages/second")
    
    return results

def test_dec_latency():
    """Test decryption latency for different configurations"""
    print("\n=== Testing Decryption Latency ===")
    
    rows = [[2,4,6,8]]
    message_sizes = [50, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000]
    
    results = []
    for row in rows:
        for t in row:
            n = t
            
            # Generate random messages
            messages = [f"message{i}".encode() for i in range(max(message_sizes))]
            
            for m in message_sizes:
                print(f"\nTesting configuration: {t} nodes, {m} messages")
                
                # Setup and encryption
                pp, keys, coms = Hise.setup(n, t)
                batch = Hise.dist_gr_enc(messages[:m], pp, keys, coms, t)
                
                # Warmup run
                _ = Hise.dist_gr_dec(batch, pp, keys, coms, t, messages[:m])
                
                # Measure decryption time
                start_time = time.time()
                decrypted = Hise.dist_gr_dec(batch, pp, keys, coms, t, messages[:m])
                duration = time.time() - start_time
                
                latency = duration * 1000  # Convert to milliseconds
                messages_per_second = m / duration
                
                results.append({
                    'nodes': t,
                    'messages': m,
                    'latency_ms': latency,
                    'throughput': messages_per_second
                })
                
                print(f"Decryption latency for {t} nodes and {m} messages: {latency:.2f} ms")
                print(f"Decryption throughput: {messages_per_second:.2f} messages/second")
    
    return results

def parallel_encrypt(args) -> float:
    """Helper function for parallel encryption throughput testing"""
    messages, pp, keys, coms, t = args
    start_time = time.time()
    Hise.dist_gr_enc(messages, pp, keys, coms, t)
    return time.time() - start_time

def parallel_decrypt(args) -> float:
    """Helper function for parallel decryption throughput testing"""
    batch, pp, keys, coms, t, messages = args
    start_time = time.time()
    Hise.dist_gr_dec(batch, pp, keys, coms, t, messages)
    return time.time() - start_time

def test_enc_throughput():
    """Test encryption throughput with parallel processing"""
    print("\n=== Testing Encryption Throughput ===")
    
    num_cpu = multiprocessing.cpu_count()
    print(f"Testing with {num_cpu} CPU cores")
    
    rows = [[2,4,6,8]]
    message_sizes = [50, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000]
    
    results = []
    for row in rows:
        for t in row:
            n = t
            
            for m in message_sizes:
                print(f"\nTesting configuration: {t} nodes, {m} messages")
                
                # Setup
                pp, keys, coms = Hise.setup(n, t)
                messages = [f"message{i}".encode() for i in range(m)]
                
                # Prepare parallel tasks
                args = [(messages, pp, keys, coms, t) for _ in range(num_cpu)]
                
                # Measure throughput using parallel processing
                with multiprocessing.Pool(num_cpu) as pool:
                    start_time = time.time()
                    durations = pool.map(parallel_encrypt, args)
                    total_duration = time.time() - start_time
                
                total_messages = m * num_cpu
                throughput = total_messages / total_duration
                avg_latency = (sum(durations) / len(durations)) * 1000  # ms
                
                results.append({
                    'nodes': t,
                    'messages': m,
                    'parallel_throughput': throughput,
                    'avg_latency_ms': avg_latency
                })
                
                print(f"Parallel encryption throughput: {throughput:.2f} messages/second")
                print(f"Average latency per batch: {avg_latency:.2f} ms")
    
    return results

def test_dec_throughput():
    """Test decryption throughput with parallel processing"""
    print("\n=== Testing Decryption Throughput ===")
    
    num_cpu = multiprocessing.cpu_count()
    print(f"Testing with {num_cpu} CPU cores")
    
    rows = [[2,4,6,8]]
    message_sizes = [50, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000]
    
    results = []
    for row in rows:
        for t in row:
            n = t
            
            for m in message_sizes:
                print(f"\nTesting configuration: {t} nodes, {m} messages")
                
                # Setup
                pp, keys, coms = Hise.setup(n, t)
                messages = [f"message{i}".encode() for i in range(m)]
                batch = Hise.dist_gr_enc(messages, pp, keys, coms, t)
                
                # Prepare parallel tasks
                args = [(batch, pp, keys, coms, t, messages) for _ in range(num_cpu)]
                
                # Measure throughput using parallel processing
                with multiprocessing.Pool(num_cpu) as pool:
                    start_time = time.time()
                    durations = pool.map(parallel_decrypt, args)
                    total_duration = time.time() - start_time
                
                total_messages = m * num_cpu
                throughput = total_messages / total_duration
                avg_latency = (sum(durations) / len(durations)) * 1000  # ms
                
                results.append({
                    'nodes': t,
                    'messages': m,
                    'parallel_throughput': throughput,
                    'avg_latency_ms': avg_latency
                })
                
                print(f"Parallel decryption throughput: {throughput:.2f} messages/second")
                print(f"Average latency per batch: {avg_latency:.2f} ms")
    
    return results

def format_results(results: List[dict]) -> None:
    """Format and display performance results"""
    print("\n=== Performance Results ===")
    
    # Group results by number of nodes
    by_nodes = {}
    for result in results:
        nodes = result['nodes']
        if nodes not in by_nodes:
            by_nodes[nodes] = []
        by_nodes[nodes].append(result)
    
    # Display results for each node configuration
    for nodes, node_results in sorted(by_nodes.items()):
        print(f"\nResults for {nodes} nodes:")
        print("-" * 80)
        print(f"{'Messages':<10} {'Latency (ms)':<15} {'Throughput (msg/s)':<20}")
        print("-" * 80)
        
        for result in sorted(node_results, key=lambda x: x['messages']):
            messages = result['messages']
            latency = result.get('latency_ms', result.get('avg_latency_ms', 0))
            throughput = result.get('throughput', result.get('parallel_throughput', 0))
            
            print(f"{messages:<10} {latency:,.2f}{'':5} {throughput:,.2f}")

if __name__ == "__main__":
    print("Starting HISE performance tests...")
    
    print("\nTesting encryption performance:")
    enc_latency_results = test_enc_latency()
    enc_throughput_results = test_enc_throughput()
    
    print("\nTesting decryption performance:")
    dec_latency_results = test_dec_latency()
    dec_throughput_results = test_dec_throughput()
    
    print("\n=== Final Results ===")
    print("\nEncryption Latency Results:")
    format_results(enc_latency_results)
    
    print("\nEncryption Throughput Results:")
    format_results(enc_throughput_results)
    
    print("\nDecryption Latency Results:")
    format_results(dec_latency_results)
    
    print("\nDecryption Throughput Results:")
    format_results(dec_throughput_results)
