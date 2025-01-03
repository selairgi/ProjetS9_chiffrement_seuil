import numpy as np
import pandas as pd
import tracemalloc
import time
import random
import string
from hashlib import sha256

# Simulate DPRF setup
def setup_dprf(n, t):
    secret = random.getrandbits(128)
    shares = [secret ^ random.getrandbits(128) for _ in range(n)]
    return shares

# Simulate DPRF evaluation
def eval_dprf(share, x):
    w = sha256(x.encode()).hexdigest()
    return int(w, 16) ^ share

# Simulate distributed encryption process for a file of 32 bytes
def encrypt_32_bytes(n, t):
    data = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    key_shares = setup_dprf(n, t)
    
    # Simulate distributed DPRF encryption
    x = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    selected_shares = random.sample(key_shares, t)
    
    prf_outputs = [eval_dprf(share, x) for share in selected_shares]
    encrypted_data = ''.join(chr(ord(c) ^ (sum(prf_outputs) % 256)) for c in data)
    
    return encrypted_data

# Measure RAM usage during encryption
def measure_ram_usage(n, t):
    tracemalloc.start()
    start_time = time.time()
    encrypt_32_bytes(n, t)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    ram_usage_kb = peak / 1024
    return round(ram_usage_kb, 2)

# Parameters for testing
nodes = [8, 12, 24, 40]
thresholds = [4, 3, 1]

# Collect data for the table
results = []
for t_ratio in thresholds:
    for n in nodes:
        t = max(1, n // t_ratio)
        ram_usage = measure_ram_usage(n, t)
        results.append([f'N/{t_ratio}', n, f'{ram_usage}ko'])

# Create DataFrame
df = pd.DataFrame(results, columns=['t', 'n', 'ko'])

print(df)
