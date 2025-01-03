import secrets
import time
import psutil
import gc
import hashlib


# Simulated node attributes and policies
node_attributes = {
    1: ["role:admin", "location:EU"],
    2: ["role:user", "location:US"],
    3: ["role:admin", "location:US"],
    4: ["role:manager", "location:EU"],
    5: ["role:engineer", "location:ASIA"]
}

access_policy = ["role:admin", "location:EU"]


# Helper to check if a node meets the access policy

def can_encrypt(node_id, policy):
    return all(attr in node_attributes.get(node_id, []) for attr in policy)


# Shamir Secret Sharing implementation
def generate_shamir_coefficients(secret, threshold, prime):
    return [secret] + [secrets.randbelow(prime) for _ in range(threshold - 1)]



def evaluate_polynomial(coefficients, x, prime):
    result = 0
    for power, coeff in enumerate(coefficients):
        result += coeff * pow(x, power, prime)
        result %= prime
    return result


# DPRF for DiAE
def dprf_eval(secret_share: int, x: int) -> int:
    key = hashlib.sha256(str(secret_share).encode() + str(x).encode()).digest()
    return int.from_bytes(key, 'big') % (2**127)



def encrypt_file_dprf(secret_share: int, file_path: str, output_path: str, node_id: int):
    with open(file_path, 'rb') as f:
        data = f.read()

    dprf_key = dprf_eval(secret_share, x=node_id)
    key_bytes = dprf_key.to_bytes(32, 'big')

    start_time = time.time()
    encrypted_data = bytes([data[i] ^ key_bytes[i % 32] for i in range(len(data))])
    end_time = time.time()

    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

    return (end_time - start_time) * 1000.0



def decrypt_file_dprf(secret_share: int, file_path: str, output_path: str, node_id: int):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    dprf_key = dprf_eval(secret_share, x=node_id)
    key_bytes = dprf_key.to_bytes(32, 'big')

    start_time = time.time()
    decrypted_data = bytes([encrypted_data[i] ^ key_bytes[i % 32] for i in range(len(encrypted_data))])
    end_time = time.time()

    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    return (end_time - start_time) * 1000.0



def get_memory_usage():
    process = psutil.Process()
    gc.collect()
    time.sleep(0.05)
    memory_samples = []
    for _ in range(10):
        memory_samples.append(process.memory_info().rss)
        time.sleep(0.01)
    return max(memory_samples) / 1024


if __name__ == "__main__":
    node_sizes = [8, 12, 24, 40]
    file_sizes_kb = [1, 10, 100, 1000]

    for size in file_sizes_kb:
        input_file = f"input_file_{size}KB.bin"
        output_file = f"encrypted_file_{size}KB.bin"
        decrypted_file = f"decrypted_file_{size}KB.bin"

        with open(input_file, 'wb') as f:
            f.write(secrets.token_bytes(size * 1024))

        print(f"Generated a {size} KB input file: {input_file}")

        for num_parties in node_sizes:
            thresholds = {
                "n/4": max(1, int(num_parties / 4)),
                "n/3": max(1, int(num_parties / 3)),
                "2n/3": max(1, int(2 * num_parties / 3)),
                "n": num_parties
            }
            for threshold_name, threshold in thresholds.items():
                print(f"\nTesting with n={num_parties}, threshold={threshold_name} (t={threshold})")
                prime = 2**127 - 1
                secret = secrets.randbelow(prime)
                gc.collect()
                time.sleep(0.1)
                initial_ram = get_memory_usage()

                shares = []
                for i in range(1, num_parties + 1):
                    coefficients = generate_shamir_coefficients(secret, threshold, prime)
                    share = evaluate_polynomial(coefficients, i, prime)
                    shares.append((i, share))
                
                gc.collect()
                time.sleep(0.1)
                final_ram = get_memory_usage()
                ram_used_for_shares = max(0, final_ram - initial_ram)
                total_enc_times = []
                total_dec_times = []

                for i in range(100):  # Perform 100 encryptions and decryptions for averaging
                    node_id = (i % num_parties) + 1
                    if can_encrypt(node_id, access_policy):
                        enc_time = encrypt_file_dprf(secret, input_file, output_file, node_id)
                        total_enc_times.append(enc_time)

                for i in range(100):
                    node_id = (i % num_parties) + 1
                    dec_time = decrypt_file_dprf(secret, output_file, decrypted_file, node_id)
                    total_dec_times.append(dec_time)

                avg_enc_time = sum(total_enc_times) / len(total_enc_times)
                avg_dec_time = sum(total_dec_times) / len(total_dec_times)
                print(f"RAM used for generating shares: {ram_used_for_shares:.2f} KB")
                print(f"Average encryption time (over 100 encryptions for {size} KB): {avg_enc_time:.2f} ms")
                print(f"Average decryption time (over 100 decryptions for {size} KB): {avg_dec_time:.2f} ms")