import os
import random
import tracemalloc
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Define the directory path
directory_path = '/home/alex/Desktop/T3/Projet S9/DIAE/'

# Step 1: Remove all .txt files in the directory
for filename in os.listdir(directory_path):
    if filename.endswith('.txt'):
        file_path = os.path.join(directory_path, filename)
        os.remove(file_path)
        print(f"Deleted file: {file_path}")

# Step 2: Create a new 'texte.txt' file with 15 random digits
file_path = os.path.join(directory_path, 'texte.txt')
with open(file_path, 'w') as file:
    random_digits = ''.join([str(random.randint(0, 9)) for _ in range(15)])
    file.write(random_digits)
    print(f"Created file: {file_path} with content: {random_digits}")

# Define parameters for key sharing
data_nodes_nb = 8  # Number of nodes
t = 8  # Minimum number of nodes required to reconstruct

# Start memory tracking
tracemalloc.start()

# Generate symmetric encryption key
symmetric_key = os.urandom(32)  # 256-bit key
print("Clé symétrique générée:", symmetric_key.hex())

# Generate AES encryption key and IV for encrypting the symmetric key
aes_key = os.urandom(32)  # AES 256-bit key
iv = os.urandom(12)  # 12-byte IV for AES-GCM
backend = default_backend()
cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=backend)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(symmetric_key) + encryptor.finalize()
print("Clé AES utilisée pour chiffrer la clé symétrique:", aes_key.hex())
print(f"IV: {iv.hex()}")
print("Clé symétrique chiffrée:", ciphertext.hex())
print(f"Tag (pour l'intégrité) généré: {encryptor.tag.hex()}")

# Function to share the encrypted symmetric key among nodes
def share_key_among_nodes(key, nodes):
    key_length = len(key)
    share_size = key_length // nodes
    key_shares = [(i, key[i * share_size:(i + 1) * share_size]) for i in range(nodes)]
    random.shuffle(key_shares)
    return key_shares

# Function to reconstruct the key from shares
def reconstruct_key_from_shares(key_shares, nodes):
    key_shares_sorted = sorted(key_shares, key=lambda x: x[0])
    reconstructed_key = b''.join([share for _, share in key_shares_sorted])
    return reconstructed_key

# Share the AES encryption key
key_shares = share_key_among_nodes(aes_key, data_nodes_nb)
print(f"\nNombre de parts générées pour la clé: {len(key_shares)}")
for index, (original_index, share) in enumerate(key_shares):
    print(f"Noeud {index + 1}: Partie de la clé (Index original {original_index}): {share.hex()}")

# Reconstruct the AES key from shares
reconstructed_key = reconstruct_key_from_shares(key_shares, data_nodes_nb)
print("\nClé AES reconstituée:", reconstructed_key.hex())

# Encrypt the file with the symmetric key
def encrypt_file(file_path, key):
    iv = os.urandom(12)  # Generate IV for file encryption
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()

    encrypted_file_path = file_path.replace('.txt', '_encrypted.txt')
    with open(file_path, 'rb') as f, open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv)  # Write IV at the beginning
        while chunk := f.read(1024):
            encrypted_file.write(encryptor.update(chunk))
        encrypted_file.write(encryptor.finalize())
        encrypted_file.write(encryptor.tag)  # Write tag at the end

    print(f"\nFichier chiffré sauvegardé sous: {encrypted_file_path}")
    print(f"IV utilisé pour le chiffrement du fichier: {iv.hex()}")
    print(f"Tag généré pour l'intégrité du fichier: {encryptor.tag.hex()}")
    return iv, encryptor.tag  # Return IV and tag for verification if needed

# Decrypt the encrypted file
def decrypt_file(encrypted_file_path, key):
    decrypted_file_path = encrypted_file_path.replace('_encrypted.txt', '_decrypted.txt')

    with open(encrypted_file_path, 'rb') as encrypted_file:
        iv = encrypted_file.read(12)  # Read IV
        file_data = encrypted_file.read()

        # Separate ciphertext and tag
        ciphertext, tag = file_data[:-16], file_data[-16:]

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        try:
            decrypted_content = decryptor.update(ciphertext) + decryptor.finalize()
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_content)
            print(f"\nFichier déchiffré sauvegardé sous: {decrypted_file_path}")
            print(f"IV utilisé pour le déchiffrement du fichier: {iv.hex()}")
            print(f"Tag vérifié pendant le déchiffrement: {tag.hex()}")
        
        except InvalidTag:
            print("Erreur : le tag est invalide. Vérifiez que la clé, l'IV et le fichier chiffré sont corrects.")

# Perform encryption and decryption to measure memory usage
print("\n--- Début du chiffrement et déchiffrement du fichier ---")
encrypt_file(file_path, reconstructed_key)
decrypt_file(file_path.replace('.txt', '_encrypted.txt'), reconstructed_key)

# Measure and display RAM usage in KB
current, peak = tracemalloc.get_traced_memory()
print(f"\nConsommation actuelle de RAM: {current / 1024:.2f} KB")
print(f"Consommation maximale de RAM pendant l'opération: {peak / 1024:.2f} KB")

# Stop memory tracking
tracemalloc.stop()
