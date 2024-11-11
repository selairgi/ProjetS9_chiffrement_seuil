import time
from os import urandom
from dprf import generate_keys, eval_dprf, combine_prf_outputs, generate_commitment
from merkle import build_merkle_tree, get_merkle_path, validate_merkle_path

def test_decryption_times():
    """
    Compare le temps de déchiffrement pour DISE et HiSE avec 10 fragments.
    """
    num_fragments = 10
    num_participants = 5  # Nombre de parties participantes
    keys = generate_keys(num_participants)
    
    # Générer les fragments et engagements
    fragments = [f"Fragment_{i}" for i in range(num_fragments)]
    randomness = [urandom(16).hex() for _ in fragments]
    commitments = [generate_commitment(fragment, rnd) for fragment, rnd in zip(fragments, randomness)]
    
    # Construire l'arbre Merkle et calculer les chemins
    levels = build_merkle_tree(commitments)
    root = levels[-1][0]
    paths = [get_merkle_path(commitments, i) for i in range(len(commitments))]

    # --- Temps de Déchiffrement DISE ---
    dise_start = time.time()
    for fragment in fragments:
        # Calcul PRF pour chaque fragment
        prf_outputs = [eval_dprf(key, fragment) for key in keys]
        effective_key = combine_prf_outputs(prf_outputs)
        assert effective_key  # Simulation de déchiffrement
    dise_end = time.time()
    dise_time = (dise_end - dise_start) * 1000  # En ms

    # --- Temps de Déchiffrement HiSE ---
    hise_start = time.time()
    for i, commitment in enumerate(commitments):
        path = paths[i]
        # Calcul PRF pour chaque engagement
        prf_outputs = [eval_dprf(key, commitment) for key in keys]
        effective_key = combine_prf_outputs(prf_outputs)
        assert validate_merkle_path(commitment, path, root)  # Validation chemin Merkle
    hise_end = time.time()
    hise_time = (hise_end - hise_start) * 1000  # En ms

    # --- Résultats ---
    print(f"Temps total pour DISE (10 fragments) : {dise_time:.2f} ms")
    print(f"Temps total pour HiSE (10 fragments) : {hise_time:.2f} ms")

if __name__ == "__main__":
    test_decryption_times()
