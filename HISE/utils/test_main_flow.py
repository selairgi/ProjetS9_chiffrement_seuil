import sys
import os

# Ajoutez le répertoire parent au chemin pour accéder aux modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from merkle import build_merkle_tree, get_merkle_path, validate_merkle_path
from dprf import generate_commitment, generate_keys, eval_dprf, combine_prf_outputs
from encryption import encrypt_fragment, decrypt_fragment
from os import urandom

def test_main_flow(fragments, num_participants):
    """
    Teste le flux complet du protocole HiSE avec un ensemble de fragments donné.
    
    Arguments :
    - fragments : Liste des fragments de données.
    - num_participants : Nombre de participants pour générer les clés.
    """
    # Génération des engagements
    randomness = [urandom(16).hex() for _ in fragments]
    commitments = [generate_commitment(fragment, rnd) for fragment, rnd in zip(fragments, randomness)]

    # Construction de l'arbre de Merkle
    levels = build_merkle_tree(commitments)
    root = levels[-1][0]

    # Génération des clés locales
    keys = generate_keys(num_participants)

    # Chiffrement des fragments
    encrypted_fragments = []
    for fragment, commitment in zip(fragments, commitments):
        prf_outputs = [eval_dprf(key, commitment) for key in keys]
        effective_key = combine_prf_outputs(prf_outputs)
        ciphertext = encrypt_fragment(effective_key, fragment)
        encrypted_fragments.append(ciphertext)

    # Déchiffrement et validation
    for i, ciphertext in enumerate(encrypted_fragments):
        prf_outputs = [eval_dprf(key, commitments[i]) for key in keys]
        effective_key = combine_prf_outputs(prf_outputs)
        decrypted_fragment = decrypt_fragment(effective_key, ciphertext)

        # Validation du chemin Merkle
        path = get_merkle_path(commitments, i)
        is_valid = validate_merkle_path(commitments[i], path, root)

        # Vérifications automatiques
        assert decrypted_fragment == fragments[i], f"Erreur de déchiffrement pour le fragment {i+1}"
        assert is_valid, f"Erreur de validation Merkle pour le fragment {i+1}"
        print(f"Fragment {i+1} : Déchiffrement et validation réussis.")

def run_complex_scenarios():
    """
    Exécute plusieurs scénarios avec différentes tailles de fragments et nombre de participants.
    """
    scenarios = [
        {"fragments": ["Fragment 1", "Fragment 2", "Fragment 3", "Fragment 4"], "num_participants": 3},
        {"fragments": ["D1", "D2", "D3", "D4", "D5", "D6"], "num_participants": 4},
        {"fragments": [f"Data {i}" for i in range(10)], "num_participants": 5},
        {"fragments": [f"Chunk {i}" for i in range(25)], "num_participants": 6},
        {"fragments": [f"Block {i}" for i in range(500)], "num_participants": 8},
    ]

    for idx, scenario in enumerate(scenarios):
        print(f"\n=== Scénario {idx + 1} ===")
        print(f"Fragments : {len(scenario['fragments'])}, Participants : {scenario['num_participants']}")
        test_main_flow(scenario["fragments"], scenario["num_participants"])

if __name__ == "__main__":
    run_complex_scenarios()
