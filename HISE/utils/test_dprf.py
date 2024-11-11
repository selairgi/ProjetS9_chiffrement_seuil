import sys
import os

# Ajoutez le répertoire parent au chemin pour accéder aux modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dprf import generate_commitment, generate_keys, eval_dprf, combine_prf_outputs

def test_dprf():
    # Étape 1 : Générer un engagement
    fragment = "unique_fragment_id"
    randomness = "random_nonce"
    commitment = generate_commitment(fragment, randomness)
    print(f"Engagement : {commitment}")

    # Étape 2 : Générer des clés
    num_participants = 5
    keys = generate_keys(num_participants)
    print(f"Clés générées : {[key.hex()[:8] for key in keys]}")

    # Étape 3 : Évaluer les PRF
    prf_outputs = [eval_dprf(key, commitment) for key in keys]
    print(f"Sorties DPRF : {[output.hex()[:8] for output in prf_outputs]}")

    # Étape 4 : Combiner les PRF
    effective_key = combine_prf_outputs(prf_outputs)
    print(f"Clé effective combinée : {effective_key.hex()}")

if __name__ == "__main__":
    test_dprf()
