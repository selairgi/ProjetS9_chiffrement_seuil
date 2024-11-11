from merkle import build_merkle_tree, visualize_merkle_tree, get_merkle_path, validate_merkle_path
from dprf import generate_commitment, generate_keys, eval_dprf, combine_prf_outputs
from encryption import encrypt_fragment, decrypt_fragment
from os import urandom

def main():
    """
    Exécution principale du protocole HiSE :
    - Génération des engagements.
    - Construction de l'arbre de Merkle.
    - Évaluation DPRF et chiffrement.
    - Déchiffrement et validation de l'intégrité.
    """
    # Étape 1 : Préparation des fragments
    fragments = ["Fragment 1", "Fragment 2", "Fragment 3", "Fragment 4"]
    
    # Étape 2 : Génération des engagements pour chaque fragment
    randomness = [urandom(16).hex() for _ in fragments]
    commitments = [generate_commitment(fragment, rnd) for fragment, rnd in zip(fragments, randomness)]

    # Étape 3 : Construction de l'arbre de Merkle
    levels = build_merkle_tree(commitments)
    root = levels[-1][0]
    visualize_merkle_tree(levels)

    # Étape 4 : Génération des clés locales
    num_participants = 5
    keys = generate_keys(num_participants)

    # Étape 5 : Chiffrement des fragments
    encrypted_fragments = []
    for fragment, commitment in zip(fragments, commitments):
        prf_outputs = [eval_dprf(key, commitment) for key in keys]
        effective_key = combine_prf_outputs(prf_outputs)
        ciphertext = encrypt_fragment(effective_key, fragment)
        encrypted_fragments.append(ciphertext)

    # Étape 6 : Déchiffrement et validation d'intégrité
    for i, ciphertext in enumerate(encrypted_fragments):
        commitment = commitments[i]
        prf_outputs = [eval_dprf(key, commitment) for key in keys]
        effective_key = combine_prf_outputs(prf_outputs)
        decrypted_fragment = decrypt_fragment(effective_key, ciphertext)

        # Validation du chemin Merkle
        path = get_merkle_path(commitments, i)
        is_valid = validate_merkle_path(commitments[i], path, root)

        # Résultats
        print(f"Fragment {i+1} déchiffré : {decrypted_fragment}")
        print(f"Validation Merkle : {'Réussi' if is_valid else 'Échoué'}")

if __name__ == "__main__":
    main()
