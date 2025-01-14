# # test_distributed_protocol.py

# import pytest
# import hashlib

# # On importe les classes/fonctions nécessaires
# from hise_avec_threads import Hise
# from distributed_protocol import DistEncryptionServer, DistEncryptionClient
# from structures import Scalar

# @pytest.mark.parametrize("n, t", [
#     (5, 3),
#     (4, 2),
#     (3, 2)
# ])
# def test_hise_distributed_encryption(n, t):
#     """
#     Teste le schéma HiSE en mode distribué avec n serveurs et un seuil t.
#     On lance :
#       1. le setup pour générer les parts,
#       2. la création de n serveurs,
#       3. un client qui chiffre un lot de messages (3 messages),
#       4. un déchiffrement depuis un sous-ensemble t serveurs,
#       5. on vérifie la correspondance entre original et déchiffré.
#     """

#     # 1) Setup initial HiSE
#     proof_params, private_keys, commitments = Hise.setup(n, t)

#     # 2) Création des serveurs
#     servers = []
#     for i in range(n):
#         server_id = i + 1
#         witness = private_keys[i]
#         com = commitments[i]

#         srv = DistEncryptionServer(
#             server_id=server_id,
#             witness=witness,
#             proof_params=proof_params,
#             com=com
#         )
#         servers.append(srv)

#     # 3) Création du client
#     client = DistEncryptionClient(
#         proof_params=proof_params,
#         servers=servers
#     )

#     # Préparation d'un lot de messages
#     messages = [b"Hello World!", b"Distributed Encryption", b"Threshold Crypto"]

#     # Sous-ensemble de t serveurs pour le chiffrement
#     chosen_enc = list(range(1, t + 1))  # ex: [1, 2, 3] si t=3

#     # Lancement du chiffrement
#     encryption_result = client.initiate_encryption(messages, chosen_enc)
#     assert "cipher_tree" in encryption_result, "L'encryption n'a pas renvoyé de cipher_tree"

#     # Vérif : on doit avoir un cipher_tree de taille 2^k >= len(messages)
#     cipher_tree = encryption_result["cipher_tree"]
#     assert len(cipher_tree) >= len(messages), "Le cipher_tree n'a pas la bonne taille"

#     # 4) Déchiffrement
#     #    On sélectionne un (autre) sous-ensemble t serveurs 
#     #    (ici, on peut reprendre chosen_enc ou en choisir un autre)
#     chosen_dec = list(range(n - t + 1, n + 1))  # ex: [3, 4, 5] si n=5, t=3
#     if len(chosen_dec) < t:
#         # Si on n'a pas assez de serveurs dans ce range, on reprend simplement chosen_enc
#         chosen_dec = chosen_enc

#     decrypted_messages = client.initiate_decryption(encryption_result, chosen_dec)

#     # 5) Vérification : messages en clair = messages originaux
#     # Attention : Il peut y avoir un padding final si 2^k > len(messages)
#     # => on s'assure juste que les premiers len(messages) correspondent
#     for i, m in enumerate(messages):
#         dec = decrypted_messages[i]
#         assert dec == m, (
#             f"Le message déchiffré (index={i}) ne correspond pas. "
#             f"Attendu={m}, obtenu={dec}"
#         )

#     # Si on arrive ici sans exception, le test est validé
#     print(f"Test HiSE distribué OK pour n={n}, t={t}.")

# test_distributed_protocol.py

import sys
import hashlib

from hise_avec_threads import Hise
from distributed_protocol import DistEncryptionServer, DistEncryptionClient

def test_distributed_hise_demo(n=5, t=3):
    """
    Démonstration complète du chiffrement distribué (HiSE) avec n serveurs et un seuil t.
    Affiche chaque étape en détail pour comprendre la logique.
    """

    print("=== Etape 1 : Setup initial de HiSE ===")
    print(f" - Nombre de serveurs (n) = {n}, Seuil (t) = {t}")
    # 1) Setup initial
    proof_params, private_keys, commitments = Hise.setup(n, t)
    print("   > Paramètres publics NIZK générés (g, h).")
    print("   > Parts de clés (witness) générées, et engagements Pedersen (com_alpha, com_beta) calculés.\n")

    print("=== Etape 2 : Création des serveurs (DistEncryptionServer) ===")
    servers = []
    for i in range(n):
        server_id = i + 1
        witness = private_keys[i]
        com = commitments[i]

        print(f" - Serveur {server_id}: witness=({witness.α1.value}, {witness.β1.value}), com=...")
        srv = DistEncryptionServer(
            server_id=server_id,
            witness=witness,
            proof_params=proof_params,
            com=com
        )
        servers.append(srv)
    print("   > Tous les serveurs ont été instanciés.\n")

    print("=== Etape 3 : Création du client (DistEncryptionClient) ===")
    client = DistEncryptionClient(proof_params=proof_params, servers=servers)
    print("   > Le client connaît la liste des serveurs et les paramètres publics NIZK.\n")

    print("=== Etape 4 : Préparation d'un lot de messages à chiffrer ===")
    messages = [
        b"Hello World!", 
        b"Distributed Encryption", 
        b"Threshold Crypto"
    ]
    print("   > Messages originaux :")
    for idx, msg in enumerate(messages):
        print(f"     - Message {idx}: {msg}")
    print()

    print("=== Etape 5 : Sélection d'un sous-ensemble de serveurs pour le chiffrement ===")
    chosen_enc = [1, 2, 3]  # on prend 3 serveurs parmi les 5
    print(f"   > On contacte les serveurs avec IDs = {chosen_enc}.\n")

    print("=== Etape 6 : Lancement du chiffrement distribué (initiate_encryption) ===")
    encryption_result = client.initiate_encryption(messages, chosen_enc)
    print("   > Chiffrement terminé. Voici quelques infos importantes :")
    print("      - Racine Merkle (root):", encryption_result["root"])
    print("      - Nombre de messages (N):", encryption_result["N"])
    print("      - Cipher_tree (taille=", len(encryption_result["cipher_tree"]), "):")
    for idx, c in enumerate(encryption_result["cipher_tree"]):
        # On affiche les 16 premiers bytes pour ne pas polluer l'output
        print(f"         Cipher[{idx}]: {c[:16]} ... (len={len(c)})")
    print("      - Serveurs utilisés :", encryption_result["servers_used"])
    print()

    print("=== Etape 7 : Examen du résultat de chiffrement ===")
    print("   > Le client a stocké : 'merkle_paths', 'batch_keys', 'x_w', etc.")
    print("   > On pourrait sauvegarder ce dictionnaire 'encryption_result' dans un fichier JSON.\n")

    print("=== Etape 8 : Déchiffrement depuis un autre sous-ensemble de serveurs ===")
    chosen_dec = [1, 3, 5]  # on choisit par ex. 3 serveurs différents
    print(f"   > On contacte les serveurs IDs = {chosen_dec} pour déchiffrer.")
    decrypted_messages = client.initiate_decryption(encryption_result, chosen_dec)

    print("\n>>> Résultat du déchiffrement :")
    for idx, dec in enumerate(decrypted_messages):
        if dec is None:
            print(f"     - Message {idx}: [Padding ou Vide]")
        else:
            print(f"     - Message {idx}: {dec} (décodé: {dec.decode('utf-8', errors='ignore')})")

    print("\n=== Etape 9 : Vérification finale ===")
    # Compare les messages originaux avec le déchiffré
    all_ok = True
    for i in range(len(messages)):
        if decrypted_messages[i] != messages[i]:
            all_ok = False
            break

    if all_ok:
        print("   > Les messages déchiffrés correspondent aux originaux.")
    else:
        print("   > Attention : Des écarts ont été détectés entre l'original et le déchiffré.")

    print("\n=== Fin de la démonstration. ===\n")


def main():
    """
    Fonction main pour exécuter le test de démo.
    """
    test_distributed_hise_demo(n=5, t=3)

if __name__ == "__main__":
    sys.exit(main())
