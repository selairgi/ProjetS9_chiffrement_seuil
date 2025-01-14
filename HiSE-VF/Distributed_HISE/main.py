# main.py
import sys

# On importe le setup de HiSE et les nouvelles classes du protocole distribué
from hise_avec_threads import Hise
from distributed_protocol import DistEncryptionServer, DistEncryptionClient

def main():
    """
    Exemple d'utilisation des classes DistEncryptionServer et DistEncryptionClient
    pour un chiffrement/déchiffrement distribué par seuil.
    """
    # Paramètres du schéma : n serveurs au total, seuil t
    n = 5
    t = 3

    # 1) Setup initial : on génère les polynômes pour alpha et beta
    #    ainsi que les engagements correspondants, via la fonction Hise.setup(...)
    proof_params, private_keys, commitments = Hise.setup(n, t)

    # private_keys[i] est un HiseNizkWitness (α_i, α_rand, β_i, β_rand)
    # commitments[i] est le tuple (com_alpha, com_beta)

    # 2) Création de n serveurs (DistEncryptionServer)
    servers = []
    for i in range(n):
        server_id = i + 1  # identifiant du serveur (1..n)
        witness = private_keys[i]
        com = commitments[i]
        # Instanciation du serveur avec sa part de secret
        server = DistEncryptionServer(
            server_id=server_id,
            witness=witness,
            proof_params=proof_params,
            com=com
        )
        servers.append(server)

    # 3) Création du client (DistEncryptionClient)
    #    On lui fournit les paramètres publics NIZK et la liste des serveurs
    client = DistEncryptionClient(
        proof_params=proof_params,
        servers=servers
    )

    # 4) Exemple : on chiffre un lot de messages
    messages = [
        b"Hello World!", 
        b"Distributed Encryption", 
        b"Threshold Crypto"
    ]

    # On choisit t=3 serveurs (IDs) parmi les 5
    chosen_servers_for_enc = [1, 2, 3]  # Par exemple

    # On lance le chiffrement
    encryption_result = client.initiate_encryption(messages, chosen_servers_for_enc)
    print(">>> Chiffrement terminé. Résultat :")
    print("root =", encryption_result["root"])
    print("cipher_tree =", encryption_result["cipher_tree"])
    print("servers_used =", encryption_result["servers_used"])
    print()

    # 5) (Optionnel) Déchiffrement avec potentiellement un autre sous-ensemble de serveurs
    chosen_servers_for_dec = [1, 3, 5]  # on peut en choisir 3, pas forcément les mêmes
    decrypted_messages = client.initiate_decryption(encryption_result, chosen_servers_for_dec)

    print(">>> Déchiffrement terminé. Messages en clair :")
    for idx, m in enumerate(decrypted_messages):
        # Certains indices peuvent être None si c'était du padding
        if m is not None:
            print(f"Message {idx}: {m.decode('utf-8')}")
        else:
            print(f"Message {idx}: [Padding / None]")

    # 6) Vérification simple
    #    On compare le message original (sans padding) avec le message déchiffré
    #    pour les indices qui ne sont pas None
    all_ok = True
    for orig, dec in zip(messages, decrypted_messages):
        if dec is None:
            continue
        if orig != dec:
            all_ok = False
            break

    if all_ok:
        print("\n>>> Vérification : Les messages déchiffrés correspondent aux originaux.")
    else:
        print("\n>>> Attention : Il y a un écart entre l'original et le déchiffré.")

if __name__ == "__main__":
    # Lancement du script
    sys.exit(main())
