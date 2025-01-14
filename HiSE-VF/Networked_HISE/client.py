# client.py

import argparse
import json
import base64
import sys
import hashlib
import requests

from charm.toolbox.pairinggroup import pair


from merkle import MerkleTree
from hise_avec_threads import Hise
from polynomial import Polynomial
from nizk import (
    HiseEncNizkProof,
    HiseEncNizkStatement,
    HiseDecNizkProof,
    HiseDecNizkStatement,
    HiseNizkProofParams
)
from structures import Scalar
from scalar_types import group
from utils import hash_to_g1

# -----------------------------------------------------------
# 1) UTILS pour sérialisation base64 (G1, Scalar, proofs...)
# -----------------------------------------------------------
def scalar_to_b64(s: Scalar) -> str:
    raw = group.serialize(s.value)
    return base64.b64encode(raw).decode()

def scalar_from_b64(b64_str: str) -> Scalar:
    raw = base64.b64decode(b64_str)
    zr = group.deserialize(raw)
    return Scalar(zr)

def g1_to_b64(elem) -> str:
    raw = group.serialize(elem)
    return base64.b64encode(raw).decode()

def g1_from_b64(b64_str: str):
    raw = base64.b64decode(b64_str)
    return group.deserialize(raw)

def enc_proof_from_dict(d: dict) -> HiseEncNizkProof:
    """
    Recrée un HiseEncNizkProof depuis un dict:
      {
        "ut1_b64": "...",
        "ut2_b64": "...",
        "alpha_z1_b64": "...",
        "alpha_z2_b64": "..."
      }
    """
    ut1 = g1_from_b64(d["ut1_b64"])
    ut2 = g1_from_b64(d["ut2_b64"])
    alpha_z1 = scalar_from_b64(d["alpha_z1_b64"])
    alpha_z2 = scalar_from_b64(d["alpha_z2_b64"])
    return HiseEncNizkProof(ut1=ut1, ut2=ut2, alpha_z1=alpha_z1, alpha_z2=alpha_z2)

def dec_proof_from_dict(d: dict) -> HiseDecNizkProof:
    """
    Recrée un HiseDecNizkProof depuis un dict:
      {
        "ut1_b64": "...",
        "ut2_b64": "...",
        "ut3_b64": "...",
        "alpha_z1_b64": "...",
        ...
      }
    """
    ut1 = g1_from_b64(d["ut1_b64"])
    ut2 = g1_from_b64(d["ut2_b64"])
    ut3 = g1_from_b64(d["ut3_b64"])
    alpha_z1 = scalar_from_b64(d["alpha_z1_b64"])
    alpha_z2 = scalar_from_b64(d["alpha_z2_b64"])
    beta_z1  = scalar_from_b64(d["beta_z1_b64"])
    beta_z2  = scalar_from_b64(d["beta_z2_b64"])
    return HiseDecNizkProof(
        ut1=ut1, ut2=ut2, ut3=ut3,
        alpha_z1=alpha_z1, alpha_z2=alpha_z2,
        beta_z1=beta_z1,   beta_z2=beta_z2
    )

# -----------------------------------------------------------
# 2) Charger la config du client : proof_params, engagements, etc.
# -----------------------------------------------------------
def load_client_config(path: str):
    """
    Suppose un JSON, par ex:
    {
      "n": 5,
      "t": 3,
      "proof_params": {
         "g_b64": "...",
         "h_b64": "..."
      },
      "servers": {
        "1": {
          "host": "127.0.0.1",
          "port": 5001,
          "com_alpha_b64": "...",
          "com_beta_b64": "..."
        },
        "2": {
          "host": "127.0.0.1",
          "port": 5002,
          "com_alpha_b64": "...",
          "com_beta_b64": "..."
        },
        ...
      }
    }
    """
    with open(path, 'r') as f:
        data = json.load(f)

    n = data["n"]
    t = data["t"]

    pp_data = data["proof_params"]
    g_elem = group.deserialize(base64.b64decode(pp_data["g_b64"]))
    h_elem = group.deserialize(base64.b64decode(pp_data["h_b64"]))
    proof_params = HiseNizkProofParams(g=g_elem, h=h_elem)

    # servers_info => dict[str, dict]
    servers_info = data["servers"]
    # ex: servers_info["1"] = { "host":..., "port":..., "com_alpha_b64":..., "com_beta_b64":... }

    return n, t, proof_params, servers_info

# -----------------------------------------------------------
# 3) ENCRYPT: contact t serveurs, récupère shares + proof
# -----------------------------------------------------------
def do_encrypt(client_config: str, messages: list, chosen_servers: list):
    """
    1) Charge la config client (n, t, proof_params, engagements, etc.)
    2) Construit Merkle, pad messages...
    3) Calcule h_root, h_x_w
    4) Envoie /encrypt_request à t serveurs => récupère combined_share + proof
    5) Vérifie la proof => accumule shares => interpolation => g^k
    6) Chiffre localement => stocke en encryption_result.json
    """
    print("[INFO] Chargement config client.")
    n, t, proof_params, servers_info = load_client_config(client_config)

    # 1) On pad les messages
    N = 1 << (len(messages) - 1).bit_length()
    padded = Hise.pad_messages(messages)

    # 2) Génération batch_keys (rho_k, r_k, g2_r_k)
    batch_keys = Hise.generate_batch_keys(N)

    # 3) Construction feuilles Merkle
    leaves = []
    for i in range(N):
        leaf = Hise._compute_merkle_leaf(padded[i], batch_keys.rho_k[i], batch_keys.r_k[i])
        leaves.append(leaf)

    merkle_tree = MerkleTree(leaves)
    root = merkle_tree.get_root()
    merkle_paths = [merkle_tree.get_path(i) for i in range(len(messages))]

    # 4) Génération x_w, calcul h_root, h_x_w
    x_w = Hise.get_random_data_commitment()
    h_root = hash_to_g1(root)
    h_x_w  = hash_to_g1(x_w)

    print(f"[INFO] Merkle root = {root[:8]}... (len={len(root)})")
    print("[INFO] h_root, h_x_w calculés.")

    # 5) Contact t serveurs
    responses = []
    for sid in chosen_servers:
        sid_str = str(sid)
        if sid_str not in servers_info:
            raise ValueError(f"Server ID {sid} not found in client_config.")
        host = servers_info[sid_str]["host"]
        port = servers_info[sid_str]["port"]
        url = f"http://{host}:{port}/encrypt_request"

        # Préparation payload
        data = {
            "h_root_b64":  base64.b64encode(group.serialize(h_root)).decode(),
            "h_x_w_b64":   base64.b64encode(group.serialize(h_x_w)).decode()
        }

        print(f"[INFO] -> Contact serveur {sid} sur {url}")
        r = requests.post(url, json=data)
        if r.status_code != 200:
            raise RuntimeError(f"Serveur {sid} error: {r.status_code}, {r.text}")

        resp_json = r.json()
        responses.append(resp_json)

    # 6) Vérification des preuves
    verified_shares = []
    xs = []

    for resp in responses:
        sid = resp["server_id"]

        # 1) Récupération (désérialisation) alpha_share et combined_share
        alpha_share_b64 = resp["alpha_share_b64"]
        combined_share_b64 = resp["combined_share_b64"]
        alpha_share = g1_from_b64(alpha_share_b64)
        combined_share = g1_from_b64(combined_share_b64)

        # 2) Récupération et reconstruction de la proof
        proof_enc_dict = resp["proof_enc"]
        proof_enc = enc_proof_from_dict(proof_enc_dict)

        # 3) Récupération du commitment alpha du serveur
        s_info = servers_info[str(sid)]
        com_alpha_b64 = s_info["com_alpha_b64"]
        com_alpha = g1_from_b64(com_alpha_b64)

        # 4) Construction du statement (on place alpha_share)
        stmt = HiseEncNizkStatement(
            g=proof_params.g,
            h=proof_params.h,
            h_of_x_eps=h_root,
            h_of_x_eps_pow_a=alpha_share,  # correspond à h_root^(α_i)
            com=com_alpha
        )
        if not proof_enc.verify(stmt):
            raise ValueError(f"Invalid encryption proof from server {sid}")

        # 5) On utilise combined_share pour l’interpolation
        verified_shares.append(combined_share)
        xs.append(Scalar(sid))


    if len(verified_shares) < t:
        raise ValueError(f"Nombre insuffisant de parts pour chiffrer : {len(verified_shares)} sur {t} nécessaires.")


    # 7) Interpolation Lagrange => reconstitution g^k
    coeffs = Polynomial.lagrange_coefficients(xs)
    gk = verified_shares[0] ** coeffs[0].value
    for share, coeff in zip(verified_shares[1:], coeffs[1:]):
        gk *= share ** coeff.value

    # 8) Chiffrement local
    cipher_tree = []
    for i in range(N):
        if i < len(messages):
            mk = pair(batch_keys.g2_r_k[i], gk)
            mk_bytes = hashlib.sha256(str(mk).encode()).digest()
            cipher = bytes(a ^ b for a, b in zip(padded[i].ljust(32, b'\0'), mk_bytes))
        else:
            cipher = b'\0' * 32
        cipher_tree.append(cipher)

    # 9) Construire l'objet final et l'enregistrer
    result = {
        "N": N,
        "root_b64": base64.b64encode(root).decode(),
        "cipher_tree": [ base64.b64encode(c).decode() for c in cipher_tree ],
        "merkle_paths": [ [base64.b64encode(x).decode() for x in p] for p in merkle_paths ],
        "batch_keys": {
            "rho_k_b64": [ scalar_to_b64(rho) for rho in batch_keys.rho_k ],
            "r_k_b64":   [ scalar_to_b64(r) for r in batch_keys.r_k ],
            "g2_r_k_b64":[ base64.b64encode(group.serialize(x)).decode() for x in batch_keys.g2_r_k ]
        },
        "x_w_b64": base64.b64encode(x_w).decode(),
        "servers_used": chosen_servers
    }

    with open("encryption_result.json", "w") as f:
        json.dump(result, f, indent=2)
    print("[OK] encryption_result.json généré.")
    print("[INFO] Chiffrement terminé.")

# -----------------------------------------------------------
# 4) DECRYPT: charge encryption_result.json, contact t serveurs
# -----------------------------------------------------------
def do_decrypt(client_config: str, chosen_servers: list):
    """
    1) Charge la config client
    2) Lit encryption_result.json
    3) Contact t serveurs => /decrypt_request => récupère combined_share + proof_dec
    4) Vérifie la proof => interpolation => g^k
    5) Déchiffre localement => affiche ou stocke
    """
    print("[INFO] Chargement config client.")
    n, t, proof_params, servers_info = load_client_config(client_config)

    # 1) Charger encryption_result.json
    with open("encryption_result.json", "r") as f:
        enc_data = json.load(f)

    N = enc_data["N"]
    root_b64 = enc_data["root_b64"]
    root = base64.b64decode(root_b64)  # bytes
    cipher_tree_b64 = enc_data["cipher_tree"]
    cipher_tree = [ base64.b64decode(c) for c in cipher_tree_b64 ]

    batch_keys_data = enc_data["batch_keys"]
    rho_k = [ scalar_from_b64(x) for x in batch_keys_data["rho_k_b64"] ]
    r_k   = [ scalar_from_b64(x) for x in batch_keys_data["r_k_b64"] ]
    g2_r_k= [ group.deserialize(base64.b64decode(x)) for x in batch_keys_data["g2_r_k_b64"] ]

    x_w = base64.b64decode(enc_data["x_w_b64"])

    # 2) Recalcule h_root, h_x_w
    h_root = hash_to_g1(root)
    h_x_w  = hash_to_g1(x_w)

    # 3) Contact t serveurs pour la phase de decrypt
    responses = []
    for sid in chosen_servers:
        sid_str = str(sid)
        if sid_str not in servers_info:
            raise ValueError(f"Server ID {sid} not found in client_config.")
        host = servers_info[sid_str]["host"]
        port = servers_info[sid_str]["port"]
        url = f"http://{host}:{port}/decrypt_request"

        data = {
            "h_root_b64": base64.b64encode(group.serialize(h_root)).decode(),
            "h_x_w_b64":  base64.b64encode(group.serialize(h_x_w)).decode()
        }
        print(f"[INFO] -> Contact serveur {sid} sur {url}")
        r = requests.post(url, json=data)
        if r.status_code != 200:
            raise RuntimeError(f"Serveur {sid} error: {r.status_code}, {r.text}")

        resp_json = r.json()
        responses.append(resp_json)

    # 4) Vérification proofs
    verified_shares = []
    xs = []
    for resp in responses:
        sid = resp["server_id"]
        combined_share_b64 = resp["combined_share_b64"]
        proof_dec_dict = resp["proof_dec"]

        combined_share = g1_from_b64(combined_share_b64)
        proof_dec = dec_proof_from_dict(proof_dec_dict)

        # Reconstituer statement
        s_info = servers_info[str(sid)]
        com_alpha = g1_from_b64(s_info["com_alpha_b64"])
        com_beta  = g1_from_b64(s_info["com_beta_b64"])

        stmt = HiseDecNizkStatement(
            g=proof_params.g,
            h=proof_params.h,
            h_of_x_eps=h_root,
            h_of_x_w=h_x_w,
            h_of_x_eps_pow_a_h_of_x_w_pow_b=combined_share,
            com_a=com_alpha,
            com_b=com_beta
        )
        if not proof_dec.verify(stmt):
            raise ValueError(f"Invalid decryption proof from server {sid}")

        verified_shares.append(combined_share)
        xs.append(Scalar(sid))

    if len(verified_shares) < t:
        raise ValueError(f"Nombre insuffisant de parts pour déchiffrer : {len(verified_shares)} sur {t} nécessaires.")


    # 5) Interpolation => g^k
    coeffs = Polynomial.lagrange_coefficients(xs)
    gk = verified_shares[0] ** coeffs[0].value
    for share, coeff in zip(verified_shares[1:], coeffs[1:]):
        gk *= share ** coeff.value

    # 6) Déchiffrement local
    decrypted_list = []
    for i, ciph in enumerate(cipher_tree):
        if ciph == b'\0' * 32:
            decrypted_list.append(None)
            continue
        mk = pair(g2_r_k[i], gk)

        mk_bytes = hashlib.sha256(str(mk).encode()).digest()
        msg = bytes(a ^ b for a, b in zip(ciph, mk_bytes))
        msg = msg.rstrip(b'\0')
        decrypted_list.append(msg)


    # 7) Afficher le résultat
    print("[INFO] Messages déchiffrés :")
    for i, m in enumerate(decrypted_list):
        if m:  # Vérifie si le message n'est pas vide (exclut les paddings)
            try:
                txt = m.decode("utf-8")  # Décodage UTF-8 du message
                print(f" - {i+1}: {txt}")
            except UnicodeDecodeError:
                print(f" - {i+1}: {m}")  # Affichage brut en cas d'erreur de décodage

    
    return decrypted_list

# -----------------------------------------------------------
# 5) MAIN avec argparse
# -----------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client_config", type=str, required=True, 
                        help="Chemin vers le fichier JSON avec la config client (servers, proof_params, etc.).")
    subparsers = parser.add_subparsers(dest="command", help="Commande: encrypt ou decrypt")

    # Commande ENCRYPT
    enc_parser = subparsers.add_parser("encrypt", help="Chiffrer des messages")
    enc_parser.add_argument("--servers", type=str, nargs='+', required=True,
                           help="Liste d'IDs de serveurs à contacter (ex: 1 2 3)")
    enc_parser.add_argument("--messages", type=str, nargs='+', required=True,
                           help="Liste de messages à chiffrer (ex: 'Hello' 'World')")

    # Commande DECRYPT
    dec_parser = subparsers.add_parser("decrypt", help="Déchiffrer un lot")
    dec_parser.add_argument("--servers", type=str, nargs='+', required=True,
                           help="Liste d'IDs de serveurs à contacter (ex: 1 2 3)")

    args = parser.parse_args()

    if args.command == "encrypt":
        chosen = [int(s) for s in args.servers]
        msgs = [m.encode('utf-8') for m in args.messages]
        do_encrypt(args.client_config, msgs, chosen)
    elif args.command == "decrypt":
        chosen = [int(s) for s in args.servers]
        do_decrypt(args.client_config, chosen)
    else:
        parser.print_help()

if __name__ == "__main__":
    sys.exit(main())
