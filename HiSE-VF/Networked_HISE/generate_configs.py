# generate_configs.py

import json
import base64
import argparse
from hise_avec_threads import Hise
from structures import Scalar
from scalar_types import group
from nizk import HiseNizkProofParams, HiseNizkWitness

def serialize_g1(elem):
    """Serialize a G1 element to base64."""
    raw = group.serialize(elem)
    return base64.b64encode(raw).decode()

def serialize_scalar(s: Scalar):
    """Serialize a Scalar (in ZR) to base64."""
    raw = group.serialize(s.value)
    return base64.b64encode(raw).decode()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, required=True, help="Nombre total de nœuds (n).")
    parser.add_argument("--t", type=int, required=True, help="Seuil (t).")
    args = parser.parse_args()

    n, t = args.n, args.t
    print(f"[INFO] Génération de la config pour n={n}, t={t}")

    # 1) On exécute Hise.setup(n, t)
    proof_params, private_keys, commitments = Hise.setup(n, t)
    # - proof_params : HiseNizkProofParams(g, h)
    # - private_keys[i] : HiseNizkWitness(α1, α2, β1, β2)
    # - commitments[i] : (com_alpha, com_beta)

    # Sérialisation de g, h
    g_b64 = serialize_g1(proof_params.g)
    h_b64 = serialize_g1(proof_params.h)

    # 2) Pour chaque i, on crée un JSON
    for i in range(n):
        server_id = i + 1

        # Récupération witness
        witness = private_keys[i]
        alpha1_b64 = serialize_scalar(witness.α1)
        alpha2_b64 = serialize_scalar(witness.α2)
        beta1_b64  = serialize_scalar(witness.β1)
        beta2_b64  = serialize_scalar(witness.β2)

        # Engagements
        com_alpha, com_beta = commitments[i]
        com_alpha_b64 = serialize_g1(com_alpha)
        com_beta_b64  = serialize_g1(com_beta)

        config_data = {
            "server_id": server_id,
            "proof_params": {
                "g_b64": g_b64,
                "h_b64": h_b64
            },
            "witness": {
                "alpha1_b64": alpha1_b64,
                "alpha2_b64": alpha2_b64,
                "beta1_b64":  beta1_b64,
                "beta2_b64":  beta2_b64
            },
            "com": {
                "com_alpha_b64": com_alpha_b64,
                "com_beta_b64":  com_beta_b64
            }
        }

        filename = f"server_{server_id}.json"
        with open(filename, "w") as f:
            json.dump(config_data, f, indent=2)
        print(f"[OK] Fichier {filename} généré.")

if __name__ == "__main__":
    main()
