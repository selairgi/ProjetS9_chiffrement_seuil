# server.py

import argparse
import json
import base64
import sys

from flask import Flask, request, jsonify

# =======================
# Imports du code HiSE
# =======================
from hise_avec_threads import Hise
from nizk import (
    HiseNizkProofParams,
    HiseNizkWitness,
    HiseEncNizkProof,
    HiseDecNizkProof
)
from distributed_protocol import DistEncryptionServer
from structures import Scalar
from scalar_types import group

app = Flask(__name__)

# ------------------------------------------------------------------
# 1) GLOBALE : on stocke l'instance DistEncryptionServer dans dist_server
# ------------------------------------------------------------------
dist_server = None


# ------------------------------------------------------------------
# 2) UTILITAIRES pour (dé)sérialiser en base64
# ------------------------------------------------------------------

def scalar_from_b64(b64_str: str) -> Scalar:
    """Reconstruit un Scalar depuis une string base64 (ZR)"""
    raw = base64.b64decode(b64_str)
    zr_elem = group.deserialize(raw)
    return Scalar(zr_elem)

def scalar_to_b64(s: Scalar) -> str:
    """Sérialise un Scalar (ZR) en base64"""
    raw = group.serialize(s.value)
    return base64.b64encode(raw).decode()

def g1_from_b64(b64_str: str):
    """Reconstruit un élément G1 depuis base64"""
    raw = base64.b64decode(b64_str)
    return group.deserialize(raw)

def g1_to_b64(elem) -> str:
    """Sérialise un élément G1 en base64"""
    raw = group.serialize(elem)
    return base64.b64encode(raw).decode()

def g2_from_b64(b64_str: str):
    """Reconstruit un élément G2 depuis base64 (si besoin)"""
    raw = base64.b64decode(b64_str)
    return group.deserialize(raw)

def g2_to_b64(elem) -> str:
    """Sérialise un élément G2 en base64"""
    raw = group.serialize(elem)
    return base64.b64encode(raw).decode()


# ------------------------------------------------------------------
# 3) (Dé)sérialisation de la preuve "EncNizkProof" en JSON
# ------------------------------------------------------------------
def enc_proof_to_dict(proof: HiseEncNizkProof) -> dict:
    """
    HiseEncNizkProof contient : ut1, ut2 (de type G1), alpha_z1, alpha_z2 (de type Scalar)
    On renvoie un dict JSON-friendly avec tout en base64
    """
    return {
        "ut1_b64": g1_to_b64(proof.ut1),
        "ut2_b64": g1_to_b64(proof.ut2),
        "alpha_z1_b64": scalar_to_b64(proof.alpha_z1),
        "alpha_z2_b64": scalar_to_b64(proof.alpha_z2)
    }

def enc_proof_from_dict(d: dict) -> HiseEncNizkProof:
    """
    Recrée un HiseEncNizkProof depuis un dict (ex: reçu en JSON).
    """
    ut1 = g1_from_b64(d["ut1_b64"])
    ut2 = g1_from_b64(d["ut2_b64"])
    alpha_z1 = scalar_from_b64(d["alpha_z1_b64"])
    alpha_z2 = scalar_from_b64(d["alpha_z2_b64"])
    return HiseEncNizkProof(ut1=ut1, ut2=ut2, alpha_z1=alpha_z1, alpha_z2=alpha_z2)


# ------------------------------------------------------------------
# 4) (Dé)sérialisation de la preuve "DecNizkProof"
# ------------------------------------------------------------------
def dec_proof_to_dict(proof: HiseDecNizkProof) -> dict:
    """
    HiseDecNizkProof contient: ut1, ut2, ut3 (G1), alpha_z1, alpha_z2, beta_z1, beta_z2 (Scalars)
    """
    return {
        "ut1_b64": g1_to_b64(proof.ut1),
        "ut2_b64": g1_to_b64(proof.ut2),
        "ut3_b64": g1_to_b64(proof.ut3),
        "alpha_z1_b64": scalar_to_b64(proof.alpha_z1),
        "alpha_z2_b64": scalar_to_b64(proof.alpha_z2),
        "beta_z1_b64":  scalar_to_b64(proof.beta_z1),
        "beta_z2_b64":  scalar_to_b64(proof.beta_z2)
    }

def dec_proof_from_dict(d: dict) -> HiseDecNizkProof:
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


# ------------------------------------------------------------------
# 5) CHARGEMENT DE LA CONFIG SERVEUR
# ------------------------------------------------------------------
def load_server_config(config_path: str) -> DistEncryptionServer:
    """
    Charge le JSON qui contient:
      - server_id
      - proof_params (g_b64, h_b64)
      - witness (alpha1_b64, alpha2_b64, beta1_b64, beta2_b64)
      - com (com_alpha_b64, com_beta_b64)
    Reconstruit le DistEncryptionServer correspondant.
    """
    with open(config_path, 'r') as f:
        data = json.load(f)

    server_id = data["server_id"]

    # Reconstitution proof_params (g, h)
    pp_data = data["proof_params"]
    g_elem = group.deserialize(base64.b64decode(pp_data["g_b64"]))
    h_elem = group.deserialize(base64.b64decode(pp_data["h_b64"]))
    proof_params = HiseNizkProofParams(g=g_elem, h=h_elem)

    # Reconstitution witness
    w_data = data["witness"]
    alpha1 = scalar_from_b64(w_data["alpha1_b64"])
    alpha2 = scalar_from_b64(w_data["alpha2_b64"])
    beta1  = scalar_from_b64(w_data["beta1_b64"])
    beta2  = scalar_from_b64(w_data["beta2_b64"])

    witness = HiseNizkWitness(
        α1=alpha1, α2=alpha2,
        β1=beta1,   β2=beta2
    )

    # Commitments
    com_data = data["com"]
    com_alpha = group.deserialize(base64.b64decode(com_data["com_alpha_b64"]))
    com_beta  = group.deserialize(base64.b64decode(com_data["com_beta_b64"]))
    com_tuple = (com_alpha, com_beta)

    # Création
    dist_srv = DistEncryptionServer(
        server_id=server_id,
        witness=witness,
        proof_params=proof_params,
        com=com_tuple
    )
    return dist_srv

# ------------------------------------------------------------------
# 6) ROUTES FLASK
# ------------------------------------------------------------------

@app.route("/encrypt_request", methods=["POST"])
def encrypt_request():
    """
    Reçoit un JSON du client avec:
    {
      "h_root_b64": "...",
      "h_x_w_b64":  "..."
    }
    Retourne:
    {
      "server_id": <int>,
      "combined_share_b64": "...",
      "proof_enc": {
          "ut1_b64": "...",
          "ut2_b64": "...",
          "alpha_z1_b64": "...",
          "alpha_z2_b64": "..."
      }
    }
    """
    if dist_server is None:
        return jsonify({"error": "Server not initialized"}), 500

    req = request.json
    if not req:
        return jsonify({"error": "Invalid JSON"}), 400

    try:
        h_root = g1_from_b64(req["h_root_b64"])
        h_x_w  = g1_from_b64(req["h_x_w_b64"])
    except KeyError:
        return jsonify({"error": "Missing keys (h_root_b64, h_x_w_b64)"}), 400
    except Exception as e:
        return jsonify({"error": f"Deserialization failed: {str(e)}"}), 400

    data_local = {
        "h_root": h_root,
        "h_x_w":  h_x_w
    }
    resp = dist_server.process_encryption_request(data_local)

    combined_share_b64 = g1_to_b64(resp["combined_share"])
    proof_dict = enc_proof_to_dict(resp["proof"])   # on convertit la proof en dict base64

    alpha_share_b64 = g1_to_b64(resp["alpha_share"])   # <-- on ajoute ceci

    final_json = {
        "server_id": resp["server_id"],
        "alpha_share_b64": alpha_share_b64,            # <-- clé supplémentaire
        "combined_share_b64": combined_share_b64,
        "proof_enc": proof_dict
    }

    return jsonify(final_json), 200


@app.route("/decrypt_request", methods=["POST"])
def decrypt_request():
    """
    Reçoit un JSON:
    {
      "h_root_b64": "...",
      "h_x_w_b64":  "..."
    }
    Retourne:
    {
      "server_id": <int>,
      "combined_share_b64": "...",
      "proof_dec": { ... }
    }
    """
    if dist_server is None:
        return jsonify({"error": "Server not initialized"}), 500

    req = request.json
    if not req:
        return jsonify({"error": "Invalid JSON"}), 400

    try:
        h_root = g1_from_b64(req["h_root_b64"])
        h_x_w  = g1_from_b64(req["h_x_w_b64"])
    except KeyError:
        return jsonify({"error": "Missing keys (h_root_b64, h_x_w_b64)"}), 400
    except Exception as e:
        return jsonify({"error": f"Deserialization failed: {str(e)}"}), 400

    data_local = {
        "h_root": h_root,
        "h_x_w":  h_x_w
    }
    resp = dist_server.process_decryption_request(data_local)

    combined_share_b64 = g1_to_b64(resp["combined_share"])
    proof_dict = dec_proof_to_dict(resp["proof"])

    final_json = {
        "server_id": resp["server_id"],
        "combined_share_b64": combined_share_b64,
        "proof_dec": proof_dict
    }
    return jsonify(final_json), 200


# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, required=True,
                        help="Chemin vers le fichier JSON contenant la part du serveur (witness, proof_params, etc.).")
    parser.add_argument("--port", type=int, default=5000,
                        help="Port HTTP sur lequel écouter (défaut 5000).")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="Adresse d'écoute, défaut=0.0.0.0")
    args = parser.parse_args()

    global dist_server
    dist_server = load_server_config(args.config)
    print(f"[INFO] Serveur ID={dist_server.server_id} initialisé")
    print(f"[INFO] Lance Flask sur {args.host}:{args.port}")

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    sys.exit(main())
