# generate_client_config.py

import argparse
import json
import os

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--t", type=int, required=True)
    parser.add_argument("--ip", type=str, default="127.0.0.1",
                        help="IP par défaut pour tous les serveurs")
    parser.add_argument("--base_port", type=int, default=5001,
                        help="Port de base (ex: 5001, 5002, etc.)")
    args = parser.parse_args()

    n, t = args.n, args.t
    client_data = {
        "n": n,
        "t": t,
        "proof_params": None,
        "servers": {}
    }

    for i in range(1, n+1):
        fname = f"server_{i}.json"
        if not os.path.isfile(fname):
            raise FileNotFoundError(f"{fname} non trouvé, génère d'abord server_i.json via generate_configs.py")

        with open(fname, "r") as f:
            srv_data = json.load(f)
        
        # On prend le proof_params de server_1 (les suivants sont identiques)
        if i == 1:
            client_data["proof_params"] = srv_data["proof_params"]

        # Récupérer com_alpha, com_beta
        com_alpha_b64 = srv_data["com"]["com_alpha_b64"]
        com_beta_b64  = srv_data["com"]["com_beta_b64"]

        # On suppose host= --ip, port= --base_port + i - 1
        # ou on pourrait lire un tableau de ports etc.
        host = args.ip
        port = args.base_port + (i - 1)

        client_data["servers"][str(i)] = {
            "host": host,
            "port": port,
            "com_alpha_b64": com_alpha_b64,
            "com_beta_b64":  com_beta_b64
        }
    
    # Ecrit client_config.json
    with open("client_config.json", "w") as f:
        json.dump(client_data, f, indent=2)
    print("[OK] client_config.json généré.")

if __name__ == "__main__":
    main()

