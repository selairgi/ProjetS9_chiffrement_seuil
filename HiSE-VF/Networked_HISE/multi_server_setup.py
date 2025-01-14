# multi_server_setup.py

import argparse
import subprocess
import os
import signal
import sys

def main():
    """
    Script pour lancer plusieurs serveurs HiSE (server.py) en parallèle,
    chacun avec un fichier config distinct (server_i.json) et un port différent.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, required=True,
                        help="Nombre total de serveurs à lancer.")
    parser.add_argument("--base_port", type=int, default=5001,
                        help="Port de base. Le ième serveur écoutera sur base_port + i - 1.")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="Adresse d'écoute (0.0.0.0 pour écouter sur toutes les interfaces).")
    args = parser.parse_args()

    n = args.n
    base_port = args.base_port
    host = args.host

    print(f"[INFO] Lancement de {n} serveurs, host={host}, base_port={base_port}...")

    processes = []
    for i in range(1, n + 1):
        # Fichier de config server_i.json (ex: server_1.json, server_2.json, etc.)
        config_file = f"server_{i}.json"
        if not os.path.exists(config_file):
            print(f"[WARNING] Fichier {config_file} introuvable. "
                  f"Assure-toi d'avoir généré server_{i}.json.")
            continue

        port = base_port + (i - 1)
        cmd = [
            "python", "server.py",
            "--config", config_file,
            "--port", str(port),
            "--host", host
        ]
        print(f"[INFO] Lancement du serveur {i} avec la commande: {' '.join(cmd)}")

        # Lance le serveur en sous-processus
        p = subprocess.Popen(cmd)
        processes.append((i, p))

    # On attend que tous les serveurs tournent jusqu'à l'interruption Ctrl-C
    print("[INFO] Appuyez sur Ctrl-C pour arrêter tous les serveurs.")
    try:
        for (server_id, proc) in processes:
            # .wait() bloque jusqu'à la fin du process
            exit_code = proc.wait()
            print(f"[INFO] Serveur {server_id} terminé avec code de sortie = {exit_code}")
    except KeyboardInterrupt:
        print("\n[INFO] Interruption détectée (Ctrl-C). On arrête tous les serveurs...")
        for (server_id, proc) in processes:
            proc.terminate()
        print("[INFO] Fin de multi_server_setup.py.")
        sys.exit(0)

if __name__ == "__main__":
    main()
