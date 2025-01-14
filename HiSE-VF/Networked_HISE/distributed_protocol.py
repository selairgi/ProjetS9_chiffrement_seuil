# distributed_protocol.py

"""
Ce module définit les classes et fonctions de haut niveau pour gérer
le chiffrement distribué par seuil (Client/Serveur) selon le schéma HiSE.
Il repose sur les modules existants :
  - hise_avec_threads.py
  - merkle.py
  - polynomial.py
  - nizk.py
  - scalar_types.py
  - structures.py
  - utils.py
"""

from typing import Any, Dict, List, Tuple

# Import spécifique pour le pairing (utilisé dans Hise pour le calcul de pair())
from charm.toolbox.pairinggroup import pair

# Import du code existant HiSE
from hise_avec_threads import Hise
from merkle import MerkleTree, is_power_of_two
from polynomial import Polynomial
from nizk import (
    HiseEncNizkProof,
    HiseEncNizkStatement,
    HiseDecNizkProof,
    HiseDecNizkStatement,
    HiseNizkWitness,
    HiseNizkProofParams
)
from structures import (
    Scalar,
    HISEBatchWithProofs
)
from scalar_types import group
from utils import (
    hash_to_g1,
    hash_to_g2,
    hash_to_scalar,
    pedersen_commit
)

# Pour le parallélisme si nécessaire dans le protocole
from concurrent.futures import ThreadPoolExecutor

# Pour le hachage (XOR, dérivation, etc.)
import hashlib




class DistEncryptionServer:
    """
    Représente un nœud (serveur) dans le schéma de chiffrement distribué.
    Chaque serveur détient :
      - une part de la clé (witness: α_i, β_i, etc.),
      - les engagements (Pedersen) associés,
      - les paramètres publics nécessaires aux preuves NIZK.

    Le serveur est capable de:
      - Calculer (localement) sa contribution à la fonction pseudo-aléatoire
        distribuée (DPRF) pour le chiffrement.
      - Générer une preuve NIZK prouvant qu'il a bien utilisé sa part,
        sans révéler le secret.
      - Faire de même pour la phase de déchiffrement (optionnel).
    """

    def __init__(
        self,
        server_id: int,
        witness: HiseNizkWitness,
        proof_params: HiseNizkProofParams,
        com: Tuple[Any, Any]
    ):
        """
        Initialise le serveur.

        :param server_id: Identifiant unique du serveur (ex: 1, 2, 3, etc.).
        :param witness: HiseNizkWitness (objets contenant α1, α2, β1, β2).
        :param proof_params: HiseNizkProofParams (g, h) pour les preuves NIZK.
        :param com: Tuple (com_alpha, com_beta), engagement Pedersen
                    pour la part du serveur.
        """
        self.server_id = server_id
        self.witness = witness
        self.proof_params = proof_params
        self.com = com  # (commitment_alpha, commitment_beta)

    def process_encryption_request(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Traite une requête de chiffrement (ou DPRF) venant du client.

        data attend généralement:
          {
            "h_root": G1,  # H(racine de Merkle) ou autre param pour le calcul
            "h_x_w": G1,   # H(x_w), donnée aléatoire pour ce batch
            ...
          }

        Étapes principales:
          1. Extrait h_root et h_x_w du dictionnaire data.
          2. Calcule alpha_share = h_root^(α_i),
             beta_share  = h_x_w^(β_i).
          3. Combine ces deux partages: combined_share = alpha_share * beta_share.
          4. Génère une preuve NIZK (phase 'enc') prouvant l’utilisation de α_i
             (et éventuellement β_i) sans révéler la valeur.
          5. Retourne un dictionnaire contenant :
             - "server_id"        : l'ID de ce serveur
             - "combined_share"   : la contribution partielle (dans G1)
             - "proof"            : preuve NIZK d'enc
        """
        # 1) Lecture des données du client
        h_root = data["h_root"]  # G1
        h_x_w = data["h_x_w"]    # G1

        # 2) Calcul des parts pour la phase de chiffrement
        alpha_share = h_root ** self.witness.α1.value
        beta_share = h_x_w ** self.witness.β1.value
        combined_share = alpha_share * beta_share

        # 3) Construction du statement pour la preuve d'encryption
        #    On prouve que: h_root^(α_i) est bien cohérent avec l'engagement com_alpha
        #    (et potentiellement la même logique pour β_i).
        stmt = HiseEncNizkStatement(
            g=self.proof_params.g,
            h=self.proof_params.h,
            h_of_x_eps=h_root,
            h_of_x_eps_pow_a=alpha_share,  # partie h_root^α_i
            com=self.com[0]               # engagement Pedersen pour alpha
        )


        # 4) Génération de la preuve de chiffrement
        proof_enc = HiseEncNizkProof.prove(self.witness, stmt)


        # 5) Construction de la réponse vers le client
        response = {
            "server_id": self.server_id,
            "alpha_share": alpha_share, 
            "combined_share": combined_share,
            "proof": proof_enc
        }
        return response

    def process_decryption_request(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Traite une requête de déchiffrement (DPRF) venant du client.

        data attend généralement:
          {
            "h_root": G1,
            "h_x_w":  G1,
            ...
          }

        Étapes principales:
          1. Extrait h_root et h_x_w du dictionnaire data.
          2. Calcule alpha_share = h_root^(α_i),
             beta_share  = h_x_w^(β_i).
          3. Combine ces deux partages: combined_share = alpha_share * beta_share.
          4. Génère la preuve NIZK (phase 'dec') prouvant l’utilisation de α_i et β_i
             sans révéler les secrets.
          5. Retourne un dictionnaire contenant :
             - "server_id"        : l'ID de ce serveur
             - "combined_share"   : la contribution partielle (dans G1)
             - "proof"            : preuve NIZK de déchiffrement
        """
        # 1) Lecture des données du client
        h_root = data["h_root"]  # G1
        h_x_w = data["h_x_w"]    # G1

        # 2) Calcul des parts pour la phase de déchiffrement
        alpha_share = h_root ** self.witness.α1.value
        beta_share = h_x_w ** self.witness.β1.value
        combined_share = alpha_share * beta_share

        # 3) Construction du statement pour la preuve de déchiffrement
        #    On prouve que: h_root^(α_i) * h_x_w^(β_i) est cohérent avec
        #    (com_alpha, com_beta) = (self.com[0], self.com[1]).
        stmt = HiseDecNizkStatement(
            g=self.proof_params.g,
            h=self.proof_params.h,
            h_of_x_eps=h_root,
            h_of_x_w=h_x_w,
            h_of_x_eps_pow_a_h_of_x_w_pow_b=combined_share,
            com_a=self.com[0],
            com_b=self.com[1]
        )

        # 4) Génération de la preuve de déchiffrement
        proof_dec = HiseDecNizkProof.prove(self.witness, stmt)

        # 5) Construction de la réponse vers le client
        response = {
            "server_id": self.server_id,
            "combined_share": combined_share,
            "proof": proof_dec
        }
        return response





class DistEncryptionClient:
    """
    Le 'client' ou l'application qui souhaite chiffrer (et éventuellement déchiffrer)
    un lot de messages en utilisant un protocole distribué par seuil.

    Il possède:
    - Les paramètres publics (proof_params),
    - Une liste (ou dict) de serveurs (DistEncryptionServer),
    - Des méthodes pour:
        1. initier le chiffrement,
        2. contacter t serveurs (sur n),
        3. vérifier leurs réponses (preuves NIZK),
        4. combiner les shares pour former la clé éphémère,
        5. chiffrer ou déchiffrer localement.
    """

    def __init__(self, proof_params: HiseNizkProofParams, servers: List[Any]):
        """
        Initialise le client.

        :param proof_params: Les paramètres publics NIZK (g, h) pour le schéma HiSE.
        :param servers: Liste (ou dict) d'instances DistEncryptionServer.
                        On peut en faire un dict {server_id: server} si besoin.
        """
        self.proof_params = proof_params

        # On préfère un dict { server_id: DistEncryptionServer } pour y accéder facilement.
        # S'il s'agit déjà d'un dict, on peut juste stocker self.servers = servers
        # Sinon on le convertit.
        self.servers = {}
        for srv in servers:
            self.servers[srv.server_id] = srv

    def initiate_encryption(self, messages: List[bytes], server_ids: List[int]) -> Dict[str, Any]:
        """
        Lance la procédure de chiffrement distribué d'un lot de messages,
        en contactant un sous-ensemble 'server_ids' (t serveurs parmi n).

        Étapes principales:
          1) Prépare la structure Merkle (ou d'autres métadonnées) si nécessaire.
          2) Calcule h_root et h_x_w.
          3) Envoie une requête de chiffrement (DPRF) à chaque serveur sélectionné.
          4) Vérifie les preuves renvoyées par chacun.
          5) Combine les 'combined_share' pour reconstruire g^k.
          6) Chiffre localement les messages en utilisant la clé éphémère.

        :param messages: Liste de messages (bytes) à chiffrer.
        :param server_ids: Liste des identifiants de serveurs à contacter (taille >= t).
        :return: Un dictionnaire contenant:
                  - 'root' : la racine Merkle (bytes)
                  - 'cipher_tree' : liste de messages chiffrés (bytes)
                  - 'merkle_paths' : chemins Merkle pour vérification future
                  - 'batch_keys' : struct (rho_k, r_k, etc.)
                  - 'x_w' : l'élément aléatoire (bytes) pour ce batch
                  - 'servers_used' : la liste des serveurs contactés
                  - 'responses' : les réponses (combined_share, proof) de chaque serveur
                  - ... etc.
        """

        # 1) Construction du Merkle Tree (si besoin) via la logique HiSE
        #    On peut réutiliser Hise.pad_messages(...) pour s'assurer que
        #    le nombre de messages est une puissance de 2, etc.
        N = 1 << (len(messages) - 1).bit_length()
        padded_messages = Hise.pad_messages(messages)

        # Génération des batch_keys (rho_k, r_k, g2_r_k, ...)
        batch_keys = Hise.generate_batch_keys(N)

        # Calcul des feuilles (en local) pour construire la racine Merkle
        leaves = []
        for i in range(N):
            leaf = Hise._compute_merkle_leaf(
                padded_messages[i], batch_keys.rho_k[i], batch_keys.r_k[i]
            )
            leaves.append(leaf)

        merkle_tree = MerkleTree(leaves)
        root = merkle_tree.get_root()
        merkle_paths = [merkle_tree.get_path(i) for i in range(len(messages))]

        # 2) On génère x_w, puis on calcule h_root et h_x_w
        x_w = Hise.get_random_data_commitment()  # 32-byte random data
        h_root = hash_to_g1(root)
        h_x_w = hash_to_g1(x_w)

        # 3) Préparation de la requête à envoyer aux serveurs
        request_data = {
            "h_root": h_root,
            "h_x_w": h_x_w
        }

        # Envoi de la requête à chaque serveur dans server_ids
        responses = []
        for sid in server_ids:
            server = self.servers[sid]
            # Le serveur calcule sa part (combined_share) et renvoie une preuve
            response = server.process_encryption_request(request_data)
            responses.append(response)

        # 4) Vérification des preuves pour chaque réponse
        verified_shares = []
        xs = []
        for idx, resp in enumerate(responses):
            # On récupère le combined_share et la proof
            # combined_share = resp["combined_share"]
            # proof_enc = resp["proof"]

            alpha_share = resp["alpha_share"]        # Récupéré du serveur
            combined_share = resp["combined_share"]
            proof_enc = resp["proof"]
            
            """
            # Construction d'un 'statement' minimal pour la vérification
            # On sait que:
            #   statement.h_of_x_eps_pow_a = h_root^(α_i)
            #   or on peut le déduire de combined_share si on veut
            #   => il faut être cohérent avec la structure du code server
            #   => Dans process_encryption_request, la proof enc vise alpha_share= h_root^α_i
            #      Donc on doit repasser alpha_share au moment de la vérification
            #      ou re-construire un statement identique.
            # Pour faire simple, on suppose qu'on sait "alpha_share = combined_share / (h_x_w^β_i)",
            # mais on ne connaît pas β_i. Donc, pour la démo, on reconstruit le statement
            # comme le serveur l'a fait (voir server.process_encryption_request).
            # Ici, on ne peut pas deviner alpha_share seul, mais on peut valider
            # que la proof enc est cohérente avec le commitment com_alpha.
            # On va donc accéder directement (client-side) au DistEncryptionServer.com[0]
            # ou bien le serveur nous l'envoie, c'est selon le protocole.
            # EXEMPLE (simplifié) : 
            """

            # Récupérer le com_alpha pour le serveur concerné
            com_alpha = self.servers[resp["server_id"]].com[0]

            stmt = HiseEncNizkStatement(
                g=self.proof_params.g,
                h=self.proof_params.h,
                h_of_x_eps=h_root,
                h_of_x_eps_pow_a=alpha_share,     # = h_root^(α_i), comme côté serveur
                com=com_alpha
            )



            # Appel de la vérification
            if not proof_enc.verify(stmt):
                raise ValueError(f"Invalid encryption proof from server {resp['server_id']}")

            # Si c'est OK, on enregistre ce combined_share
            verified_shares.append(combined_share)

            # On choisit un x_i pour l'interpolation
            # => souvent c'est x_i = server_id (par ex. 1,2,3,...) pour la Lagrange
            #   tant que c'est cohérent avec la phase setup.
            x_i = Scalar(resp["server_id"])
            xs.append(x_i)

        # 5) Interpolation (Lagrange) pour reconstituer g^k
        # => on fait l'exponentiation cumulée gk = Π (share_i^(λ_i))
        #    où λ_i sont les coefficients de Lagrange calculés sur x_1...x_t
        if len(verified_shares) == 0:
            raise ValueError("No valid shares found.")

        coeffs = Polynomial.lagrange_coefficients(xs)  # calcule λ_i
        gk = verified_shares[0] ** coeffs[0].value
        for share, coeff in zip(verified_shares[1:], coeffs[1:]):
            gk *= (share ** coeff.value)

        # 6) Chiffrement final local
        cipher_tree = []
        for i in range(N):
            if i < len(messages):
                # e(g2^(r_i), g^k) => mk, puis on XOR
                mk = pair(batch_keys.g2_r_k[i], gk)
                mk_bytes = hashlib.sha256(str(mk).encode()).digest()
                # On pad le message sur 32 octets (ou plus) avant le XOR
                cipher = bytes(a ^ b for a, b in zip(padded_messages[i].ljust(32, b'\0'), mk_bytes))
            else:
                cipher = b'\0' * 32  # padding
            cipher_tree.append(cipher)

        # Construction du résultat (à stocker ou renvoyer)
        result = {
            "N": N,
            "root": root,
            "cipher_tree": cipher_tree,
            "merkle_paths": merkle_paths,
            "batch_keys": batch_keys,
            "x_w": x_w,
            "servers_used": server_ids,
            "responses": responses
        }
        return result

    # =========================================================================
    # Optionnel: Méthodes pour initier le déchiffrement, vérifier les parts, etc.
    # =========================================================================

    def initiate_decryption(self, batch_info: Dict[str, Any], server_ids: List[int]) -> List[bytes]:
        """
        Exécute un déchiffrement distribué, en contactant t serveurs pour obtenir
        leurs parts. Reconstruit ensuite la clé et déchiffre.

        :param batch_info: Dictionnaire retourné précédemment par 'initiate_encryption'
                           ou structure équivalente (qui contient 'root', 'cipher_tree',
                           'batch_keys', 'x_w', etc.).
        :param server_ids: Identifiants des serveurs qui participeront au déchiffrement.
        :return: Liste de messages (en clair).
        """

        # 1) Extraire les infos essentielles du batch
        N = batch_info["N"]
        root = batch_info["root"]
        cipher_tree = batch_info["cipher_tree"]
        batch_keys = batch_info["batch_keys"]
        x_w = batch_info["x_w"]

        # On recalcule h_root et h_x_w
        h_root = hash_to_g1(root)
        h_x_w = hash_to_g1(x_w)

        # 2) Contacter les serveurs pour la phase de déchiffrement
        request_data = {
            "h_root": h_root,
            "h_x_w": h_x_w
        }
        responses = []
        for sid in server_ids:
            server = self.servers[sid]
            resp = server.process_decryption_request(request_data)
            responses.append(resp)

        # 3) Vérification des preuves (similar to encryption)
        verified_shares = []
        xs = []
        for resp in responses:
            combined_share = resp["combined_share"]
            proof_dec = resp["proof"]
            com_a = self.servers[resp["server_id"]].com[0]
            com_b = self.servers[resp["server_id"]].com[1]

            stmt = HiseDecNizkStatement(
                g=self.proof_params.g,
                h=self.proof_params.h,
                h_of_x_eps=h_root,
                h_of_x_w=h_x_w,
                h_of_x_eps_pow_a_h_of_x_w_pow_b=combined_share,
                com_a=com_a,
                com_b=com_b
            )
            if not proof_dec.verify(stmt):
                raise ValueError(f"Invalid decryption proof from server {resp['server_id']}")

            verified_shares.append(combined_share)
            xs.append(Scalar(resp["server_id"]))

        # 4) Interpolation (Lagrange)
        coeffs = Polynomial.lagrange_coefficients(xs)
        gk = verified_shares[0] ** coeffs[0].value
        for share, coeff in zip(verified_shares[1:], coeffs[1:]):
            gk *= (share ** coeff.value)

        # 5) Déchiffrement local
        decrypted_list = []
        for i, cipher in enumerate(cipher_tree):
            if cipher == b'\0' * 32:
                # padding
                decrypted_list.append(None)
                continue

            mk = pair(batch_keys.g2_r_k[i], gk)
            mk_bytes = hashlib.sha256(str(mk).encode()).digest()
            msg = bytes(a ^ b for a, b in zip(cipher, mk_bytes))
            msg = msg.rstrip(b'\0')  # retirer le padding
            decrypted_list.append(msg)

        # Filtrer ou retourner la liste complète
        return decrypted_list
