import hmac
import hashlib
from functools import reduce
from os import urandom

# ==========================================
# 1. Génération des Engagements Cryptographiques (Commitments)
# ==========================================

def generate_commitment(fragment, randomness):
    """
    Génère un engagement cryptographique pour un fragment donné.

    Arguments :
    - fragment : Fragment de données (string).
    - randomness : Valeur aléatoire pour rendre chaque engagement unique (string).

    Retour :
    - Engagement cryptographique sous forme de string (hexadecimal).
    """
    return hashlib.sha256((fragment + randomness).encode()).hexdigest()

# ==========================================
# 2. Génération des Clés Locales
# ==========================================

def generate_keys(num_keys, key_size=32):
    """
    Génère un ensemble de clés aléatoires pour les participants.

    Arguments :
    - num_keys : Nombre de clés à générer.
    - key_size : Taille des clés en octets (par défaut 32 octets pour AES-256).

    Retour :
    - Liste des clés générées sous forme de bytes.
    """
    return [urandom(key_size) for _ in range(num_keys)]

# ==========================================
# 3. Évaluation de la DPRF
# ==========================================

def eval_dprf(key, input_data):
    """
    Évalue une fonction pseudorandomisée distribuée (DPRF) pour un participant donné.
    Utilise HMAC avec SHA-256 pour produire une sortie pseudorandomisée basée sur
    une clé locale et un engagement (input_data).

    Arguments :
    - key : Clé locale d'un participant (bytes).
    - input_data : Engagement ou identifiant unique (string).

    Retour :
    - Sortie pseudorandomisée sous forme de bytes.
    """
    return hmac.new(key, input_data.encode(), hashlib.sha256).digest()

# ==========================================
# 4. Combinaison des sorties PRF
# ==========================================

def combine_prf_outputs(outputs):
    """
    Combine les sorties PRF des participants pour produire une clé effective.

    Applique un XOR sur chaque octet des sorties PRF pour garantir que la clé
    effective dépend de toutes les contributions des participants.

    Arguments :
    - outputs : Liste des sorties PRF (bytes) des différents participants.

    Retour :
    - Clé effective combinée sous forme de bytes.
    """
    return reduce(lambda x, y: bytes(a ^ b for a, b in zip(x, y)), outputs)
