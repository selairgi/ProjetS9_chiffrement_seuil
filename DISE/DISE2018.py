from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from functools import reduce
from os import urandom
import hmac
import hashlib
import random

##############################################################################################
########################  Fonctionnalitées actuelles du protocole  ###########################
##############################################################################################


# Dans DistEnc, l'une des parties, appelée le crypteur, qui détient un message, envoie un message de demande à t−1 autres parties du protocole.
# Les parties participantes utilisent leurs clés secrètes respectives pour calculer leurs réponses individuelles. À la
# fin du protocole, seul le chiffreur apprend un texte chiffré. De manière analogue, dans DistDec, l'une des parties
# (le déchiffreur) avec un texte chiffré effectue un processus similaire et apprend le message correspondant. Notez
# que nous ne supposons pas que la même partie joue le rôle de chiffreur et de déchiffreur. Notre propriété de
# cohérence exige que tout sous ensemble de t parties soit capable de chiffrer ou de déchiffrer

# => Sélectionne t parties au hasard parmi les n disponibles pour participer activement au chiffrement.
# => Une de ces parties actives est ensuite choisie au hasard pour être celle qui initie le chiffrement 
# => Création des clés avec l'algorithme AES de chaque partie (Advanced Encryption Standard) 
# => Pour chaque partie active, on génère une valeur apparemment aléatoire à partir 
#    de la clé secrète et d'une entrée spécifique(message unique)
# => Toutes ces valeurs en sorties sont stockées puis combinées pour obtenir une clé finale
# => Chiffrement du message avec la clé finale.
# => Pour déchiffrer, on reproduit la clé finale en répétant les mêmes étapes. 
#    Ensuite, une fonction utilise cette clé finale pour déchiffrer le texte chiffré.

#  * Consistance : 
#    Pour assurer que la clé finale est bien consistante pour toutes les parties actives, 
#    le script répète la combinaison des PRF pour chaque partie.
#    Il compare la clé finale recalculée avec la clé finale originale, 
#    et vérifie qu’elles sont identiques. Si une inconsistance est détectée, une erreur est levée.

# 1. Attaque par falsification des sorties PRF :
#    Simule un scénario dans lequel une ou plusieurs parties actives envoient des valeurs PRF erronées 
#    (par exemple, des sorties aléatoires au lieu des résultats PRF calculés).
#    Vérifie si le protocole est capable de détecter l'incohérence dans la combinaison des PRF et 
#    d'échouer proprement, en empêchant la génération d'une clé finale valide.

# 2. Attaque par modification de la clé finale :
#    Introduis une altération dans le processus de combinaison des PRF. Par exemple, 
#    fais en sorte qu'une partie modifie la clé finale en ajoutant une valeur aléatoire 
#    après la combinaison.
#    Teste si le protocole est capable de détecter cette modification 
#    (en comparant la clé finale pour différentes parties) et de lever une alerte 
#    ou de rejeter l'opération.

# 3. Attaque par interception de la clé (Man-in-the-Middle) :
#    Simule une interception de la clé finale après sa génération,
#    en faisant en sorte qu’un attaquant capture la clé avant le chiffrement du message.
#    Tu pourrais tester cette attaque pour vérifier si des mesures de sécurité supplémentaires 
#    (comme des signatures ou des jetons d'authentification) seraient nécessaires 
#    pour rendre la clé inutilisable en cas d'interception.

# 4. Attaque de consensus malveillant (Byzantine Fault) :
#    Fais en sorte que plusieurs parties actives envoient des sorties PRF incorrectes ou agissent de manière incohérente.
#    Dans un contexte distribué, une telle simulation permettrait de tester la résilience du protocole DiSE face à un nombre défini de parties corrompues et de vérifier si le protocole parvient à générer une clé correcte malgré l’attaque.

# 5. Attaque de substitution de message :
#    Au lieu d’envoyer le message original pour le chiffrement, un attaquant pourrait tenter de substituer le message par un autre avant l’étape de chiffrement.
#    Cette simulation peut être utile pour tester si le protocole peut garantir que le message déchiffré correspond bien à celui initialement destiné à être chiffré.


# Exigences de sécurité :

# Confidentialité :
# La confidentialité assure que le contenu du message reste inaccessible aux parties 
# non autorisées, même en cas de compromission partielle.
# (page 18-19)
# Nous autorisons deux types de requêtes de chiffrement dans le jeu de confidentialité 
# des messages : 
#
# 1) l’adversaire peut initier une session de chiffrement pour obtenir 
# à la fois le texte chiffré final ainsi que les transcriptions des parties qu’il 
# corrompt. 
# 
# 2) il peut faire une requête de chiffrement indirecte où il invoque une partie honnête 
# pour initier une session de chiffrement en utilisant un message de son choix. 
# => Pour rendre la définition plus forte, nous fournissons le texte chiffré produit 
# par la partie honnête à l’adversaire. 
# L'adversaire peut faire une requête où une partie honnête initie le chiffrement 
# avec un texte chiffré choisit par l'adversaire.

# Exactitude :
# Le processus d'exactitude assure que la clé finale générée lors du chiffrement 
# est identique à celle obtenue lors du déchiffrement. Le message déchiffré 
# correspond bien au message initial.

# Authenticité :
# L'authenticité vise à garantir que chaque message chiffré provient bien 
# d'une source légitime et n'a pas été altéré.

# Intégrité des textes chiffrés :

# Résilience :
# La résilience est assurée par un modèle de corruption, 
# qui suppose que jusqu'à un certain seuil de parties malveillantes peut être 
# toléré sans compromettre la sécurité globale.


##############################################################################################


# Parameters
n = 50  # nombre de parties totales
t = 49  # nombre de parties actives

######################################################################################
########################  Distributed Pseudorandom Functions #########################
######################################################################################

# Fonction Setup
def setup(n):
    """Génère une clé pour chaque partie."""
    keys = {}
    for i in range(n):
        keys[f'party_{i}'] = urandom(32)  # Génère une clé AES de 256 bits (32 octets) pour chaque partie
    return keys

# Fonction Eval
def eval(key, input_data):
    """Évalue la PRF avec une clé donnée sur une entrée."""
    return hmac.new(key, input_data.encode(), hashlib.sha256).digest() #HMAC-SHA256 est une fonction pseudorandomisée 

# Fonction Combine
def combine(prf_outputs):
    """Combine plusieurs sorties de PRF pour obtenir la clé finale."""
    final_key = reduce(lambda x, y: bytes(a ^ b for a, b in zip(x, y)), prf_outputs)
    return final_key

######################################################################################
###########################  Fonctions DistEnc/DistDec ###############################
######################################################################################

def encrypt_message(key, message):
    iv = urandom(16)  # Génère un vecteur d'initialisation aléatoire
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ciphertext  # Renvoie le texte chiffré avec l'IV

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]  # Extraire l'IV
    ciphertext = ciphertext[16:]  # Le reste est le texte chiffré
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

######################################################################################
######################################################################################
######################################################################################

# Setup
keys = setup(n)

######################################################################################
###################################  Chiffrement  ####################################
######################################################################################

# Sélection des parties actives 
parties = random.sample(range(n), t)

# Choisir une partie aléatoire qui initie le chiffrement
EncParty = random.choice(parties)

print("Les indices des parties actives sont :", parties)
print("L'indice de la partie qui débute le chiffrement est :", EncParty)

# Évaluation de la PRF pour chaque partie active
input_data = "unique_message_identifier"
prf_outputs = [eval(keys[f'party_{party}'], input_data) for party in parties]

# Combiner les sorties PRF pour obtenir la clé finale
final_key = combine(prf_outputs)
print(f"Final combined key: {final_key.hex()}")

# Chiffre le message avec la clé finale
message = "Ceci est un message secret."
texte_chiffre = encrypt_message(final_key, message)

print(f"Texte chiffré: {texte_chiffre.hex()}")

######################################################################################
##################################  Déchiffrement  ###################################
######################################################################################

# Évaluer la PRF pour chaque partie active
prf_outputs = [eval(keys[f'party_{party}'], input_data) for party in parties]

# Combiner les sorties PRF pour obtenir la clé finale
final_key = combine(prf_outputs)

# Utiliser la clé finale pour déchiffrer le message
decrypted_message = decrypt_message(final_key, texte_chiffre)

print(f"Message déchiffré : {decrypted_message}")

######################################################################################
##################################  Consistence  #####################################
######################################################################################

for party in parties:
    # Cette partie récupère ses propres sorties PRF et celle des autres parties
    prf_outputs_check = [eval(keys[f'party_{p}'], input_data) for p in parties]
    final_key_check = combine(prf_outputs_check)
    
    assert final_key == final_key_check, f"Inconsistance pour la partie {party}"

print("Clé finale combinée est consistante pour toutes les parties.")

######################################################################################
################################# Message Privacy ####################################
######################################################################################

# Permettre à l'adversaire de demander le chiffrement par une partie honnête
def adversary_encryption_request(message, honest_party, parties, keys):
    """Permet à l'adversaire de demander un chiffrement d'un message par une partie honnête."""
    input_data = "unique_message_identifier"
    # Évaluer la PRF pour chaque partie active
    prf_outputs = [eval(keys[f'party_{party}'], input_data) for party in parties]
    # Combiner les sorties PRF pour obtenir la clé finale
    final_key = combine(prf_outputs)
    # Chiffre le message avec la clé finale
    ciphertext = encrypt_message(final_key, message)
    return ciphertext  # Retourne uniquement le texte chiffré à l'adversaire

# Permettre à l'adversaire de demander un déchiffrement par une partie honnête
def adversary_decryption_request(ciphertext, honest_party, parties, keys):
    """Permet à l'adversaire de demander un déchiffrement d'un texte chiffré par une partie honnête."""
    input_data = "unique_message_identifier"
    # Évaluer la PRF pour chaque partie active
    prf_outputs = [eval(keys[f'party_{party}'], input_data) for party in parties]
    # Combiner les sorties PRF pour obtenir la clé finale
    final_key = combine(prf_outputs)
    # Déchiffre le texte chiffré avec la clé finale sans révéler le message déchiffré à l'adversaire
    decrypted_message = decrypt_message(final_key, ciphertext)
    # Pour assurer la confidentialité, nous ne renvoyons pas le message déchiffré directement
    return "Déchiffrement réussi, contenu non révélé"

##############################################################################################
# Exécution des requêtes de chiffrement et déchiffrement par l'adversaire
##############################################################################################

# Setup
keys = setup(n)

# Sélection des parties actives
parties = random.sample(range(n), t)

# L'adversaire demande un chiffrement via une partie honnête
adversary_message = "Message confidentiel pour l'adversaire"
ciphertext = adversary_encryption_request(adversary_message, EncParty, parties, keys)
print("Texte chiffré pour l'adversaire:", ciphertext.hex())

# L'adversaire demande un déchiffrement sans révéler le message déchiffré
decryption_result = adversary_decryption_request(ciphertext, EncParty, parties, keys)
print("Résultat du déchiffrement demandé par l'adversaire:", decryption_result)