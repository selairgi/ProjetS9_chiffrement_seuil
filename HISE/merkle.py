from hashlib import sha256
import networkx as nx
import matplotlib.pyplot as plt

def hash_data(data):
    """
    Hache une donnée avec SHA-256.
    
    Arguments :
    - data : La donnée à hacher (str).
    
    Retourne :
    - Le hash de la donnée (hex).
    """
    return sha256(data.encode()).hexdigest()

def build_merkle_tree(data):
    """
    Construit un arbre de Merkle et retourne ses niveaux.
    
    Arguments :
    - data : Liste des données (feuilles).
    
    Retourne :
    - Liste des niveaux de l'arbre (chaque niveau est une liste de hash).
    """
    levels = [list(map(hash_data, data))]  # Premier niveau : feuilles hachées

    while len(levels[-1]) > 1:
        current_level = levels[-1]
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            next_level.append(hash_data(left + right))
        levels.append(next_level)

    return levels


def get_merkle_path(data, index):
    """
    Génère le chemin Merkle pour une feuille spécifique.
    
    Arguments :
    - data : Liste des données initiales (feuilles).
    - index : Index de la feuille pour laquelle générer le chemin.
    
    Retourne :
    - Liste des paires (sibling_hash, is_left).
    """
    levels = build_merkle_tree(data)
    path = []

    for level in levels[:-1]:  # Pas besoin de la racine
        sibling_index = index + 1 if index % 2 == 0 else index - 1
        is_left = index % 2 == 0
        
        # Si le frère existe, ajoute au chemin
        if sibling_index < len(level):
            sibling_hash = level[sibling_index]
        else:
            sibling_hash = level[index]  # Pas de frère, utilise le même nœud

        path.append((sibling_hash, is_left))
        index //= 2

    return path


def validate_merkle_path(leaf, path, root):
    """
    Valide un chemin Merkle pour une feuille donnée.
    
    Arguments :
    - leaf : La feuille (donnée originale).
    - path : Chemin Merkle (liste des paires (sibling_hash, is_left)).
    - root : Racine attendue de l'arbre.
    
    Retourne :
    - True si le chemin est valide, False sinon.
    """
    current_hash = hash_data(leaf)
    
    for sibling_hash, is_left in path:
        if is_left:
            current_hash = hash_data(current_hash + sibling_hash)
        else:
            current_hash = hash_data(sibling_hash + current_hash)
    
    return current_hash == root

def visualize_merkle_tree(levels):
    """
    Visualise un arbre de Merkle avec NetworkX.
    
    Arguments :
    - levels : Liste des niveaux de l'arbre Merkle.
    """
    G = nx.DiGraph()
    pos = {}
    node_id = 0

    for i, level in enumerate(levels):
        for j, node in enumerate(level):
            G.add_node(node_id, label=node[:8])
            pos[node_id] = (j * 2 ** (len(levels) - i), -i)
            node_id += 1

    node_id = 0
    for i in range(len(levels) - 1):
        level_size = len(levels[i])
        next_level_size = len(levels[i + 1])
        for j in range(next_level_size):
            G.add_edge(node_id + j * 2, node_id + level_size + j)
            if j * 2 + 1 < level_size:
                G.add_edge(node_id + j * 2 + 1, node_id + level_size + j)
        node_id += level_size

    labels = nx.get_node_attributes(G, 'label')
    nx.draw(G, pos, with_labels=True, labels=labels, node_size=3000, node_color="lightblue", font_size=8, font_color="black")
    plt.title("Arbre de Merkle")
    plt.show()


# project/
# ├── merkle.py          # Gestion de l'arbre de Merkle
# ├── dprf.py            # Gestion des fonctions pseudorandomisées distribuées (DPRF)
# ├── encryption.py      # Chiffrement et déchiffrement des fragments
# ├── main.py            # Script principal pour exécuter le protocole HiSE
# └── utils/             # Dossier pour des utilitaires (par exemple : hashing, tests)
