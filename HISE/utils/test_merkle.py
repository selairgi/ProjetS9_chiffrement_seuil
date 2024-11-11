import sys
import os

# Ajoutez le répertoire parent au chemin pour accéder aux modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from merkle import build_merkle_tree, get_merkle_path, validate_merkle_path, visualize_merkle_tree

def test_merkle():
    data = ["D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9"]
    levels = build_merkle_tree(data)
    root = levels[-1][0]
    
    # Test pour un fragment spécifique
    index = 7  
    path = get_merkle_path(data, index)
    
    assert validate_merkle_path(data[index], path, root), f"Validation échouée pour {data[index]}"
    print(f"Validation réussie pour {data[index]}")
    
    # Visualisation
    visualize_merkle_tree(levels)

if __name__ == "__main__":
    test_merkle()
