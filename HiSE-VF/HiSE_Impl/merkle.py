from charm.toolbox.pairinggroup import PairingGroup
from typing import List, Tuple, Any, Dict
import hashlib
from structures import HISEBatchWithProofs
from scalar_types import Scalar

# Initialize the pairing group
group = PairingGroup('BN254')

###########################################################################################################
# MERKLE TREE IMPLEMENTATION
###########################################################################################################


class MerkleTree:
    """
    Merkle tree implementation for HISE.
    Handles tree construction, proof path generation,
    and verification.
    """
    def __init__(self, leaves: List[bytes]):
        self.leaves = leaves
        self.nodes = self._build_tree()

    def _build_tree(self) -> Dict[int, List[bytes]]:
        """
        Builds the Merkle tree level by level.
        
        Returns:
            Dict[int, List[bytes]]: Dictionary of tree levels
        """
        nodes = {0: self.leaves}
        current_level = self.leaves
        level = 0

        while len(current_level) > 1:
            level += 1
            current_level = self._build_level(current_level)
            nodes[level] = current_level

        return nodes

    def _build_level(self, prev_level: List[bytes]) -> List[bytes]:
        """
        Builds one level of the tree by hashing pairs of nodes.
        
        Args:
            prev_level: Previous level of the tree
            
        Returns:
            List[bytes]: Newly constructed level
        """
        current_level = []
        for i in range(0, len(prev_level), 2):
            left = prev_level[i]
            right = prev_level[i + 1] if i + 1 < len(prev_level) else left
            current_level.append(self._hash_nodes(left, right))
        return current_level

    def _hash_nodes(self, left: bytes, right: bytes) -> bytes:
        """
        Hashes two nodes together.
        
        Args:
            left: Left node
            right: Right node
            
        Returns:
            bytes: Hash of the two nodes
        """
        combined = bytearray()
        combined.extend(left)
        combined.extend(right)
        return hashlib.sha256(combined).digest()

    def get_root(self) -> bytes:
        """Returns the root of the tree."""
        max_level = max(self.nodes.keys())
        return self.nodes[max_level][0]

    def get_path(self, index: int) -> List[bytes]:
        """
        Generates the proof path for a given leaf.
        
        Args:
            index: Index of the leaf
            
        Returns:
            List[bytes]: Merkle proof path
        """
        path = []
        for level in range(len(self.nodes) - 1):
            level_nodes = self.nodes[level]
            sibling_idx = index + 1 if index % 2 == 0 else index - 1
            if sibling_idx < len(level_nodes):
                path.append(level_nodes[sibling_idx])
            index //= 2
        return path

    @staticmethod
    def verify_path(leaf: bytes, path: List[bytes], root: bytes, leaf_index: int) -> bool:
        """
        Verifies that a proof path is valid.
        
        Args:
            leaf: Leaf to verify
            path: Proof path
            root: Expected root
            leaf_index: Index of the leaf
            
        Returns:
            bool: True if the path is valid
        """
        current = leaf
        index = leaf_index
        
        for sibling in path:
            if index % 2 == 0:
                left, right = current, sibling
            else:
                left, right = sibling, current
                
            combined = bytearray()
            combined.extend(left)
            combined.extend(right)
            current = hashlib.sha256(combined).digest()
            index //= 2
        
        return current == root

class MerkleTreeVerifier:
    """Verifier for Merkle tree in HISE"""
    
    @staticmethod
    def verify_tree(batch: HISEBatchWithProofs, original_messages: List[bytes]) -> bool:
        """
        Verifies the integrity of the Merkle tree with MTVer.
        
        Args:
            batch: Message batch with proofs
            original_messages: Original messages for verification
            
        Returns:
            bool: True if the tree is valid
        """
        # 1. Size verification
        if not is_power_of_two(batch.N):
            return False

        # 2. Verify leaves and paths
        for i in range(len(original_messages)):
            leaf = compute_merkle_leaf(
                original_messages[i],
                batch.batch_keys.rho_k[i],
                batch.batch_keys.r_k[i]
            )
            
            if not MerkleTree.verify_path(leaf, batch.merkle_paths[i], batch.root, i):
                return False

        # 3. Verify level consistency
        levels = build_tree_levels(batch.merkle_paths, batch.N)
        return verify_tree_consistency(levels)

###########################################################################################################
# UTILITY FUNCTIONS
###########################################################################################################

def is_power_of_two(n: int) -> bool:
    """Checks if a number is a power of 2."""
    if n <= 0:
        return False
    return (n & (n - 1)) == 0

def compute_merkle_leaf(message: bytes, rho: Scalar, r: Scalar) -> bytes:
    """Computes a Merkle tree leaf according to the construction"""
    data = bytearray()
    data.extend(message)
    data.extend(group.serialize(rho.value))
    data.extend(group.serialize(r.value))
    return hashlib.sha256(data).digest()

def compute_root_from_leaf(leaf: bytes, path: List[bytes], leaf_index: int) -> bytes:
    """
    Computes tree root from a leaf and its path.
    
    Args:
        leaf: Leaf to compute path from
        path: List of nodes forming the proof path
        leaf_index: Position of the leaf in the tree
        
    Returns:
        bytes: Computed root
    """
    current = leaf
    index = leaf_index
    
    for sibling in path:
        combined = bytearray()
        if index % 2 == 0:
            combined.extend(current)
            combined.extend(sibling)
        else:
            combined.extend(sibling)
            combined.extend(current)
        current = hashlib.sha256(combined).digest()
        index //= 2
        
    return current

def build_tree_levels(paths: List[List[bytes]], N: int) -> List[List[bytes]]:
    """
    Reconstructs tree levels from paths.
    
    Args:
        paths: List of proof paths
        N: Total tree size
    
    Returns:
        List[List[bytes]]: Reconstructed tree levels
    """
    if not paths:
        return []
        
    height = len(paths[0])
    levels = [[] for _ in range(height + 1)]
    
    # Place known leaves
    for i in range(len(paths)):
        levels[0].append((i, paths[i][0]))
        
    # Reconstruct upper levels
    for level in range(1, height + 1):
        for i in range(0, len(levels[level-1]), 2):
            if i + 1 < len(levels[level-1]):
                left = levels[level-1][i][1]
                right = levels[level-1][i+1][1]
                combined = bytearray()
                combined.extend(left)
                combined.extend(right)
                parent_hash = hashlib.sha256(combined).digest()
                levels[level].append((i//2, parent_hash))
                
    return levels

def verify_tree_consistency(levels: List[List[bytes]]) -> bool:
    """Verifies consistency between tree levels"""
    for level_idx in range(len(levels) - 1):
        level = levels[level_idx]
        next_level = levels[level_idx + 1]
        
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                left = level[i][1]
                right = level[i+1][1]
                combined = bytearray()
                combined.extend(left)
                combined.extend(right)
                computed_parent = hashlib.sha256(combined).digest()
                
                parent_idx = i // 2
                if parent_idx >= len(next_level) or next_level[parent_idx][1] != computed_parent:
                    return False
                    
    return True
