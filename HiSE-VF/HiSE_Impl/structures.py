from charm.toolbox.pairinggroup import PairingGroup, ZR
from charm.core.math.integer import integer
from typing import Tuple, Any, List
from nizk import HiseEncNizkStatement, HiseEncNizkProof
from dataclasses import dataclass


# Initialize the pairing group
group = PairingGroup('BN254')


###########################################################################################################
# CORE MATHEMATICAL STRUCTURES
###########################################################################################################


from dataclasses import dataclass
from typing import Tuple, Any, List
from scalar_types import Scalar

@dataclass
class HISEBatch:
    N: int
    root: bytes
    cipher_tree: List[bytes]
    omega: List[bytes]
    r_values: List[Scalar]
    g2_r_values: List[Any]

@dataclass
class HISEKeys:
    rho_k: List[Scalar]
    r_k: List[Scalar]
    g2_r_k: List[Any]

@dataclass
class HISEBatchWithProofs:
    N: int
    root: bytes
    cipher_tree: List[bytes]
    omega: List[bytes]
    r_values: List[Scalar]
    g2_r_values: List[Any]
    enc_proofs: List[Tuple['HiseEncNizkStatement', 'HiseEncNizkProof']]
    x_w: bytes
    merkle_paths: List[List[bytes]]
    batch_keys: HISEKeys