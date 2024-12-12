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

# class Scalar:
#     """Wrapper for ZR elements with arithmetic operations"""
#     def __init__(self, value):
#         if isinstance(value, integer):
#             self.value = group.init(ZR, int(value))
#         elif isinstance(value, int):
#             self.value = group.init(ZR, value)
#         else:
#             self.value = value

#     @classmethod
#     def zero(cls):
#         return cls(0)

#     @classmethod
#     def one(cls):
#         return cls(1)

#     def __add__(self, other):
#         return Scalar(self.value + other.value)

#     def __sub__(self, other):
#         return Scalar(self.value - other.value)

#     def __mul__(self, other):
#         return Scalar(self.value * other.value)

#     def __eq__(self, other):
#         return self.value == other.value

#     def __neg__(self):
#         return Scalar(-self.value)

#     def invert(self):
#         if self.value == 0:
#             return None
#         return Scalar(1 / self.value)

#     @classmethod
#     def random(cls):
#         """Generate a random scalar"""
#         return cls(group.random(ZR))


# @dataclass
# class HISEBatch:
#     N: int
#     root: bytes
#     cipher_tree: List[bytes]
#     omega: List[bytes]
#     r_values: List[Scalar]
#     g2_r_values: List[Any]

# @dataclass
# class HISEKeys:
#     rho_k: List[Scalar]
#     r_k: List[Scalar]
#     g2_r_k: List[Any]

# @dataclass
# class HISEBatchWithProofs:
#     N: int
#     root: bytes
#     cipher_tree: List[bytes]
#     omega: List[bytes]
#     r_values: List[Scalar]
#     g2_r_values: List[Any]
#     enc_proofs: List[Tuple['HiseEncNizkStatement', 'HiseEncNizkProof']]
#     x_w: bytes
#     merkle_paths: List[List[bytes]]
#     batch_keys: HISEKeys

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