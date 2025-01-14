from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2
from typing import Any
import hashlib

from structures import Scalar

group = PairingGroup('BN254')


###########################################################################################################
# UTILITY FUNCTIONS
###########################################################################################################

def hash_to_scalar(msg: bytes) -> Scalar:
    """Hash bytes to a scalar"""
    h = hashlib.sha256(msg).digest()
    return Scalar(group.hash(h, type=ZR))

def hash_to_g1(msg: bytes) -> Any:
    """Hash bytes to a G1 element"""
    h = hashlib.sha256(msg).digest()
    return group.hash(h, type=G1)

def hash_to_g2(msg: bytes) -> Any:
    """Hash bytes to a G2 element"""
    h = hashlib.sha256(msg).digest()
    return group.hash(h, type=G2)

def pedersen_commit(g: Any, h: Any, a: Scalar, b: Scalar) -> Any:
    """Generate a Pedersen commitment"""
    return (g ** a.value) * (h ** b.value)