from charm.toolbox.pairinggroup import PairingGroup, ZR, G1
from dataclasses import dataclass
from typing import Tuple, Any
from scalar_types import Scalar, group


###########################################################################################################
# NIZK PROOF STRUCTURES
###########################################################################################################

# Type alias for HiseWitnessCommitment
HiseWitnessCommitment = Tuple[Any, Any]  # (G1Element, G1Element)

@dataclass
class HiseNizkProofParams:
    """Public parameters for NIZK proofs"""
    g: Any  # G1
    h: Any  # G1

    @classmethod
    def new(cls) -> 'HiseNizkProofParams':
        """Generate new NIZK parameters"""
        g = group.random(G1)
        r = group.random(ZR)
        while r == 0:
            r = group.random(ZR)
        h = g ** r
        return cls(g=g, h=h)


@dataclass
class HiseEncNizkStatement:
    """Statement for encryption NIZK proof"""
    g: Any          # G1
    h: Any          # G1
    h_of_x_eps: Any # G1 - H(x_eps)
    h_of_x_eps_pow_a: Any # G1 - H(x_eps)^a
    com: Any        # G1 - Pedersen commitment

@dataclass
class HiseDecNizkStatement:
    """Statement for decryption NIZK proof"""
    g: Any          # G1
    h: Any          # G1
    h_of_x_eps: Any # G1
    h_of_x_w: Any   # G1
    h_of_x_eps_pow_a_h_of_x_w_pow_b: Any  # G1
    com_a: Any      # G1
    com_b: Any      # G1

@dataclass
class HiseNizkWitness:
    """Witness for NIZK proofs"""
    α1: Scalar
    α2: Scalar
    β1: Scalar
    β2: Scalar

@dataclass
class HiseEncNizkProof:
    """Encryption NIZK proof"""
    ut1: Any
    ut2: Any
    alpha_z1: Scalar
    alpha_z2: Scalar

    @staticmethod
    def random_oracle(ut1: Any, ut2: Any) -> Scalar:
        """Hash function for Fiat-Shamir transform"""
        bytes_data = group.serialize(ut1) + group.serialize(ut2)
        return Scalar(group.hash(bytes_data, type=ZR))

    @classmethod
    def prove(cls, witness: HiseNizkWitness, stmt: HiseEncNizkStatement) -> 'HiseEncNizkProof':
        """Generate NIZK proof for encryption"""
        # Generate random values
        αt1 = Scalar.random()
        αt2 = Scalar.random()

        # Calculate commitments
        ut1 = stmt.h_of_x_eps ** αt1.value
        ut2 = (stmt.g ** αt1.value) * (stmt.h ** αt2.value)

        # Generate challenge
        c = cls.random_oracle(ut1, ut2)

        # Calculate responses
        alpha_z1 = αt1 + (c * witness.α1)
        alpha_z2 = αt2 + (c * witness.α2)

        return cls(ut1=ut1, ut2=ut2, alpha_z1=alpha_z1, alpha_z2=alpha_z2)

    def verify(self, stmt: HiseEncNizkStatement) -> bool:
        """Verify NIZK proof for encryption"""
        c = self.random_oracle(self.ut1, self.ut2)

        # Verify first equation
        lhs1 = stmt.h_of_x_eps ** self.alpha_z1.value
        rhs1 = self.ut1 * (stmt.h_of_x_eps_pow_a ** c.value)

        # Verify second equation
        lhs2 = (stmt.g ** self.alpha_z1.value) * (stmt.h ** self.alpha_z2.value)
        rhs2 = self.ut2 * (stmt.com ** c.value)

        return lhs1 == rhs1 and lhs2 == rhs2

@dataclass
class HiseDecNizkProof:
    """Decryption NIZK proof"""
    ut1: Any
    ut2: Any
    ut3: Any
    alpha_z1: Scalar
    alpha_z2: Scalar
    beta_z1: Scalar
    beta_z2: Scalar

    @staticmethod
    def random_oracle(ut1: Any, ut2: Any, ut3: Any) -> Scalar:
        """Hash function for Fiat-Shamir transform"""
        bytes_data = group.serialize(ut1) + group.serialize(ut2) + group.serialize(ut3)
        return Scalar(group.hash(bytes_data, type=ZR))

    @classmethod
    def prove(cls, witness: HiseNizkWitness, stmt: HiseDecNizkStatement) -> 'HiseDecNizkProof':
        """Generate NIZK proof for decryption"""
        # Generate random values
        αt1 = Scalar.random()
        αt2 = Scalar.random()
        βt1 = Scalar.random()
        βt2 = Scalar.random()

        # Calculate commitments
        ut1 = (stmt.h_of_x_eps ** αt1.value) * (stmt.h_of_x_w ** βt1.value)
        ut2 = (stmt.g ** αt1.value) * (stmt.h ** αt2.value)
        ut3 = (stmt.g ** βt1.value) * (stmt.h ** βt2.value)

        # Generate challenge
        c = cls.random_oracle(ut1, ut2, ut3)

        # Calculate responses
        alpha_z1 = αt1 + (c * witness.α1)
        alpha_z2 = αt2 + (c * witness.α2)
        beta_z1 = βt1 + (c * witness.β1)
        beta_z2 = βt2 + (c * witness.β2)

        return cls(ut1=ut1, ut2=ut2, ut3=ut3,
                  alpha_z1=alpha_z1, alpha_z2=alpha_z2,
                  beta_z1=beta_z1, beta_z2=beta_z2)

    def verify(self, stmt: HiseDecNizkStatement) -> bool:
        """Verify NIZK proof for decryption"""
        c = self.random_oracle(self.ut1, self.ut2, self.ut3)

        # Verify first equation
        lhs1 = (stmt.h_of_x_eps ** self.alpha_z1.value) * (stmt.h_of_x_w ** self.beta_z1.value)
        rhs1 = self.ut1 * (stmt.h_of_x_eps_pow_a_h_of_x_w_pow_b ** c.value)

        # Verify second equation
        lhs2 = (stmt.g ** self.alpha_z1.value) * (stmt.h ** self.alpha_z2.value)
        rhs2 = self.ut2 * (stmt.com_a ** c.value)

        # Verify third equation
        lhs3 = (stmt.g ** self.beta_z1.value) * (stmt.h ** self.beta_z2.value)
        rhs3 = self.ut3 * (stmt.com_b ** c.value)

        return lhs1 == rhs1 and lhs2 == rhs2 and lhs3 == rhs3