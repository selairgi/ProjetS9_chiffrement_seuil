from typing import List, Tuple
import hashlib

from charm.toolbox.pairinggroup import ZR, G2, pair

from structures import *
from scalar_types import *
from nizk import *
from merkle import *
from polynomial import *
from utils import *



###########################################################################################################
# DISTRIBUTED ENCRYPTION AND DECRYPTION IMPLEMENTATION
###########################################################################################################

class Hise:
    @staticmethod
    def setup(n: int, t: int) -> Tuple[HiseNizkProofParams, List[HiseNizkWitness], List[HiseWitnessCommitment]]:
        """Setup with separate polynomials for α and β"""
        pp = HiseNizkProofParams.new()
        
        # Two separate polynomials
        alpha_poly = sample_random_poly(t - 1)  # polynomial for α
        beta_poly = sample_random_poly(t - 1)   # polynomial for β
        
        private_keys = []
        commitments = []
        
        for i in range(1, n + 1):
            x_i = Scalar(i)
            
            # Separate shares for α and β
            alpha_share = alpha_poly.eval(x_i)
            beta_share = beta_poly.eval(x_i)
            
            # Separate randomization
            alpha_rand = Scalar.random()
            beta_rand = Scalar.random()
            
            witness = HiseNizkWitness(
                α1=alpha_share,
                α2=alpha_rand,
                β1=beta_share,
                β2=beta_rand
            )
            private_keys.append(witness)
            
            # Separate commitments for α and β
            com_alpha = pedersen_commit(pp.g, pp.h, alpha_share, alpha_rand)
            com_beta = pedersen_commit(pp.g, pp.h, beta_share, beta_rand)
            commitments.append((com_alpha, com_beta))
            
        return pp, private_keys, commitments

    @staticmethod
    def pad_messages(messages: List[bytes]) -> List[bytes]:
        """Pad message list to power of 2"""
        n = len(messages)
        next_pow2 = 1 << (n - 1).bit_length()
        if n != next_pow2:
            messages.extend([b''] * (next_pow2 - n))
        return messages

    @staticmethod
    def generate_batch_keys(N: int) -> HISEKeys:
        """Generate random values for a batch"""
        g2_generator = group.random(G2)
        rho_k = [Scalar.random() for _ in range(N)]
        r_k = [Scalar.random() for _ in range(N)]
        g2_r_k = [(g2_generator ** r.value) for r in r_k]
        return HISEKeys(rho_k=rho_k, r_k=r_k, g2_r_k=g2_r_k)

    @staticmethod
    def get_random_data_commitment() -> bytes:
        """Generate a random 32-byte commitment"""
        # Using hashlib to generate a proper 32-byte commitment from a random ZR element
        random_zr = group.random(ZR)
        return hashlib.sha256(str(random_zr).encode()).digest()

    @staticmethod
    def _compute_merkle_leaf(message: bytes, rho: Scalar, r: Scalar) -> bytes:
        """Compute a Merkle tree leaf"""
        data = bytearray()
        data.extend(message)
        # Use proper serialization for Charm elements
        data.extend(str(rho.value).encode())
        data.extend(str(r.value).encode())
        return hashlib.sha256(data).digest()

    @staticmethod
    def dist_gr_enc(messages: List[bytes], pp: HiseNizkProofParams, 
                    keys: List[HiseNizkWitness], coms: List[HiseWitnessCommitment], 
                    t: int) -> HISEBatchWithProofs:
        """
        Distributed encryption of a message set according to HISE protocol.
        
        Args:
            messages: Messages to encrypt
            pp: Public HISE parameters
            keys: Server keys
            coms: Commitments
            t: Threshold
            
        Returns:
            HISEBatchWithProofs with encrypted messages and proofs
        """
        # Initialization and padding
        N = 1 << (len(messages) - 1).bit_length()
        padded_messages = messages + [b''] * (N - len(messages))
        batch_keys = Hise.generate_batch_keys(N)
        
        # Merkle tree construction
        leaves = [
            Hise._compute_merkle_leaf(msg, batch_keys.rho_k[i], batch_keys.r_k[i])
            for i, msg in enumerate(padded_messages)
        ]
        merkle_tree = MerkleTree(leaves)
        root = merkle_tree.get_root()
        merkle_paths = [merkle_tree.get_path(i) for i in range(len(messages))]
        
        # Generate x_w and compute hashes
        x_w = Hise.get_random_data_commitment()
        h_root = hash_to_g1(root)
        h_x_w = hash_to_g1(x_w)

        # Collect server shares and generate proofs
        server_shares = []
        enc_proofs = []
        
        for i in range(t):
            # Compute α and β shares
            alpha_share = h_root ** keys[i].α1.value
            beta_share = h_x_w ** keys[i].β1.value
            combined_share = alpha_share * beta_share
            server_shares.append(combined_share)
            
            # Generate and verify proof
            stmt = HiseEncNizkStatement(
                g=pp.g, h=pp.h,
                h_of_x_eps=h_root,
                h_of_x_eps_pow_a=alpha_share,
                com=coms[i][0]
            )
            proof = HiseEncNizkProof.prove(keys[i], stmt)
            assert proof.verify(stmt), f"Invalid proof for server {i}"
            enc_proofs.append((stmt, proof))

        # Compute DPRF
        xs = [Scalar(i + 1) for i in range(t)]
        coeffs = Polynomial.lagrange_coefficients(xs)
        
        # Calculate gk using multi-exponentiation
        gk = server_shares[0] ** coeffs[0].value
        for share, coeff in zip(server_shares[1:], coeffs[1:]):
            gk *= share ** coeff.value

        # Encrypt messages
        cipher_tree = []
        omega = []
        
        for k in range(N):
            omega.append(format(k, f'0{(N-1).bit_length()}b').encode())
            
            if k < len(messages):
                mk = pair(batch_keys.g2_r_k[k], gk)
                # Proper handling of pairing result serialization
                mk_bytes = hashlib.sha256(str(mk).encode()).digest()
                cipher = bytes(a ^ b for a, b in zip(padded_messages[k].ljust(32, b'\0'), mk_bytes))
            else:
                cipher = b'\0' * 32
            cipher_tree.append(cipher)
    
        return HISEBatchWithProofs(
            N=N,
            root=root,
            cipher_tree=cipher_tree,
            omega=omega,
            r_values=batch_keys.r_k,
            g2_r_values=batch_keys.g2_r_k,
            enc_proofs=enc_proofs,
            x_w=x_w,
            merkle_paths=merkle_paths,
            batch_keys=batch_keys
        )

    @staticmethod
    def verify_merkle_proof(batch: HISEBatchWithProofs, original_messages: List[bytes]) -> bool:
        """
        MTVer verification with original messages
        """
        # 1. Size verification
        if not is_power_of_two(batch.N):
            return False

        # 2. Verify leaves and paths
        for i in range(len(original_messages)):
            leaf = Hise._compute_merkle_leaf(
                original_messages[i],
                batch.batch_keys.rho_k[i],
                batch.batch_keys.r_k[i]
            )
            if not MerkleTree.verify_path(leaf, batch.merkle_paths[i], batch.root, i):
                return False

        return True

    @staticmethod
    def verify_batch_proofs(batch: HISEBatchWithProofs) -> bool:
        """Verify all NIZK proofs in the batch"""
        for stmt, proof in batch.enc_proofs:
            if not proof.verify(stmt):
                return False
        return True

    @staticmethod
    def dist_gr_dec(batch: HISEBatchWithProofs, pp: HiseNizkProofParams, 
                    keys: List[HiseNizkWitness], coms: List[HiseWitnessCommitment],
                    t: int, original_messages: List[bytes]) -> List[bytes]:
        """
        Distributed decryption according to HISE protocol.
        
        Args:
            batch: Batch of encrypted messages with proofs
            pp: Public HISE parameters
            keys: Server keys
            coms: Commitments
            t: Threshold
            original_messages: Original messages for MTVer verification
            
        Returns:
            List of decrypted messages
            
        Raises:
            ValueError: If MTVer verification or proofs fail, or if threshold is invalid
        """
        # Check threshold validity
        if t <= 0:
            raise ValueError("Threshold must be positive")
        if t > len(keys):
            raise ValueError(f"Threshold {t} exceeds number of available servers {len(keys)}")
        if t > len(coms):
            raise ValueError(f"Threshold {t} exceeds number of available commitments {len(coms)}")

        # 1. MTVer verification
        if not Hise.verify_merkle_proof(batch, original_messages):
            raise ValueError("MTVer verification failed")
            
        # 2. Verify encryption proofs
        if not Hise.verify_batch_proofs(batch):
            raise ValueError("Encryption proof verification failed")

        # 3. Prepare hashes
        h_root = hash_to_g1(batch.root)
        h_x_w = hash_to_g1(batch.x_w)
        
        # 4. Collect server shares
        server_shares = []
        try:
            for i in range(t):
                # Compute α and β shares
                alpha_share = h_root ** keys[i].α1.value
                beta_share = h_x_w ** keys[i].β1.value
                combined_share = alpha_share * beta_share
                
                # Verify decryption proofs
                dec_stmt = HiseDecNizkStatement(
                    g=pp.g,
                    h=pp.h,
                    h_of_x_eps=h_root,
                    h_of_x_w=h_x_w,
                    h_of_x_eps_pow_a_h_of_x_w_pow_b=combined_share,
                    com_a=coms[i][0],
                    com_b=coms[i][1]
                )
                
                dec_proof = HiseDecNizkProof.prove(keys[i], dec_stmt)
                if not dec_proof.verify(dec_stmt):
                    raise ValueError(f"Invalid decryption proof for server {i}")
                
                server_shares.append(combined_share)
        except IndexError:
            raise ValueError(f"Not enough valid servers available for threshold {t}")

        # 5. Compute DPRF
        xs = [Scalar(i + 1) for i in range(t)]
        coeffs = Polynomial.lagrange_coefficients(xs)

        # Calculate gk using multi-exponentiation
        gk = server_shares[0] ** coeffs[0].value
        for share, coeff in zip(server_shares[1:], coeffs[1:]):
            gk *= share ** coeff.value

        # 6. Decrypt valid messages
        decrypted_messages = []
        valid_indices = range(len(batch.cipher_tree))
        
        for i in valid_indices:
            if batch.cipher_tree[i] != b'\0' * 32:  # Skip padding
                mk = pair(batch.g2_r_values[i], gk)
                mk_bytes = hashlib.sha256(str(mk).encode()).digest()
                
                message = bytes(a ^ b for a, b in zip(batch.cipher_tree[i], mk_bytes))
                message = message.rstrip(b'\0')
                
                if message:
                    decrypted_messages.append(message)

        return decrypted_messages
