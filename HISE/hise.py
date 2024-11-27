from typing import List, Tuple, Optional, Any
from dataclasses import dataclass
import random
from polynomial import Polynomial, Scalar
import utils

# Type alias comme en Rust
HiseWitnessCommitment = Tuple[Any, Any]  # (G1Projective, G1Projective)

@dataclass
class HiseNizkProofParams:
    g: Any  # G1Projective
    h: Any  # G1Projective

    @classmethod
    def new(cls) -> 'HiseNizkProofParams':
        g = utils.get_generator_in_g1()
        
        while True:
            r = Scalar(random.randrange(utils.curve_order))
            # avoid degenerate points
            if r != Scalar.zero():
                h = utils.multiply(g, r.value)
                return cls(g=g, h=h)





@dataclass
class HiseEncNizkProof:
    ut1: Any
    ut2: Any
    alpha_z1: Scalar
    alpha_z2: Scalar

    @staticmethod
    def random_oracle(ut1: Any, ut2: Any) -> Scalar:
        # Utilisation des coordonnées x uniquement pour le hachage
        bytes_data = bytearray()
        bytes_data.extend(str(ut1[0]).encode())  # Coordonnée x de ut1
        bytes_data.extend(str(ut2[0]).encode())  # Coordonnée x de ut2
        return utils.hash_to_scalar(bytes_data)

    @classmethod
    def prove(cls, witness: 'HiseNizkWitness', stmt: 'HiseEncNizkStatement') -> 'HiseEncNizkProof':
        # Génération des valeurs aléatoires modulo l'ordre de la courbe
        αt1 = Scalar(random.randrange(utils.curve_order))
        αt2 = Scalar(random.randrange(utils.curve_order))

        # Calcul des commitments
        ut1 = utils.multiply(stmt.h_of_x_eps, αt1.value)
        temp1 = utils.multiply(stmt.g, αt1.value)
        temp2 = utils.multiply(stmt.h, αt2.value)
        ut2 = utils.add(temp1, temp2)

        # Génération du challenge
        c = cls.random_oracle(ut1, ut2)

        # Calcul des réponses (modulo l'ordre de la courbe)
        alpha_z1 = Scalar((αt1.value + (c.value * witness.α1.value)) % utils.curve_order)
        alpha_z2 = Scalar((αt2.value + (c.value * witness.α2.value)) % utils.curve_order)

        return cls(ut1=ut1, ut2=ut2, alpha_z1=alpha_z1, alpha_z2=alpha_z2)

    @staticmethod
    def verify(stmt: 'HiseEncNizkStatement', proof: 'HiseEncNizkProof') -> bool:
        c = HiseEncNizkProof.random_oracle(proof.ut1, proof.ut2)

        # Vérification de la première équation
        lhs1 = utils.multiply(stmt.h_of_x_eps, proof.alpha_z1.value)
        temp1 = utils.multiply(stmt.h_of_x_eps_pow_a, c.value)
        rhs1 = utils.add(proof.ut1, temp1)

        # Vérification de la deuxième équation
        temp2 = utils.multiply(stmt.g, proof.alpha_z1.value)
        temp3 = utils.multiply(stmt.h, proof.alpha_z2.value)
        lhs2 = utils.add(temp2, temp3)
        temp4 = utils.multiply(stmt.com, c.value)
        rhs2 = utils.add(proof.ut2, temp4)

        return utils.points_equal(lhs1, rhs1) and utils.points_equal(lhs2, rhs2)





@dataclass
class HiseDecNizkProof:
    ut1: Any
    ut2: Any
    ut3: Any
    alpha_z1: Scalar
    alpha_z2: Scalar
    beta_z1: Scalar
    beta_z2: Scalar

    @staticmethod
    def random_oracle(ut1: Any, ut2: Any, ut3: Any) -> Scalar:
        bytes_data = bytearray()
        # Utilisation des coordonnées x uniquement
        bytes_data.extend(str(ut1[0]).encode())
        bytes_data.extend(str(ut2[0]).encode())
        bytes_data.extend(str(ut3[0]).encode())
        return utils.hash_to_scalar(bytes_data)

    @classmethod
    def prove(cls, witness: 'HiseNizkWitness', stmt: 'HiseDecNizkStatement') -> 'HiseDecNizkProof':
        # Génération des valeurs aléatoires
        αt1 = Scalar(random.randrange(utils.curve_order))
        αt2 = Scalar(random.randrange(utils.curve_order))
        βt1 = Scalar(random.randrange(utils.curve_order))
        βt2 = Scalar(random.randrange(utils.curve_order))

        # Calcul des commitments
        ut1_part1 = utils.multiply(stmt.h_of_x_eps, αt1.value)
        ut1_part2 = utils.multiply(stmt.h_of_x_w, βt1.value)
        ut1 = utils.add(ut1_part1, ut1_part2)

        ut2_part1 = utils.multiply(stmt.g, αt1.value)
        ut2_part2 = utils.multiply(stmt.h, αt2.value)
        ut2 = utils.add(ut2_part1, ut2_part2)

        ut3_part1 = utils.multiply(stmt.g, βt1.value)
        ut3_part2 = utils.multiply(stmt.h, βt2.value)
        ut3 = utils.add(ut3_part1, ut3_part2)

        # Génération du challenge
        c = cls.random_oracle(ut1, ut2, ut3)

        # Calcul des réponses
        alpha_z1 = Scalar((αt1.value + (c.value * witness.α1.value)) % utils.curve_order)
        alpha_z2 = Scalar((αt2.value + (c.value * witness.α2.value)) % utils.curve_order)
        beta_z1 = Scalar((βt1.value + (c.value * witness.β1.value)) % utils.curve_order)
        beta_z2 = Scalar((βt2.value + (c.value * witness.β2.value)) % utils.curve_order)

        return cls(ut1=ut1, ut2=ut2, ut3=ut3,
                  alpha_z1=alpha_z1, alpha_z2=alpha_z2,
                  beta_z1=beta_z1, beta_z2=beta_z2)

    @staticmethod
    def verify(stmt: 'HiseDecNizkStatement', proof: 'HiseDecNizkProof') -> bool:
        c = HiseDecNizkProof.random_oracle(proof.ut1, proof.ut2, proof.ut3)

        # Vérification de la première équation
        lhs1_part1 = utils.multiply(stmt.h_of_x_eps, proof.alpha_z1.value)
        lhs1_part2 = utils.multiply(stmt.h_of_x_w, proof.beta_z1.value)
        lhs1 = utils.add(lhs1_part1, lhs1_part2)

        rhs1 = utils.add(
            proof.ut1,
            utils.multiply(stmt.h_of_x_eps_pow_a_h_of_x_w_pow_b, c.value)
        )

        # Vérification de la deuxième équation
        lhs2_part1 = utils.multiply(stmt.g, proof.alpha_z1.value)
        lhs2_part2 = utils.multiply(stmt.h, proof.alpha_z2.value)
        lhs2 = utils.add(lhs2_part1, lhs2_part2)

        rhs2 = utils.add(proof.ut2, utils.multiply(stmt.com_a, c.value))

        # Vérification de la troisième équation
        lhs3_part1 = utils.multiply(stmt.g, proof.beta_z1.value)
        lhs3_part2 = utils.multiply(stmt.h, proof.beta_z2.value)
        lhs3 = utils.add(lhs3_part1, lhs3_part2)

        rhs3 = utils.add(proof.ut3, utils.multiply(stmt.com_b, c.value))

        return (utils.points_equal(lhs1, rhs1) and 
                utils.points_equal(lhs2, rhs2) and 
                utils.points_equal(lhs3, rhs3))






@dataclass
class HiseEncNizkStatement:
    g: Any  # G1Projective
    h: Any  # G1Projective
    h_of_x_eps: Any  # G1Projective - H(x_eps)
    h_of_x_eps_pow_a: Any  # G1Projective - H(x_eps)^a
    com: Any  # G1Projective - ped com g^a.h^b

@dataclass
class HiseDecNizkStatement:
    g: Any  # G1Projective
    h: Any  # G1Projective
    h_of_x_eps: Any  # G1Projective - H(x_eps)
    h_of_x_w: Any  # G1Projective - H(x_w)
    h_of_x_eps_pow_a_h_of_x_w_pow_b: Any  # G1Projective - H(x_eps)^a.H(w)^b
    com_a: Any  # G1Projective - ped com g^a.h^b
    com_b: Any  # G1Projective

@dataclass
class HiseNizkWitness:
    α1: Scalar
    α2: Scalar
    β1: Scalar
    β2: Scalar

class Hise:
    @staticmethod
    def setup(n: int, t: int) -> Tuple[HiseNizkProofParams, List[HiseNizkWitness], List[HiseWitnessCommitment]]:
        pp = HiseNizkProofParams.new()

        p1 = utils.sample_random_poly(t - 1)
        p2 = utils.sample_random_poly(t - 1)
        p3 = utils.sample_random_poly(t - 1)
        p4 = utils.sample_random_poly(t - 1)

        private_keys = []
        commitments = []

        for i in range(1, n + 1):
            x = Scalar(i)
            α1_i = p1.eval(x)
            α2_i = p2.eval(x)
            β1_i = p3.eval(x)
            β2_i = p4.eval(x)

            witness = HiseNizkWitness(
                α1=α1_i,
                α2=α2_i,
                β1=β1_i,
                β2=β2_i
            )
            private_keys.append(witness)

            com_alpha = utils.pedersen_commit_in_g1(pp.g, pp.h, α1_i, α2_i)
            com_beta = utils.pedersen_commit_in_g1(pp.g, pp.h, β1_i, β2_i)
            commitments.append((com_alpha, com_beta))

        return pp, private_keys, commitments

    @staticmethod
    def get_random_data_commitment() -> bytes:
        """Génère un commitment aléatoire de 32 bytes."""
        return random.randbytes(32)

    @staticmethod
    def encrypt_server(
        pp: HiseNizkProofParams,
        key: HiseNizkWitness,
        com: HiseWitnessCommitment,
        gamma: bytes  # merkle root, 32 bytes
    ) -> Tuple[HiseEncNizkStatement, HiseEncNizkProof]:
        # gamma comes from the client
        h_of_gamma = utils.hash_to_g1(gamma)
        h_of_gamma_pow_α1 = utils.multiply(h_of_gamma, key.α1.value)
        
        stmt = HiseEncNizkStatement(
            g=pp.g,
            h=pp.h,
            h_of_x_eps=h_of_gamma,
            h_of_x_eps_pow_a=h_of_gamma_pow_α1,
            com=com[0]  # com.0 en Rust
        )

        proof = HiseEncNizkProof.prove(key, stmt)
        return stmt, proof

    @staticmethod
    def decrypt_server(
        pp: HiseNizkProofParams,
        key: HiseNizkWitness,
        com: HiseWitnessCommitment,
        x_eps: bytes,
        x_w: bytes
    ) -> Tuple[HiseDecNizkStatement, HiseDecNizkProof]:
        # x_eps and x_w come from the client
        h_of_x_eps = utils.hash_to_g1(x_eps)
        h_of_x_w = utils.hash_to_g1(x_w)

        eval = utils.add(
            utils.multiply(h_of_x_eps, key.α1.value),
            utils.multiply(h_of_x_w, key.β1.value)
        )

        stmt = HiseDecNizkStatement(
            g=pp.g,
            h=pp.h,
            h_of_x_eps=h_of_x_eps,
            h_of_x_w=h_of_x_w,
            h_of_x_eps_pow_a_h_of_x_w_pow_b=eval,
            com_a=com[0],
            com_b=com[1]
        )

        proof = HiseDecNizkProof.prove(key, stmt)
        return stmt, proof

    @staticmethod
    def encrypt_client_phase_1() -> bytes:
        """Phase 1 of encryption: Client sends a merkle data commitment to the servers.
        For simplicity a random commitment is taken."""
        return Hise.get_random_data_commitment()

    @staticmethod
    def encrypt_client_phase_2(
        m: int,
        server_responses: List[Tuple[HiseEncNizkStatement, HiseEncNizkProof]]
    ) -> None:
        # Vérification des preuves
        for stmt, proof in server_responses:
            assert HiseEncNizkProof.verify(stmt, proof)

        # Calcul des coefficients de Lagrange
        n = len(server_responses)
        all_xs = [Scalar(i) for i in range(1, n + 1)]
        coeffs = Polynomial.lagrange_coefficients(all_xs)

        # Calcul de l'évaluation DPRF interpolée
        solo_evals = [stmt.h_of_x_eps_pow_a for stmt, _ in server_responses]
        gk = utils.multi_exp_g1(solo_evals, coeffs[:n])  # Point G1
        log_m = (m - 1).bit_length()

        # Travail sur chaque chiffrement
        g2_generator = utils.get_generator_in_g2()
        for i in range(m):
            r_i = Scalar(random.randrange(utils.curve_order))
            g2_pow_r_i = utils.multiply(g2_generator, r_i.value)  # Point G2
            
            for j in range(log_m):
                x_w_j = Hise.get_random_data_commitment()
                h_of_x_w_j = utils.hash_to_g1(x_w_j)
                h_of_x_w_j_pow_r_i = utils.multiply(h_of_x_w_j, r_i.value)

            # Pairing(G2, G1) dans cet ordre
            mk_j = utils.pairing(g2_pow_r_i, gk)  # Pairing(G2, G1)


    @staticmethod
    def decrypt_client_phase_1() -> Tuple[bytes, bytes]:
        """Phase 1 of decryption: Client sends the values x_eps and x_w to the servers.
        The values x_eps and x_w correspond to hash values at the root and at the node with path w.
        For simplicity random commitments are taken."""
        x_eps = Hise.get_random_data_commitment()
        x_w = Hise.get_random_data_commitment()
        return x_eps, x_w

    @staticmethod
    def decrypt_client_phase_2(
        m: int,
        server_responses: List[Tuple[HiseDecNizkStatement, HiseDecNizkProof]]
    ) -> None:
        # Vérification des preuves
        for stmt, proof in server_responses:
            assert HiseDecNizkProof.verify(stmt, proof)

        # Calcul des coefficients de Lagrange
        n = len(server_responses)
        all_xs = [Scalar(i) for i in range(1, n + 1)]
        coeffs = Polynomial.lagrange_coefficients(all_xs)

        # Calcul de l'évaluation DPRF interpolée
        solo_evals = [stmt.h_of_x_eps_pow_a_h_of_x_w_pow_b for stmt, _ in server_responses]
        gk = utils.multi_exp_g1(solo_evals, coeffs[:n])  # Point G1

        g2_generator = utils.get_generator_in_g2()
        R = utils.multiply(g2_generator, Scalar(random.randrange(utils.curve_order)).value)  # Point G2
        S_w = utils.multiply(g2_generator, Scalar(random.randrange(utils.curve_order)).value)  # Point G2
        g_B = server_responses[0][0].com_b  # Point G1

        for i in range(m):
            # Pairing(G2, G1) dans cet ordre
            e_r_z = utils.pairing(R, gk)  # Pairing(G2, G1)
            e_g_B_s_w = utils.pairing(S_w, g_B)  # Pairing(G2, G1)
            # Multiplication par l'inverse dans GT
            result = e_r_z * (e_g_B_s_w ** (utils.curve_order - 1))


import unittest
import time

class TestHise(unittest.TestCase):
    def test_enc_latency(self):
        """Test de latence pour l'encryption."""
        # rows = [[2, 4]]  # Paramètres réduits
        rows = [[2,4,6,8], [3,6,9,12], [4,8,12,16]]

        message_sizes = [1, 10, 100]

        for row in rows:
            for t in row:
                durations = []
                gamma = Hise.encrypt_client_phase_1()

                for m in message_sizes:
                    # Configuration initiale
                    pp, keys, coms = Hise.setup(n=t, t=t)

                    # Simulation des réponses des serveurs
                    server_responses = []
                    for i in range(t):
                        stmt, proof = Hise.encrypt_server(pp, keys[i], coms[i], gamma)
                        server_responses.append((stmt, proof))

                    # Mesurer la latence d'encryption
                    start_time = time.time()
                    Hise.encrypt_client_phase_2(m, server_responses)
                    duration = time.time() - start_time
                    
                    print(f"HiSE encrypt for {t} nodes and {m} messages: {duration:.3f} seconds")
                    durations.append(duration)

                print(f"t = {t}: ", end='')
                print(' & '.join(f"{d:.3f}" for d in durations))

    def test_dec_latency(self):
        """Test de latence pour le déchiffrement."""
        # rows = [[2, 4]]  # Paramètres réduits
        rows = [[2,4,6,8], [3,6,9,12], [4,8,12,16]]
        message_sizes = [1, 10, 100]

        for row in rows:
            for t in row:
                durations = []
                for m in message_sizes:
                    # Configuration initiale
                    pp, keys, coms = Hise.setup(n=t, t=t)

                    # Simulation des réponses des serveurs
                    server_responses = []
                    x_eps, x_w = Hise.decrypt_client_phase_1()

                    for i in range(t):
                        stmt, proof = Hise.decrypt_server(pp, keys[i], coms[i], x_eps, x_w)
                        server_responses.append((stmt, proof))

                    # Mesurer la latence de déchiffrement
                    start_time = time.time()
                    Hise.decrypt_client_phase_2(m, server_responses)
                    duration = time.time() - start_time

                    print(f"HiSE decrypt for {t} nodes and {m} messages: {duration:.3f} seconds")
                    durations.append(duration)

                print(f"t = {t}: ", end='')
                print(' & '.join(f"{d:.3f}" for d in durations))

    def test_correctness_enc_nizk(self):
        """Test de correction pour les preuves NIZK d'encryption avec débogage."""
        print("\n=== Démarrage du test de correction NIZK ===")
        
        α1 = Scalar(random.randrange(utils.curve_order))
        α2 = Scalar(random.randrange(utils.curve_order))
        β1 = Scalar(random.randrange(utils.curve_order))
        β2 = Scalar(random.randrange(utils.curve_order))
        
        
        witness = HiseNizkWitness(α1=α1, α2=α2, β1=β1, β2=β2)
        

        pp = HiseNizkProofParams.new()


        
        h_of_x_eps = utils.hash_to_g1(bytes([0] * 32))

        h_of_x_eps_pow_a = utils.multiply(h_of_x_eps, α1.value)

        
        com = utils.pedersen_commit_in_g1(pp.g, pp.h, α1, α2)

        
        stmt = HiseEncNizkStatement(
            g=pp.g,
            h=pp.h,
            h_of_x_eps=h_of_x_eps,
            h_of_x_eps_pow_a=h_of_x_eps_pow_a,
            com=com
        )
        
        proof = HiseEncNizkProof.prove(witness, stmt)
        
        print("\nVérification de la preuve...")
        check = HiseEncNizkProof.verify(stmt, proof)
        print(f"Résultat de la vérification: {check}")
        
        self.assertTrue(check)

if __name__ == '__main__':
    unittest.main()