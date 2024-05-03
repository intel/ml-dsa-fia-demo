# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: MIT

from enum import Enum
import numpy as np
from pulp import LpAffineExpression, LpBinary, LpConstraint, LpConstraintLE, LpConstraintGE, LpInteger, LpMaximize, \
    LpProblem, LpSolverDefault, LpStatusOptimal, lpSum, LpVariable
from termcolor import cprint
from tqdm import tqdm

from helper import DILITHIUM, FAULTY_SIG_FILE_PATH, FAULTY_SIGS_FILE_PATH, S1_HASH_LENGTH, S1_HASH_FILE_PATH, \
    info, load_s1_hash, get_color
from verifier import Verifier

# Turn off messages from ILP solver
LpSolverDefault.msg = False


class Attacker(Verifier):
    class Algorithm(Enum):
        CHES2018 = 0,
        AsiaCCS2019 = 1

    def __init__(self) -> None:
        super().__init__()
        self.s1 = None

    def load_faulty_sig_y_all_coefficients_zero(self):
        """
        Loads a message and a faulty signature from a JSON (JavaScript Object Notation) file. The faulty signature has
        all coefficients of the polynomials in vector y set to 0.

        Returns:
            A message and a faulty signature. The faulty signature has all coefficients of the polynomials in vector y
            set to 0.
        """
        return self.load_sig(FAULTY_SIG_FILE_PATH)

    def load_faulty_sigs_y_some_coefficients_zero(self):
        """
        Loads a list of messages and the corresponding list of faulty signatures from a JSON (JavaScript Object
        Notation) file. Each of the faulty signatures has some coefficients of the polynomials in vector y set to 0.

        Returns:
            A list of messages and a list of corresponding faulty signatures. ach of the faulty signatures has some
            coefficients of the polynomials in vector y set to 0.
        """
        return self.load_sigs(FAULTY_SIGS_FILE_PATH)

    def poly_inverse(self, p: list[int]) -> list[int]:
        """
        Computes the inverse of the provided polynomial in the polynomial ring of Dilithium.

        Args:
            p: A polynomial for which to compute its inverse.

        Returns:
            The inverse of the provided polynomial in the polynomial ring of Dilithium.
        """
        p = p.copy_to_ntt()
        p_inv = [0 for _ in range(256)]
        for i, coeff in enumerate(p.coeffs):
            p_inv[i] = pow(coeff, -1, DILITHIUM.q)
        p_inv = DILITHIUM.R(p_inv, True)
        return p_inv.from_ntt().from_montgomery()

    def recover_s1_from_single_faulty_signature(self, faulty_sig: bytes) -> None:
        """
        Recovers the secret vector of polynomials s1 from a single faulty signature that has all coefficients of all
        polynomials in y set to 0.

        Args:
            faulty_sig: A faulty signature. The faulty signature was generated with all coefficients of the polynomials
            in y set to 0.

        Returns:
            None.
        """
        c_tilde, z, _ = DILITHIUM._unpack_sig(faulty_sig)
        c = DILITHIUM._sample_in_ball(c_tilde)

        '''
        Notes:
            * A signature z = y + c * s_1
            * A single faulty signature has y = 0
            * Compute the inverse of a polynomial p using `p_inv = self.poly_inverse(p)`
            * Multiply a vector of polynomials `v` by a polynomial using `v.scale(p)`
        '''

        # Remove or comment
        raise Exception('Step 1-A: add your solution here')

        # Add your code here
        self.s1 = None

    @staticmethod
    def __recover_single_poly(faulty_sigs: list[bytes], poly_idx: int = 0) -> list[int]:
        """
        Recovers a single polynomial from the secret vector of polynomials s1 using a list of faulty signatures that
        have some coefficients of the polynomials in y set to 0.

        Args:
            faulty_sigs: A list of faulty signatures. Each faulty signature was generated with some coefficients of the
            polynomials in y set to 0.
            poly_idx: The index of the polynomial to be recovered.

        Returns:
            None.
        """

        # The paper suggests setting K to 2 * beta + gamma_1, but it can be gamma_1
        # K = 2 * DILITHIUM.beta + DILITHIUM.gamma_1
        K = DILITHIUM.gamma_1
        eta = DILITHIUM.eta

        model = LpProblem(name='dilithium-ilp', sense=LpMaximize)
        # Create variables for the secrets
        num_secrets = DILITHIUM.n
        s = [LpVariable(f's_{i}', -eta, eta, LpInteger) for i in range(num_secrets)]

        eq_idx = 0
        x = []
        for sig in tqdm(faulty_sigs, desc='Constructing ILP from faulty sigs'):
            # Recover the c from the signature
            c_tilde, z, h = DILITHIUM._unpack_sig(sig)
            c = DILITHIUM._sample_in_ball(c_tilde)
            c = np.asarray(c.coeffs)[::-1]

            z_target = z[poly_idx][0].coeffs
            for j, z_val in enumerate(z_target):
                if abs(z_val) > DILITHIUM.beta:
                    continue
                # Add constraint for each faulty candidate coefficient
                row = np.hstack([c[-(j + 1):], -c[: -(j + 1)]])
                # Sign of lhs is flipped for convenience, but should not affect results
                lhs = LpAffineExpression(zip(s, row), -z_val)
                var = LpVariable(f'x_{eq_idx}', cat=LpBinary)
                rhs = K * (1 - var)

                '''
                Notes:
                    * The ILP constraints
                        * Constraint 1: z_m - C_m * s <= K * (1 - x_m)
                        * Constraint 2: z_m - C_m * s >= -K * (1 - x_m)
                    * Terms
                      * `lhs` is z_m - C_m * s
                      * `rhs` is K * (1 - x_m)
                    * Specify constraints
                        * For `expression <= 0` use `LpConstraint(expression, LpConstraintLE)`
                        * For `expression >= 0` use `LpConstraint(expression, LpConstraintGE)`
                '''

                # Remove or comment
                raise Exception('Step 1-B: add your solution here')

                # Add your code here
                c1 = None
                c2 = None

                model.addConstraint(c1, f'eqn {eq_idx} constraint 1')
                model.addConstraint(c2, f'eqn {eq_idx} constraint 2')

                # Add the var for this equation to overall list
                x.append(var)
                eq_idx += 1

        # Objective - maximize number of satisfied equations
        model += lpSum(x)

        s_sol = None
        print('Solving ILP ...', end=None)
        model.solve()
        print('Done')
        if model.status == LpStatusOptimal:
            s_sol = [int(var.value()) for var in s]

        return s_sol

    def recover_s1_from_multiple_faulty_signatures(self, faulty_sigs: list[bytes]) -> None:
        """
        Recovers the secret vector of polynomials s1 from multiple faulty signatures that have some coefficients of the
        polynomials in y set to 0.

        Args:
            faulty_sigs: A list of faulty signatures. Each faulty signature was generated with some coefficients of the
            polynomials in y set to 0.

        Returns:
            None.
        """
        s1 = []
        for poly_idx in range(DILITHIUM.l):
            info(f'Recovering polynomial {poly_idx}')
            solution = self.__recover_single_poly(faulty_sigs, poly_idx)
            poly = [DILITHIUM.R(solution)]
            s1.append(poly)
        self.s1 = DILITHIUM.M(s1)

    def display_s1(self, start: int = 0, stop: int | None = None) -> None:
        """
        Displays (a part of) the hexadecimal representation of the bit-packed representation of the secret vector of
        polynomials s1.

        Args:
            start: The index from which to start displaying the hexadecimal representation of the bit-packed
            representation of the secret vector of polynomials s1.
            stop: The index at which to stop displaying the hexadecimal representation of the bit-packed representation
            of the secret vector of polynomials s1. If None, displays until the end of the representation.

        Returns:
            None.
        """
        if start == 0 and stop is None:
            print(f's1: {self.s1.bit_pack_s(DILITHIUM.eta).hex()[start:stop]}')
        else:
            print(f's1[{start}:{stop}]: {self.s1.bit_pack_s(DILITHIUM.eta).hex()[start:stop]}')

    def check_hash_of_recovered_s1(self, s1_hash_file_path: str = S1_HASH_FILE_PATH) -> bool:
        """
        Compares the hash of recovered secret vector s1 with the hash of actual secret vector s1.

        Args:
            s1_hash_file_path: The path to and the name of the JSON (JavaScript Object Notation) file where to save the
            hash of secret vector s1.

        Returns:
            A Boolean value indicating whether the secret vector s1 was successfully recovered.
        """

        expected_s1_hash = load_s1_hash(s1_hash_file_path)
        s1_bytes = self.s1.bit_pack_s(DILITHIUM.eta)
        actual_s1_hash = DILITHIUM._h(s1_bytes, S1_HASH_LENGTH)
        result = expected_s1_hash == actual_s1_hash

        cprint(f'Check hash of recovered s1: {result}', get_color(result))

        return result

    def __forge_signature_ches2018(self, msg: bytes) -> bytes:
        """
        Forges a signature using the recovered secret vector of polynomials s1 and the algorithm presented at CHES 2018.

        Args:
            msg: The message for which to forge a signature.

        Returns:
            None.
        """
        pk = self.pk
        s1 = self.s1
        m = msg

        # unpack the public key
        rho, t1 = DILITHIUM._unpack_pk(pk)

        # Generate matrix A ∈ R^(kxl)
        A = DILITHIUM._expandA(rho, is_ntt=True)

        # Compute hash of the public key
        tr = DILITHIUM._h(pk, 32)

        # Set seeds and nonce (kappa)
        mu = DILITHIUM._h(tr + m, 64)
        kappa = 0
        rho_prime = DILITHIUM._h(mu, 64)

        # Precompute NTT representation
        s1_hat = s1.copy_to_ntt()
        s1 = s1.copy_to_ntt()

        # Compute u
        u = (A @ s1_hat).from_ntt() - t1.scale(1 << DILITHIUM.d)

        alpha = DILITHIUM.gamma_2 << 1
        while True:
            y = DILITHIUM._expandMask(rho_prime, kappa)
            y_hat = y.copy_to_ntt()

            kappa += DILITHIUM.l

            w = (A @ y_hat).from_ntt()

            # Extract out both the high and low bits
            w1, w0 = w.decompose(alpha)

            # Create challenge polynomial
            w1_bytes = w1.bit_pack_w(DILITHIUM.gamma_2)
            c_tilde = DILITHIUM._h(mu + w1_bytes, 32)
            c = DILITHIUM._sample_in_ball(c_tilde)

            # Store c in NTT form
            c_hat = c.copy_to_ntt()

            z = y + s1.scale(c_hat).from_ntt()

            if z.check_norm_bound(DILITHIUM.gamma_1 - DILITHIUM.beta):
                continue

            '''
            Notes:
                * Hint h = MakeHint(w_0 - c * s_2 + c * t_0, w_1)
                * u = A * s_1 - t_1 * 2 ** d = t_0 - s_2
                * x = w_0 - c * s_2 + c * t_0 = w_0 + c * (t_0 - s_2) = w_0 + c * u
                * Multiply a vector of polynomials `v` by a polynomial using `v.scale(p)`
            '''

            # Remove or comment
            raise Exception('Step 2-A: add your solution here')

            # Add your code here to compute `x` as w_0 + c * u. Polynomial `c` and vector `u` are defined/computed
            # in the code above this line.
            x = w0

            x.reduce_coefficents()
            h = DILITHIUM._make_hint(x, w1, alpha)

            sig_bytes = DILITHIUM._pack_sig(c_tilde, z, h)

            if not DILITHIUM.verify(pk, m, sig_bytes):
                continue

            return sig_bytes

    def __forge_signature_asiaccs2019(self, msg: bytes) -> bytes:
        """
        Forges a signature using the recovered secret vector of polynomials s1 and the algorithm presented at AsiaCCS
        2019.

        Args:
            msg: The message for which to forge a signature.

        Returns:
            None.
        """
        pk = self.pk
        s1 = self.s1
        m = msg

        # unpack the public key
        rho, t1 = DILITHIUM._unpack_pk(pk)

        # Generate matrix A ∈ R^(kxl)
        A = DILITHIUM._expandA(rho, is_ntt=True)

        # Compute hash of the public key
        tr = DILITHIUM._h(pk, 32)

        # Set seeds and nonce (kappa)
        mu = DILITHIUM._h(tr + m, 64)
        kappa = 0
        rho_prime = DILITHIUM._h(mu, 64)

        # Precompute NTT representation
        s1_hat = s1.copy_to_ntt()

        t1_prime = t1.scale(1 << DILITHIUM.d)
        t1_prime = t1_prime.to_ntt()

        alpha = DILITHIUM.gamma_2 << 1
        while True:
            y = DILITHIUM._expandMask(rho_prime, kappa)
            y_hat = y.copy_to_ntt()

            kappa += DILITHIUM.l

            w = (A @ y_hat).from_ntt()

            # Extract out both the high and low bits
            w1, w0 = w.decompose(alpha)

            # Create challenge polynomial
            w1_bytes = w1.bit_pack_w(DILITHIUM.gamma_2)
            c_tilde = DILITHIUM._h(mu + w1_bytes, 32)
            c = DILITHIUM._sample_in_ball(c_tilde)

            # Store c in NTT form
            c.to_ntt()

            z = y + s1_hat.scale(c).from_ntt()

            if z.check_norm_bound(DILITHIUM.gamma_1 - DILITHIUM.beta):
                continue

            z = z.to_ntt()

            matrix = [[DILITHIUM.R([0 for _ in range(DILITHIUM.n)])] for _ in range(DILITHIUM.k)]
            h = DILITHIUM.M(matrix)

            '''
            Notes:
                * w_{1}^{'} = UseHint(h, w_{approx}^{'})
                * w_{approx}^{'} = A * z - c * t_1 * 2 ** d
                * Multiply a vector of polynomials `v` by a polynomial using `v.scale(p)`
            '''
            # Remove or comment
            raise Exception('Step 2-B: add your solution here')

            # Add your code here to compute `wa_prime` as A * z - c * t_1 * 2 ** d. Polynomial `c` and
            # vector `t1_prime` (equal to t_1 * 2 ** d) are defined/computed in the code above this line.
            wa_prime = (A @ z)

            wa_prime.from_ntt()
            w1_prime = DILITHIUM._use_hint(h, wa_prime, alpha)
            for i in range(0, DILITHIUM.k):
                for j in range(0, DILITHIUM.n):
                    if w1_prime[i][0].coeffs[j] != w1[i][0].coeffs[j]:
                        h[i][0].coeffs[j] = 1

            w1_prime = DILITHIUM._use_hint(h, wa_prime, alpha)
            if w1_prime != w1 or DILITHIUM._sum_hint(h) > DILITHIUM.omega:
                continue

            z = z.from_ntt().from_montgomery()

            return DILITHIUM._pack_sig(c_tilde, z, h)

    def forge_signature(self, msg: bytes, method: Algorithm = Algorithm.CHES2018) -> bytes:
        """
        Forges a signature using the recovered secret vector of polynomials s1 and the provided method.

        Args:
            msg: The message for which to forge a signature.
            method: The algorithm to use for signature forgery.

        Returns:
            None.
        """
        if method == self.Algorithm.CHES2018:
            return self.__forge_signature_ches2018(msg)
        elif method == self.Algorithm.AsiaCCS2019:
            return self.__forge_signature_asiaccs2019(msg)
        else:
            raise ValueError(f'Unsupported method for signature forgery: {method}!')


if __name__ == '__main__':
    attacker = Attacker()
    attacker.load_pk()

    msg, sig = attacker.load_sig()
    attacker.verify(msg, sig)

    msg = b'Message X'
    attacker.verify(msg, sig)

    # Step 1
    # Steps 1-A and 1-B achieve the same goal. You can solve any or both of them to continue to Step 2.

    # Step 1-A: begin
    msg, sig = attacker.load_faulty_sig_y_all_coefficients_zero()
    attacker.verify(msg, sig)

    attacker.recover_s1_from_single_faulty_signature(sig)
    attacker.check_hash_of_recovered_s1()
    # Step 1-A: end

    # Step 1-B: begin
    msgs, sigs = attacker.load_faulty_sigs_y_some_coefficients_zero()
    result = attacker.verify_sigs(msgs, sigs, display_result=False)
    print(f'Verify(msgs, sigs): {result}')

    attacker.recover_s1_from_multiple_faulty_signatures(sigs)
    attacker.check_hash_of_recovered_s1()
    # Step 1-B: end
    # Step 1: end

    # Step 2: begin
    # Steps 2-A and 2-B achieve the same goal. You can solve any or both of them to continue to Step 3.
    msg = b'This is fun'

    # Step 2-A: begin
    forged_sig = attacker.forge_signature(msg, method=Attacker.Algorithm.CHES2018)
    attacker.verify(msg, forged_sig)
    # Step 2-A: end

    # Step 2-B: begin
    forged_sig = attacker.forge_signature(msg, method=Attacker.Algorithm.AsiaCCS2019)
    attacker.verify(msg, forged_sig)
    # Step 2-B: end
    # Step 2: end
