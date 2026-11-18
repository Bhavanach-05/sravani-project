import os
import json
import hashlib
import hmac
import numpy as np
from config import Config

class RingLWE:
    """
    Ring Learning With Errors (Ring-LWE) Post-Quantum Cryptographic Engine.
    Operates over polynomial ring R_q = Z_q[x] / (x^n + 1).
    
    Standard Kyber-aligned lattice parameters:
    - n = 256 (cyclotomic polynomial degree)
    - q = 3329 (modulus prime, q = 1 mod 2n)
    - eta = 2 (Centered Binomial Distribution width)
    """
    def __init__(self, n: int = Config.RLWE_N, q: int = Config.RLWE_Q, eta: int = Config.RLWE_ETA):
        self.n = n
        self.q = q
        self.eta = eta
        self.threshold = Config.RLWE_THRESHOLD

    def poly_mul_negacyclic(self, p1: np.ndarray, p2: np.ndarray) -> np.ndarray:
        """
        Negacyclic convolution mod (x^n + 1, q).
        Multiplies two polynomials in Z_q[x] and reduces modulo x^n + 1.
        """
        c = np.convolve(p1, p2)
        res = np.zeros(self.n, dtype=int)
        for i in range(len(c)):
            deg = i % self.n
            sign = -1 if (i // self.n) % 2 == 1 else 1
            res[deg] = (res[deg] + sign * int(c[i])) % self.q
        return res

    def sample_cbd(self) -> np.ndarray:
        """
        Sample polynomial from Centered Binomial Distribution (CBD_eta).
        Produces small discrete Gaussian-like coefficients centered at 0.
        """
        a = np.random.binomial(self.eta, 0.5, self.n)
        b = np.random.binomial(self.eta, 0.5, self.n)
        return (a - b) % self.q

    def sample_uniform(self) -> np.ndarray:
        """Sample uniform random polynomial coefficients in [0, q-1]."""
        return np.random.randint(0, self.q, self.n)

    def generate_keypair(self) -> tuple[dict, list]:
        """
        Generate user Ring-LWE keypair:
        - Public polynomial a in R_q (uniformly random)
        - Secret polynomial s in R_q (small CBD coefficients)
        - Error polynomial e in R_q (small CBD coefficients)
        - Public key b = a * s + e mod q
        
        Returns:
            public_params: {"a": list, "b": list}
            secret_key: list (private to user / card)
        """
        a = self.sample_uniform()
        s = self.sample_cbd()
        e = self.sample_cbd()
        b = (self.poly_mul_negacyclic(a, s) + e) % self.q
        
        public_params = {
            "a": a.tolist(),
            "b": b.tolist(),
            "n": self.n,
            "q": self.q
        }
        return public_params, s.tolist()

    def create_challenge(self, public_params: dict) -> tuple[dict, list]:
        """
        Server generates a randomized lattice challenge tied to user's public parameters:
        - Sample ephemeral secret r from CBD
        - Sample ephemeral error e1 from CBD
        - Challenge polynomial u = a * r + e1 mod q
        - Nonce and challenge timestamp
        
        Returns:
            challenge_payload: {"u": list, "nonce": str, "timestamp": float}
            server_ephemeral_r: list (retained by server for verification)
        """
        a = np.array(public_params["a"], dtype=int)
        r = self.sample_cbd()
        e1 = self.sample_cbd()
        u = (self.poly_mul_negacyclic(a, r) + e1) % self.q
        nonce = os.urandom(16).hex()
        
        challenge = {
            "u": u.tolist(),
            "nonce": nonce
        }
        return challenge, r.tolist()

    def compute_response(self, secret_s: list, challenge: dict) -> dict:
        """
        Client computes the response using its secret key share s:
        - Response polynomial v = u * s + e2 mod q (where e2 from CBD)
        - Client client_nonce for key freshness
        
        Returns:
            response_payload: {"v": list, "client_nonce": str}
        """
        u = np.array(challenge["u"], dtype=int)
        s = np.array(secret_s, dtype=int)
        e2 = self.sample_cbd()
        v = (self.poly_mul_negacyclic(u, s) + e2) % self.q
        client_nonce = os.urandom(16).hex()
        
        return {
            "v": v.tolist(),
            "client_nonce": client_nonce
        }

    def verify_response(
        self,
        public_params: dict,
        challenge: dict,
        response: dict,
        server_ephemeral_r: list
    ) -> tuple[bool, float, str]:
        """
        Server verifies client's Ring-LWE response:
        - Server computes expected lattice projection: v' = b * r mod q
        - Computes centered difference vector: diff = v - v' mod q
        - Infinity norm ||diff||_inf = max(|diff|)
        - If ||diff||_inf <= threshold (typically ~50 vs random ~1664), verification PASSES.
        - Derives quantum-resistant session key.
        
        Returns:
            (is_valid: bool, max_error_norm: float, derived_session_key: str)
        """
        try:
            b = np.array(public_params["b"], dtype=int)
            r = np.array(server_ephemeral_r, dtype=int)
            v = np.array(response["v"], dtype=int)
            
            # Server expectation: v' = b * r = (a*s + e)*r = a*s*r + e*r mod q
            v_prime = self.poly_mul_negacyclic(b, r) % self.q
            
            # Client response: v = u * s + e2 = (a*r + e1)*s + e2 = a*s*r + e1*s + e2 mod q
            # Residual difference: (e1*s + e2 - e*r) mod q
            diff = (v - v_prime) % self.q
            diff_centered = np.where(diff > self.q // 2, diff - self.q, diff)
            max_err = float(np.max(np.abs(diff_centered)))
            
            is_valid = max_err <= self.threshold
            
            if is_valid:
                # Derive Quantum-Resistant Session Key via HKDF-SHA256
                session_key = self.derive_session_key(
                    v.tolist(),
                    challenge.get("nonce", ""),
                    response.get("client_nonce", "")
                )
                return True, max_err, session_key
            else:
                return False, max_err, ""
        except Exception:
            return False, 9999.0, ""

    def derive_session_key(self, poly_v: list, nonce_server: str, nonce_client: str) -> str:
        """
        Derive a high-entropy 256-bit post-quantum session key from the verified
        lattice polynomial projection and session nonces.
        """
        # Compress polynomial coefficients into byte representation
        v_bytes = b"".join(int(coeff).to_bytes(2, byteorder="big") for coeff in poly_v)
        salt = (nonce_server + nonce_client).encode("utf-8")
        
        # HKDF Extract & Expand (using HMAC-SHA256)
        prk = hmac.new(salt, v_bytes, hashlib.sha256).digest()
        info = b"QuantumShield-RingLWE-Session-v1"
        session_key = hmac.new(prk, info + b"\x01", hashlib.sha256).hexdigest()
        return session_key

# Global singleton
rlwe_engine = RingLWE()
