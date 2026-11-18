import os
import hmac
import hashlib
from itertools import combinations
from config import Config

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    """Bitwise XOR between two equal-length byte sequences."""
    return bytes(a ^ b for a, b in zip(b1, b2))

def bitwise_hamming_distance(b1: bytes, b2: bytes) -> int:
    """Calculate the Hamming distance (number of differing bits) between two byte strings."""
    return sum(bin(a ^ b).count("1") for a, b in zip(b1, b2))

def generate_card_secret(length: int = Config.FUZZY_SECRET_LEN) -> str:
    """Generate a random 128-bit card secret in hexadecimal."""
    return os.urandom(length).hex()

def generate_fuzzy_verifier(card_secret_hex: str) -> dict:
    """
    Wang-Wang Fuzzy Verifier Enrollment:
    Given smart card secret S (16 bytes = 128 bits):
    1. Sample random high-entropy codeword C <- {0, 1}^128.
    2. Compute helper data W = C XOR S.
    3. Generate random salt.
    4. Compute commitment V = HMAC-SHA256(salt, C).
    
    Returns verifier parameters to store on server. Neither S nor C is stored in plaintext.
    """
    try:
        s_bytes = bytes.fromhex(card_secret_hex)
    except ValueError:
        raise ValueError("Invalid hexadecimal secret")
        
    if len(s_bytes) != Config.FUZZY_SECRET_LEN:
        raise ValueError(f"Secret must be exactly {Config.FUZZY_SECRET_LEN} bytes")

    c_bytes = os.urandom(Config.FUZZY_SECRET_LEN)
    helper_bytes = xor_bytes(c_bytes, s_bytes)
    salt_bytes = os.urandom(16)
    
    verifier_hash = hmac.new(salt_bytes, c_bytes, hashlib.sha256).hexdigest()
    
    return {
        "helper_data": helper_bytes.hex(),
        "verifier_hash": verifier_hash,
        "salt": salt_bytes.hex()
    }

def verify_fuzzy_credential(
    submitted_secret_hex: str,
    helper_data_hex: str,
    verifier_hash_hex: str,
    salt_hex: str,
    tolerance: int = Config.FUZZY_TOLERANCE
) -> dict:
    """
    Wang-Wang Fuzzy Verifier Authentication:
    Given submitted credential S' (which may contain up to 'tolerance' bit noise):
    1. Candidate codeword C' = W XOR S'.
    2. Test if HMAC(salt, C') == V (0 bit noise).
    3. If not, test perturbations within Hamming ball of radius 'tolerance':
       - Test single bit flips (distance = 1, 128 tests)
       - Test two bit flips (distance = 2, 8,128 tests)
    4. If a candidate matches, return success and exact distance.
    5. If no candidate matches, reject (distance > tolerance).
    """
    try:
        s_prime = bytes.fromhex(submitted_secret_hex)
        helper = bytes.fromhex(helper_data_hex)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return {
            "success": False,
            "error_distance": -1,
            "tolerance": tolerance,
            "message": "Malformed hexadecimal inputs"
        }

    if len(s_prime) != len(helper):
        return {
            "success": False,
            "error_distance": -1,
            "tolerance": tolerance,
            "message": "Credential length mismatch"
        }

    c_prime = bytearray(xor_bytes(helper, s_prime))
    total_bits = len(c_prime) * 8

    # Distance 0 check
    h0 = hmac.new(salt, c_prime, hashlib.sha256).hexdigest()
    if hmac.compare_digest(h0, verifier_hash_hex):
        return {
            "success": True,
            "error_distance": 0,
            "tolerance": tolerance,
            "message": "Perfect match (0 noise)"
        }

    if tolerance >= 1:
        # Distance 1 check: flip 1 bit
        for i in range(total_bits):
            byte_idx = i // 8
            bit_idx = i % 8
            c_prime[byte_idx] ^= (1 << bit_idx)
            
            h1 = hmac.new(salt, c_prime, hashlib.sha256).hexdigest()
            if hmac.compare_digest(h1, verifier_hash_hex):
                return {
                    "success": True,
                    "error_distance": 1,
                    "tolerance": tolerance,
                    "message": "Reconstructed within tolerance (1 bit noise corrected)"
                }
            # Unflip
            c_prime[byte_idx] ^= (1 << bit_idx)

    if tolerance >= 2:
        # Distance 2 check: flip 2 bits
        for i, j in combinations(range(total_bits), 2):
            b_idx1, bit1 = divmod(i, 8)
            b_idx2, bit2 = divmod(j, 8)
            
            c_prime[b_idx1] ^= (1 << bit1)
            c_prime[b_idx2] ^= (1 << bit2)
            
            h2 = hmac.new(salt, c_prime, hashlib.sha256).hexdigest()
            if hmac.compare_digest(h2, verifier_hash_hex):
                return {
                    "success": True,
                    "error_distance": 2,
                    "tolerance": tolerance,
                    "message": "Reconstructed within tolerance (2 bit noise corrected)"
                }
            # Unflip
            c_prime[b_idx1] ^= (1 << bit1)
            c_prime[b_idx2] ^= (1 << bit2)

    return {
        "success": False,
        "error_distance": tolerance + 1,
        "tolerance": tolerance,
        "message": f"Verification failed: Reading error exceeds tolerance threshold (>{tolerance} bit flips)"
    }
