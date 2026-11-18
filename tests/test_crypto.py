import pytest
import numpy as np
from crypto.password import hash_password, verify_password, validate_password_strength
from crypto.fuzzy_verifier import (
    generate_card_secret,
    generate_fuzzy_verifier,
    verify_fuzzy_credential,
    bitwise_hamming_distance
)
from crypto.ring_lwe import rlwe_engine

# ==========================================
# 1. Password Verification Tests (Factor 1)
# ==========================================
def test_password_hashing():
    pwd = "QuantumSecurePassword2026!"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False

def test_password_complexity():
    valid, _ = validate_password_strength("Short1!")
    assert valid is False  # < 8 chars

    valid, _ = validate_password_strength("alllowercase123!")
    assert valid is False  # no uppercase

    valid, _ = validate_password_strength("ALLUPPERCASE123!")
    assert valid is False  # no lowercase

    valid, _ = validate_password_strength("NoDigitsHere!")
    assert valid is False  # no digits

    valid, _ = validate_password_strength("StrongPassword123!")
    assert valid is True

# ==========================================
# 2. Wang-Wang Fuzzy Verifier Tests (Factor 2)
# ==========================================
def test_fuzzy_verifier_exact():
    secret = generate_card_secret()
    v = generate_fuzzy_verifier(secret)
    res = verify_fuzzy_credential(secret, v["helper_data"], v["verifier_hash"], v["salt"], tolerance=2)
    assert res["success"] is True
    assert res["error_distance"] == 0

def test_fuzzy_verifier_within_tolerance():
    secret = generate_card_secret()
    v = generate_fuzzy_verifier(secret)
    
    # 1 bit flip
    b1 = bytearray(bytes.fromhex(secret))
    b1[0] ^= 1
    res1 = verify_fuzzy_credential(b1.hex(), v["helper_data"], v["verifier_hash"], v["salt"], tolerance=2)
    assert res1["success"] is True
    assert res1["error_distance"] == 1

    # 2 bit flips
    b2 = bytearray(bytes.fromhex(secret))
    b2[0] ^= 1
    b2[1] ^= 2
    res2 = verify_fuzzy_credential(b2.hex(), v["helper_data"], v["verifier_hash"], v["salt"], tolerance=2)
    assert res2["success"] is True
    assert res2["error_distance"] == 2

def test_fuzzy_verifier_exceeds_tolerance():
    secret = generate_card_secret()
    v = generate_fuzzy_verifier(secret)
    
    # 3 bit flips (tolerance is 2)
    b3 = bytearray(bytes.fromhex(secret))
    b3[0] ^= 1
    b3[1] ^= 2
    b3[2] ^= 4
    res3 = verify_fuzzy_credential(b3.hex(), v["helper_data"], v["verifier_hash"], v["salt"], tolerance=2)
    assert res3["success"] is False
    assert res3["error_distance"] > 2

# ==========================================
# 3. Ring-LWE Lattice Cryptography Tests (Factor 3)
# ==========================================
def test_ring_lwe_keygen():
    pub, sec = rlwe_engine.generate_keypair()
    assert "a" in pub and "b" in pub
    assert len(pub["a"]) == rlwe_engine.n
    assert len(pub["b"]) == rlwe_engine.n
    assert len(sec) == rlwe_engine.n

def test_ring_lwe_challenge_response():
    pub, sec = rlwe_engine.generate_keypair()
    chal, r = rlwe_engine.create_challenge(pub)
    resp = rlwe_engine.compute_response(sec, chal)

    is_valid, max_err, key = rlwe_engine.verify_response(pub, chal, resp, r)
    assert is_valid is True
    assert max_err <= rlwe_engine.threshold
    assert len(key) == 64  # 256-bit hex session key

def test_ring_lwe_forged_response_rejected():
    pub, sec = rlwe_engine.generate_keypair()
    chal, r = rlwe_engine.create_challenge(pub)
    
    # Forged zero/random response
    forged_resp = {"v": [500] * 256, "client_nonce": "random_client_nonce"}
    is_valid, max_err, key = rlwe_engine.verify_response(pub, chal, forged_resp, r)
    assert is_valid is False
    assert max_err > rlwe_engine.threshold
    assert key == ""
