import pytest
from crypto.fuzzy_verifier import generate_card_secret, generate_fuzzy_verifier, verify_fuzzy_credential

def test_ntag215_uid_format():
    """NTAG215 tags have 7-byte factory UIDs, typically prefixed with 04 (NXP manufacturer code)."""
    sample_ntag215_uid = "04:5A:21:B2:C1:80:4F"
    parts = sample_ntag215_uid.split(":")
    assert len(parts) == 7
    assert parts[0] == "04"
    assert all(len(p) == 2 for p in parts)

def test_ntag215_payload_fuzzy_verification():
    """Verify cryptographic payload read from physical NTAG215 NDEF record."""
    card_secret = generate_card_secret()
    fuzzy_data = generate_fuzzy_verifier(card_secret)
    
    # NTAG215 NDEF record format: "QS:<card_secret>"
    raw_ndef_text = f"QS:{card_secret}"
    assert raw_ndef_text.startswith("QS:")
    extracted_secret = raw_ndef_text[3:]
    
    # Verify extracted secret against Wang-Wang verifier
    res = verify_fuzzy_credential(
        submitted_secret_hex=extracted_secret,
        helper_data_hex=fuzzy_data["helper_data"],
        verifier_hash_hex=fuzzy_data["verifier_hash"],
        salt_hex=fuzzy_data["salt"],
        tolerance=2
    )
    assert res["success"] is True
    assert res["error_distance"] == 0

def test_ntag215_with_minor_reading_distortion():
    """Simulate transmission noise during physical NFC antenna coupling."""
    card_secret = generate_card_secret()
    fuzzy_data = generate_fuzzy_verifier(card_secret)
    
    # Introduce 1 bit flip (minor contact reading error)
    b = bytearray(bytes.fromhex(card_secret))
    b[0] ^= 1  # 1 bit error
    noisy_secret = b.hex()
    
    res = verify_fuzzy_credential(
        submitted_secret_hex=noisy_secret,
        helper_data_hex=fuzzy_data["helper_data"],
        verifier_hash_hex=fuzzy_data["verifier_hash"],
        salt_hex=fuzzy_data["salt"],
        tolerance=2
    )
    assert res["success"] is True
    assert res["error_distance"] == 1
