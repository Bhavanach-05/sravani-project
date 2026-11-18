import pytest
import time
from database import get_db_connection, init_db
from security.scad import scad_engine
from crypto.fuzzy_verifier import generate_card_secret, generate_fuzzy_verifier

@pytest.fixture
def setup_card():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    unique_user = f"scad_user_{int(time.time() * 1000) % 100000}"
    # Insert test user & card
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, 'hash123')", (unique_user,))
    user_id = cursor.lastrowid
    
    card_uid = f"NFC-SCAD-{user_id:04d}"
    secret = generate_card_secret()
    fuzzy = generate_fuzzy_verifier(secret)
    cursor.execute("""
    INSERT INTO smart_cards (user_id, card_uid, fuzzy_verifier_data, helper_data, status)
    VALUES (?, ?, ?, ?, 'active')
    """, (user_id, card_uid, str(fuzzy), fuzzy["helper_data"]))
    card_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    return {"user_id": user_id, "card_id": card_id, "card_uid": card_uid}

def test_scad_threshold_card_lock(setup_card):
    card_id = setup_card["card_id"]
    user_id = setup_card["user_id"]
    card_uid = setup_card["card_uid"]
    
    scad_engine.card_failures[card_id] = 0
    
    # Attempt 1
    r1 = scad_engine.handle_card_failure(user_id, card_id, card_uid, "10.0.0.1", "Noise test")
    assert r1["locked"] is False
    assert r1["consecutive_failures"] == 1
    
    # Attempt 2
    r2 = scad_engine.handle_card_failure(user_id, card_id, card_uid, "10.0.0.1", "Noise test")
    assert r2["locked"] is False
    assert r2["consecutive_failures"] == 2
    
    # Attempt 3 (Threshold reached -> Lock)
    r3 = scad_engine.handle_card_failure(user_id, card_id, card_uid, "10.0.0.1", "Noise test")
    assert r3["locked"] is True
    assert r3["consecutive_failures"] == 3

def test_scad_admin_unlock(setup_card):
    card_id = setup_card["card_id"]
    # Unlock card
    unlocked = scad_engine.unlock_card(card_id)
    assert unlocked is True
    assert scad_engine.card_failures[card_id] == 0

def test_scad_rapid_fire_detection():
    ip = "192.168.99.50"
    scad_engine.ip_attempts[ip] = []
    
    # 3 attempts -> not burst yet
    assert scad_engine.record_attempt(ip) is False
    assert scad_engine.record_attempt(ip) is False
    assert scad_engine.record_attempt(ip) is False
    
    # 4th attempt in rapid succession -> triggers burst!
    assert scad_engine.record_attempt(ip) is True
