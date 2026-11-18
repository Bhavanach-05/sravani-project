import pytest
import json
import time
from app import create_app
from database import init_db
from crypto.ring_lwe import rlwe_engine

@pytest.fixture
def client():
    test_db = "quantumshield_test.db"
    app = create_app({"TESTING": True, "DATABASE_PATH": test_db})
    with app.test_client() as client:
        yield client

def test_full_3factor_auth_flow(client):
    username = f"flow_user_{int(time.time()*1000)%100000}"
    password = "SuperPassword123!"

    # 1. Register User
    reg_res = client.post("/api/auth/register", json={
        "username": username,
        "password": password
    })
    assert reg_res.status_code == 201
    reg_data = reg_res.get_json()
    assert reg_data["success"] is True
    assert "card_uid" in reg_data
    assert "card_id" in reg_data
    assert "virtual_card" not in reg_data

    card_info = {
        "card_uid": reg_data["card_uid"],
        "card_secret": reg_data["enrollment"]["card_secret"],
        "ring_lwe_secret_s": reg_data["enrollment"]["ring_lwe_secret_s"]
    }

    # 2. Factor 1: Password
    p_res = client.post("/api/auth/step1-password", json={
        "username": username,
        "password": password
    })
    assert p_res.status_code == 200
    p_data = p_res.get_json()
    assert p_data["success"] is True
    stage1_token = p_data["stage1_token"]

    # 3. Factor 2: Smart Card (Wang-Wang Fuzzy Verifier)
    c_res = client.post("/api/auth/step2-smartcard", json={
        "stage1_token": stage1_token,
        "card_uid": card_info["card_uid"],
        "submitted_secret": card_info["card_secret"]
    })
    assert c_res.status_code == 200
    c_data = c_res.get_json()
    assert c_data["success"] is True
    stage2_token = c_data["stage2_token"]

    # 4. Factor 3: Ring-LWE Challenge
    chal_res = client.post("/api/auth/step3-challenge", json={
        "stage2_token": stage2_token
    })
    assert chal_res.status_code == 200
    chal_data = chal_res.get_json()
    assert chal_data["success"] is True
    challenge = chal_data["challenge"]

    # Client computes response
    resp = rlwe_engine.compute_response(card_info["ring_lwe_secret_s"], challenge)

    # 5. Factor 3: Ring-LWE Verify & Session Establishment
    v_res = client.post("/api/auth/step3-verify", json={
        "stage2_token": stage2_token,
        "nonce": challenge["nonce"],
        "response": resp
    })
    assert v_res.status_code == 200
    v_data = v_res.get_json()
    assert v_data["success"] is True
    assert "session" in v_data
    session_token = v_data["session"]["session_token"]

    # 6. Logout
    out_res = client.post("/api/auth/logout", json={"session_token": session_token})
    assert out_res.status_code == 200

def test_bypass_prevention(client):
    # Try Step 2 without Stage 1 token
    c_res = client.post("/api/auth/step2-smartcard", json={
        "stage1_token": "fake_token",
        "card_uid": "NFC-CARD-0001",
        "submitted_secret": "00"*16
    })
    assert c_res.status_code == 401

    # Try Step 3 without Stage 2 token
    chal_res = client.post("/api/auth/step3-challenge", json={
        "stage2_token": "fake_token"
    })
    assert chal_res.status_code == 401
