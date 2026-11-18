import time
import json
from flask import Blueprint, request, jsonify
from database import get_db_connection
from crypto.password import hash_password, verify_password, validate_password_strength
from crypto.fuzzy_verifier import generate_card_secret, generate_fuzzy_verifier, verify_fuzzy_credential
from crypto.ring_lwe import rlwe_engine
from security.scad import scad_engine
from security.honey_tokens import HoneyTokenManager
from security.session_manager import SessionManager
from security.audit_logger import log_audit_event
from config import Config

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# In-memory challenge store: nonce -> {user_id, r, ts} (replay-resistant single-use)
active_challenges = {}

def clean_expired_challenges():
    now = time.time()
    expired = [k for k, v in active_challenges.items() if now - v["ts"] > 120]
    for k in expired:
        active_challenges.pop(k, None)

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user:
    1. Validate password strength and hash using bcrypt.
    2. Provision virtual smart card with Wang-Wang fuzzy verifier helper data & commitment.
    3. Generate user Ring-LWE public parameters and secret key.
    4. Save in SQLite and return client credential bundle for mobile wallet simulation.
    """
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    client_ip = request.remote_addr or "127.0.0.1"

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    # Honey token check on registration username
    if HoneyTokenManager.check_and_trigger(username, "USERNAME", client_ip):
        return jsonify({"success": False, "message": "Invalid username requested"}), 400

    valid_pwd, msg = validate_password_strength(password)
    if not valid_pwd:
        return jsonify({"success": False, "message": msg}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Username is already registered"}), 409

        # Factor 1: Hash password with bcrypt
        pwd_hash = hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pwd_hash))
        user_id = cursor.lastrowid

        # Factor 2: Prepare credentials for a physical smart card.
        card_uid = f"NFC-{username.upper()[:4]}-{user_id:04d}"
        card_secret = generate_card_secret()
        fuzzy_params = generate_fuzzy_verifier(card_secret)
        
        verifier_data_json = json.dumps({
            "verifier_hash": fuzzy_params["verifier_hash"],
            "salt": fuzzy_params["salt"]
        })
        
        cursor.execute("""
        INSERT INTO smart_cards (user_id, card_uid, fuzzy_verifier_data, helper_data, status)
        VALUES (?, ?, ?, ?, 'active')
        """, (user_id, card_uid, verifier_data_json, fuzzy_params["helper_data"]))
        card_id = cursor.lastrowid

        # Factor 3: Generate Post-Quantum Ring-LWE Keypair
        public_params, secret_s = rlwe_engine.generate_keypair()
        cursor.execute("""
        INSERT INTO ringlwe_keys (user_id, public_params)
        VALUES (?, ?)
        """, (user_id, json.dumps(public_params)))

        conn.commit()

        # Log Registration
        log_audit_event(
            event_type="REGISTRATION",
            description=f"User '{username}' registered with virtual smart card {card_uid} and Ring-LWE keypair",
            outcome="SUCCESS",
            severity="INFO",
            user_id=user_id,
            ip_address=client_ip,
            db_conn=conn
        )
        conn.close()

        return jsonify({
            "success": True,
            "message": "User registered successfully. Real NFC provisioning must be completed on a physical card.",
            "user_id": user_id,
            "username": username,
            "card_uid": card_uid,
            "card_id": card_id,
            "enrollment": {
                "card_secret": card_secret,
                "ring_lwe_secret_s": secret_s
            }
        }), 201

    except Exception as e:
        conn.close()
        return jsonify({"success": False, "message": f"Registration failed: {str(e)}"}), 500

@auth_bp.route("/step1-password", methods=["POST"])
def step1_password():
    """
    Factor 1: Password Verification
    - Validates username & bcrypt hash.
    - Checks honey tokens (triggers alert on decoy).
    - Checks user lock state.
    - On success, generates Stage 1 Token.
    """
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    client_ip = request.remote_addr or "127.0.0.1"

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400

    # Honey Token Check
    if HoneyTokenManager.check_and_trigger(username, "USERNAME", client_ip):
        return jsonify({"success": False, "message": "Invalid authentication credentials"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        log_audit_event(
            event_type="PWD_FAILURE",
            description=f"Password authentication failed: unknown username '{username}'",
            outcome="FAILURE",
            severity="LOW",
            ip_address=client_ip
        )
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    user_id = user["user_id"]

    # Check if user locked
    if user["is_locked"]:
        conn.close()
        log_audit_event(
            event_type="PWD_FAILURE",
            description=f"Locked user '{username}' attempted login",
            outcome="BLOCKED",
            severity="HIGH",
            user_id=user_id,
            ip_address=client_ip
        )
        return jsonify({"success": False, "message": "Account is locked. Contact administrator."}), 403

    # Check password
    if not verify_password(password, user["password_hash"]):
        cursor.execute("UPDATE users SET failed_login_count = failed_login_count + 1 WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        log_audit_event(
            event_type="PWD_FAILURE",
            description=f"Incorrect password submitted for user '{username}'",
            outcome="FAILURE",
            severity="LOW",
            user_id=user_id,
            ip_address=client_ip
        )
        return jsonify({"success": False, "message": "Invalid password"}), 401

    # Reset failure count on success
    cursor.execute("UPDATE users SET failed_login_count = 0 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

    stage1_token = SessionManager.create_stage1_token(user_id, username)
    log_audit_event(
        event_type="PWD_SUCCESS",
        description=f"Factor 1 (Password) verified successfully for '{username}'",
        outcome="SUCCESS",
        severity="INFO",
        user_id=user_id,
        ip_address=client_ip
    )

    return jsonify({
        "success": True,
        "message": "Factor 1 verified: Password valid",
        "stage1_token": stage1_token,
        "next_step": "step2_smartcard"
    }), 200

@auth_bp.route("/step2-smartcard", methods=["POST"])
def step2_smartcard():
    """
    Factor 2: Smart Card Authentication via Wang-Wang Fuzzy Verifier
    - Enforces Stage 1 Token requirement (prevents bypass).
    - Checks honey token card UIDs.
    - Evaluates credential against Wang-Wang fuzzy verifier.
    - Dispatches failures to SCAD engine for attack detection and automated card lock.
    - On success, generates Stage 2 Token.
    """
    data = request.get_json() or {}
    stage1_token = data.get("stage1_token", "")
    card_uid = data.get("card_uid", "").strip()
    submitted_secret = data.get("submitted_secret", "").strip()
    client_ip = request.remote_addr or "127.0.0.1"

    # 1. Stage Gate Check (Bypass Prevention)
    stage1_payload = SessionManager.verify_stage1_token(stage1_token)
    if not stage1_payload:
        log_audit_event(
            event_type="CARD_FAILURE",
            description="Stage bypass attempt: Smart card submitted without valid Stage 1 token",
            outcome="BLOCKED",
            severity="HIGH",
            ip_address=client_ip
        )
        return jsonify({"success": False, "message": "Unauthorized: Valid Stage 1 verification required"}), 401

    user_id = stage1_payload["sub"]
    username = stage1_payload["username"]

    # 2. Honey Token Check for Card UID
    if HoneyTokenManager.check_and_trigger(card_uid, "CARD_UID", client_ip):
        return jsonify({"success": False, "message": "Smart card authentication rejected"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    # Find the smart card
    cursor.execute("SELECT * FROM smart_cards WHERE card_uid = ?", (card_uid,))
    card = cursor.fetchone()

    # A physical NTAG215 reports its factory UID, which is unknown at registration.
    # Resolve the user's enrolled verifier so the NDEF secret remains the credential.
    if not card:
        cursor.execute(
            "SELECT * FROM smart_cards WHERE user_id = ? AND status = 'active' ORDER BY card_id DESC LIMIT 1",
            (user_id,)
        )
        card = cursor.fetchone()

    if not card:
        conn.close()
        log_audit_event(
            event_type="CARD_FAILURE",
            description=f"Smart card authentication failed: unknown card UID '{card_uid}'",
            outcome="FAILURE",
            severity="LOW",
            user_id=user_id,
            ip_address=client_ip
        )
        return jsonify({"success": False, "message": "Smart card not recognized"}), 404

    card_id = card["card_id"]
    card_user_id = card["user_id"]

    # 3. Mismatch Check (User A using User B's card)
    if card_user_id != user_id:
        conn.close()
        scad_engine.detect_card_user_mismatch(user_id, card_user_id, card_uid, client_ip)
        return jsonify({"success": False, "message": "Security Alert: Smart card ownership mismatch"}), 403

    # 4. Check Card Lock Status
    if card["status"] == "locked":
        conn.close()
        log_audit_event(
            event_type="CARD_FAILURE",
            description=f"Attempt to authenticate with locked smart card {card_uid}",
            outcome="BLOCKED",
            severity="HIGH",
            user_id=user_id,
            ip_address=client_ip
        )
        return jsonify({
            "success": False,
            "message": "Smart card is locked due to security policy. Please contact administrator.",
            "card_status": "locked"
        }), 423

    # 5. Execute Wang-Wang Fuzzy Verifier Algorithm
    verifier_data = json.loads(card["fuzzy_verifier_data"])
    helper_data = card["helper_data"]
    
    fuzzy_result = verify_fuzzy_credential(
        submitted_secret_hex=submitted_secret,
        helper_data_hex=helper_data,
        verifier_hash_hex=verifier_data["verifier_hash"],
        salt_hex=verifier_data["salt"],
        tolerance=Config.FUZZY_TOLERANCE
    )

    if not fuzzy_result["success"]:
        conn.close()
        scad_response = scad_engine.handle_card_failure(
            user_id=user_id,
            card_id=card_id,
            card_uid=card_uid,
            ip_address=client_ip,
            reason=fuzzy_result["message"]
        )
        return jsonify({
            "success": False,
            "message": fuzzy_result["message"],
            "scad_alert": scad_response
        }), 401

    # Fuzzy verifier succeeded (within tolerance)
    conn.close()
    scad_engine.handle_card_success(card_id)
    
    log_audit_event(
        event_type="CARD_SUCCESS",
        description=f"Factor 2 (Smart Card) fuzzy verified for '{username}' on card {card_uid} (Error noise: {fuzzy_result['error_distance']} bits)",
        outcome="SUCCESS",
        severity="INFO",
        user_id=user_id,
        ip_address=client_ip,
        metadata={"card_uid": card_uid, "error_distance": fuzzy_result["error_distance"]}
    )

    stage2_token = SessionManager.create_stage2_token(user_id, username, card_id)

    return jsonify({
        "success": True,
        "message": f"Factor 2 verified: Smart card accepted ({fuzzy_result['message']})",
        "error_distance": fuzzy_result["error_distance"],
        "tolerance": fuzzy_result["tolerance"],
        "stage2_token": stage2_token,
        "next_step": "step3_challenge"
    }), 200

@auth_bp.route("/step3-challenge", methods=["POST"])
def step3_challenge():
    """
    Factor 3: Post-Quantum Layer (Challenge Phase)
    - Enforces Stage 2 Token requirement.
    - Generates randomized Ring-LWE lattice challenge u = a*r + e1 mod q.
    - Caches ephemeral state r with nonce.
    """
    clean_expired_challenges()
    data = request.get_json() or {}
    stage2_token = data.get("stage2_token", "")
    client_ip = request.remote_addr or "127.0.0.1"

    # Stage Gate Check
    stage2_payload = SessionManager.verify_stage2_token(stage2_token)
    if not stage2_payload:
        log_audit_event(
            event_type="RLWE_FAILURE",
            description="Stage bypass attempt: Requesting Ring-LWE challenge without Stage 2 token",
            outcome="BLOCKED",
            severity="HIGH",
            ip_address=client_ip
        )
        return jsonify({"success": False, "message": "Unauthorized: Valid Stage 2 verification required"}), 401

    user_id = stage2_payload["sub"]
    username = stage2_payload["username"]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT public_params FROM ringlwe_keys WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "message": "Ring-LWE public parameters not found for user"}), 404

    public_params = json.loads(row["public_params"])
    challenge, ephemeral_r = rlwe_engine.create_challenge(public_params)

    # Cache challenge state with single-use nonce
    nonce = challenge["nonce"]
    active_challenges[nonce] = {
        "user_id": user_id,
        "r": ephemeral_r,
        "public_params": public_params,
        "ts": time.time()
    }

    log_audit_event(
        event_type="RLWE_CHALLENGE_ISSUED",
        description=f"Ring-LWE challenge polynomial issued for user '{username}' (Nonce: {nonce[:8]}...)",
        outcome="SUCCESS",
        severity="INFO",
        user_id=user_id,
        ip_address=client_ip
    )

    return jsonify({
        "success": True,
        "challenge": challenge,
        "public_params": {
            "n": public_params["n"],
            "q": public_params["q"]
        }
    }), 200

@auth_bp.route("/step3-verify", methods=["POST"])
def step3_verify():
    """
    Factor 3: Post-Quantum Layer (Response & Verification Phase)
    - Receives client response polynomial v and nonce.
    - Verifies bounded residual error norm in lattice space: ||v - b*r||_inf <= Threshold.
    - Derives quantum-resistant session key K_session.
    - Establishes active session and returns quantum session token.
    """
    data = request.get_json() or {}
    stage2_token = data.get("stage2_token", "")
    nonce = data.get("nonce", "")
    response = data.get("response", {})
    client_ip = request.remote_addr or "127.0.0.1"

    stage2_payload = SessionManager.verify_stage2_token(stage2_token)
    if not stage2_payload:
        return jsonify({"success": False, "message": "Unauthorized: Valid Stage 2 token required"}), 401

    user_id = stage2_payload["sub"]
    username = stage2_payload["username"]

    # Pop challenge from active store to prevent replay
    challenge_state = active_challenges.pop(nonce, None)
    if not challenge_state or challenge_state["user_id"] != user_id:
        log_audit_event(
            event_type="RLWE_FAILURE",
            description=f"Invalid or replayed Ring-LWE challenge nonce '{nonce}' for user '{username}'",
            outcome="FAILURE",
            severity="MEDIUM",
            user_id=user_id,
            ip_address=client_ip
        )
        return jsonify({"success": False, "message": "Challenge expired or invalid"}), 400

    public_params = challenge_state["public_params"]
    ephemeral_r = challenge_state["r"]

    # Verify Ring-LWE arithmetic
    is_valid, max_err, pq_session_key = rlwe_engine.verify_response(
        public_params=public_params,
        challenge={"nonce": nonce},
        response=response,
        server_ephemeral_r=ephemeral_r
    )

    if not is_valid:
        log_audit_event(
            event_type="RLWE_FAILURE",
            description=f"Ring-LWE challenge verification failed for '{username}' (Max error norm: {max_err:.1f} > threshold {Config.RLWE_THRESHOLD})",
            outcome="FAILURE",
            severity="HIGH",
            user_id=user_id,
            ip_address=client_ip,
            metadata={"max_err": max_err, "threshold": Config.RLWE_THRESHOLD}
        )
        return jsonify({
            "success": False,
            "message": f"Ring-LWE verification failed: Lattice projection error norm {max_err:.1f} exceeded threshold",
            "max_error_norm": max_err
        }), 401

    # Create Authenticated Post-Quantum Session
    session_info = SessionManager.create_quantum_session(user_id, username, pq_session_key, client_ip)

    log_audit_event(
        event_type="RLWE_SUCCESS",
        description=f"Ring-LWE challenge verified for '{username}' (Max error norm: {max_err:.1f}). Quantum session established.",
        outcome="SUCCESS",
        severity="INFO",
        user_id=user_id,
        ip_address=client_ip,
        metadata={"max_err": max_err, "session_id": session_info["session_id"]}
    )

    return jsonify({
        "success": True,
        "message": "All 3 Factors Verified: Quantum-resistant 2FA completed successfully!",
        "session": session_info,
        "max_error_norm": max_err,
        "lattice_status": "CONVERGED_QUANTUM_SECURE"
    }), 200

@auth_bp.route("/user-card-info", methods=["GET"])
def user_card_info():
    """
    Simulation helper endpoint: Retrieves the virtual smart card and Ring-LWE secret
    for a given username to populate the mobile app simulator wallet.
    """
    username = request.args.get("username", "").strip()
    if not username:
        return jsonify({"success": False, "message": "Username required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT u.user_id, u.username, s.card_id, s.card_uid, s.status, s.helper_data, s.fuzzy_verifier_data, r.public_params
    FROM users u
    JOIN smart_cards s ON u.user_id = s.user_id
    JOIN ringlwe_keys r ON u.user_id = r.user_id
    WHERE u.username = ?
    """, (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "message": "User credentials not found"}), 404

    return jsonify({
        "success": True,
        "card_info": {
            "user_id": row["user_id"],
            "username": row["username"],
            "card_id": row["card_id"],
            "card_uid": row["card_uid"],
            "card_status": row["status"]
        }
    }), 200

@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Revoke active session."""
    data = request.get_json() or {}
    session_token = data.get("session_token", "")
    client_ip = request.remote_addr or "127.0.0.1"

    if session_token:
        SessionManager.revoke_session(session_token, client_ip)

    return jsonify({"success": True, "message": "Logged out successfully"}), 200
