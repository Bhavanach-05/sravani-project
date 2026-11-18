import jwt
import hashlib
from datetime import datetime, timezone, timedelta
from config import Config
from database import get_db_connection
from security.audit_logger import log_audit_event

class SessionManager:
    """
    Quantum-Bound Multi-Stage Authentication & Session Manager.
    Enforces strict progressive stage gates:
    - Stage 1 Token: Password verified
    - Stage 2 Token: Smart Card (Wang-Wang) verified
    - Full Session Token: Post-Quantum Ring-LWE verified & bound to quantum session key
    """
    @staticmethod
    def create_stage1_token(user_id: int, username: str) -> str:
        """Create short-lived intermediate token after successful password check."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id),
            "username": username,
            "stage": 1,
            "iat": now,
            "exp": now + timedelta(seconds=Config.STAGE_TOKEN_TTL_SECONDS)
        }
        return jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")

    @staticmethod
    def verify_stage1_token(token: str) -> dict | None:
        """Verify Stage 1 token before allowing smart card verification."""
        try:
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
            if payload.get("stage") != 1:
                return None
            payload["sub"] = int(payload["sub"])
            return payload
        except Exception:
            return None

    @staticmethod
    def create_stage2_token(user_id: int, username: str, card_id: int) -> str:
        """Create intermediate token after successful Wang-Wang smart card check."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id),
            "username": username,
            "card_id": card_id,
            "stage": 2,
            "iat": now,
            "exp": now + timedelta(seconds=Config.STAGE_TOKEN_TTL_SECONDS)
        }
        return jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")

    @staticmethod
    def verify_stage2_token(token: str) -> dict | None:
        """Verify Stage 2 token before issuing Ring-LWE challenge."""
        try:
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
            if payload.get("stage") != 2:
                return None
            payload["sub"] = int(payload["sub"])
            return payload
        except Exception:
            return None

    @staticmethod
    def create_quantum_session(user_id: int, username: str, pq_session_key: str, ip_address: str = "127.0.0.1") -> dict:
        """
        Create fully authenticated quantum session bound to the Ring-LWE derived key.
        Saves record in SQLite sessions table and generates client JWT.
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=Config.SESSION_TTL_SECONDS)
        
        key_hash = hashlib.sha256(pq_session_key.encode("utf-8")).hexdigest()
        
        payload = {
            "sub": str(user_id),
            "username": username,
            "stage": 3,
            "pq_bound": True,
            "pq_key_fingerprint": key_hash[:16],
            "iat": now,
            "exp": expires_at
        }
        session_token = jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT INTO sessions (user_id, session_token, session_key_hash, created_at, expires_at, status)
        VALUES (?, ?, ?, ?, ?, 'active')
        """, (user_id, session_token, key_hash, now.isoformat(), expires_at.isoformat()))
        
        session_id = cursor.lastrowid
        
        log_audit_event(
            event_type="SESSION_CREATED",
            description=f"Quantum-resistant session established for user '{username}' (Session ID: {session_id})",
            outcome="SUCCESS",
            severity="INFO",
            user_id=user_id,
            ip_address=ip_address,
            metadata={"session_id": session_id, "key_fingerprint": key_hash[:16]},
            db_conn=conn
        )
        
        conn.commit()
        conn.close()
        
        return {
            "session_id": session_id,
            "session_token": session_token,
            "expires_at": expires_at.isoformat(),
            "pq_key_fingerprint": key_hash[:16],
            "derived_session_key": pq_session_key
        }

    @staticmethod
    def validate_session(session_token: str) -> dict | None:
        """
        Validate active session against both cryptographic JWT signature and DB status.
        Ensures revoked/expired sessions are immediately denied.
        """
        try:
            payload = jwt.decode(session_token, Config.JWT_SECRET, algorithms=["HS256"])
            if payload.get("stage") != 3:
                return None
                
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
            SELECT * FROM sessions WHERE session_token = ?
            """, (session_token,))
            row = cursor.fetchone()
            conn.close()
            
            if not row or row["status"] != "active":
                return None
                
            # Check DB expiration
            expires_at = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) > expires_at:
                return None
                
            return {
                "user_id": payload["sub"],
                "username": payload["username"],
                "session_id": row["session_id"],
                "key_fingerprint": payload.get("pq_key_fingerprint")
            }
        except Exception:
            return None

    @staticmethod
    def revoke_session(session_token: str, ip_address: str = "127.0.0.1") -> bool:
        """Revoke active session upon logout."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
        UPDATE sessions SET status = 'revoked' WHERE session_token = ?
        """, (session_token,))
        updated = cursor.rowcount > 0
        
        if updated:
            log_audit_event(
                event_type="SESSION_REVOKED",
                description="Session successfully revoked on user logout",
                outcome="SUCCESS",
                severity="INFO",
                ip_address=ip_address,
                db_conn=conn
            )
            
        conn.commit()
        conn.close()
        return updated
