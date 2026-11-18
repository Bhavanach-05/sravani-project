from datetime import datetime, timezone
from database import get_db_connection
from security.audit_logger import log_audit_event

class HoneyTokenManager:
    """
    Honey Token Tripwire System.
    Monitors all authentication gates for the presence of decoy credentials.
    Instantly traps unauthorized automated scrapers, brute-forcers, and replay attacks.
    """
    @staticmethod
    def check_and_trigger(token_value: str, token_type: str, ip_address: str = "127.0.0.1") -> bool:
        """
        Inspect submitted token value (username, card UID, etc.).
        If it matches a decoy honey token:
        - Increments hit counter & updates timestamp
        - Logs CRITICAL incident in scad_events and audit_logs
        - Returns True (indicating an intrusion trap was triggered)
        """
        if not token_value:
            return False
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT * FROM honey_tokens WHERE decoy_value = ? AND token_type = ?
        """, (token_value.strip(), token_type.upper()))
        
        row = cursor.fetchone()
        if row:
            token_id = row["token_id"]
            new_count = row["triggered_count"] + 1
            now = datetime.now(timezone.utc).isoformat()
            
            # Update honey token telemetry
            cursor.execute("""
            UPDATE honey_tokens 
            SET triggered_count = ?, last_triggered_at = ? 
            WHERE token_id = ?
            """, (new_count, now, token_id))
            
            # Record in SCAD events
            cursor.execute("""
            INSERT INTO scad_events (event_description, severity, ip_address, timestamp)
            VALUES (?, 'CRITICAL', ?, ?)
            """, (f"HONEY TOKEN TRIPPED: Attacker submitted decoy {token_type} '{token_value}'", ip_address, now))
            
            # Audit log
            log_audit_event(
                event_type="HONEY_TOKEN_TRIGGERED",
                description=f"High-priority honeypot intrusion detected! Attacker submitted decoy {token_type}: '{token_value}'",
                outcome="ALERT",
                severity="CRITICAL",
                ip_address=ip_address,
                metadata={"token_type": token_type, "decoy_value": token_value, "total_trips": new_count},
                db_conn=conn
            )
            
            conn.commit()
            conn.close()
            return True
            
        conn.close()
        return False

    @staticmethod
    def get_all_honey_tokens():
        """Retrieve all decoy honey tokens and their trigger counts for the SOC dashboard."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM honey_tokens ORDER BY token_id ASC")
        tokens = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return tokens
