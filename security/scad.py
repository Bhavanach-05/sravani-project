import time
from collections import defaultdict
from datetime import datetime
from database import get_db_connection
from security.audit_logger import log_audit_event
from config import Config

class SCADEngine:
    """
    Smart Card Attack Detection (SCAD) Engine.
    Analyzes smart card authentication traffic in real-time to detect:
    - Brute-force & dictionary attacks against cards/PINs
    - Rapid-fire automated burst submissions
    - Card cloning, skimming, and identity mismatches
    - Probing attacks against the fuzzy verifier threshold
    """
    def __init__(self):
        # Sliding-window attempt tracker: ip -> list of timestamps
        self.ip_attempts = defaultdict(list)
        # Card attempts: card_id -> count of recent consecutive failures
        self.card_failures = defaultdict(int)

    def record_attempt(self, ip_address: str) -> bool:
        """
        Track request frequency from IP.
        Returns True if rapid-fire burst threshold breached.
        """
        now = time.time()
        window = Config.SCAD_RAPID_FIRE_WINDOW
        threshold = Config.SCAD_RAPID_FIRE_THRESHOLD
        
        # Clean older entries
        self.ip_attempts[ip_address] = [
            t for t in self.ip_attempts[ip_address] if now - t <= window
        ]
        self.ip_attempts[ip_address].append(now)
        
        return len(self.ip_attempts[ip_address]) >= threshold

    def handle_card_failure(
        self,
        user_id: int,
        card_id: int,
        card_uid: str,
        ip_address: str,
        reason: str = "Invalid credentials"
    ) -> dict:
        """
        Handle a failed smart card authentication attempt:
        - Checks rapid-fire burst attack
        - Increments card consecutive failure count
        - Locks card if threshold reached
        - Logs SCAD event and audit alert
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check rapid-fire burst
        is_burst = self.record_attempt(ip_address)
        self.card_failures[card_id] += 1
        current_fails = self.card_failures[card_id]
        
        actions_taken = []
        severity = "LOW"
        locked = False
        
        if is_burst:
            severity = "HIGH"
            actions_taken.append("IP rapid-fire burst detected")
            cursor.execute("""
            INSERT INTO scad_events (user_id, card_id, event_description, severity, ip_address)
            VALUES (?, ?, ?, ?, ?)
            """, (user_id, card_id, f"Rapid-fire burst attack detected from {ip_address} on card {card_uid}", severity, ip_address))
            
        if current_fails >= Config.SCAD_MAX_FAILED_ATTEMPTS:
            severity = "HIGH"
            locked = True
            actions_taken.append(f"Card {card_uid} locked after {current_fails} consecutive failures")
            
            # Lock the smart card
            cursor.execute("UPDATE smart_cards SET status = 'locked' WHERE card_id = ?", (card_id,))
            
            # Log SCAD alert event
            cursor.execute("""
            INSERT INTO scad_events (user_id, card_id, event_description, severity, ip_address)
            VALUES (?, ?, ?, ?, ?)
            """, (user_id, card_id, f"Threshold breached: Card {card_uid} automatically locked due to repeated failures", severity, ip_address))
            
            log_audit_event(
                event_type="CARD_LOCKED",
                description=f"Smart Card {card_uid} locked by SCAD engine",
                outcome="BLOCKED",
                severity="HIGH",
                user_id=user_id,
                ip_address=ip_address,
                metadata={"card_id": card_id, "failed_count": current_fails, "reason": reason},
                db_conn=conn
            )
        else:
            log_audit_event(
                event_type="CARD_FAILURE",
                description=f"Smart card verification failed for card {card_uid}: {reason} ({current_fails}/{Config.SCAD_MAX_FAILED_ATTEMPTS})",
                outcome="FAILURE",
                severity=severity,
                user_id=user_id,
                ip_address=ip_address,
                metadata={"card_id": card_id, "consecutive_fails": current_fails},
                db_conn=conn
            )
            
        conn.commit()
        conn.close()
        
        return {
            "locked": locked,
            "consecutive_failures": current_fails,
            "max_allowed": Config.SCAD_MAX_FAILED_ATTEMPTS,
            "severity": severity,
            "actions_taken": actions_taken,
            "message": f"Authentication failed ({current_fails}/{Config.SCAD_MAX_FAILED_ATTEMPTS})" + (" - CARD LOCKED" if locked else "")
        }

    def handle_card_success(self, card_id: int):
        """Reset card failure counter upon successful verification."""
        self.card_failures[card_id] = 0

    def detect_card_user_mismatch(self, requested_user_id: int, actual_card_user_id: int, card_uid: str, ip_address: str):
        """Detect and log cross-user card skimming / cloning attempts."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT INTO scad_events (user_id, event_description, severity, ip_address)
        VALUES (?, ?, 'CRITICAL', ?)
        """, (requested_user_id, f"Security Alert: Card UID {card_uid} presented by user {requested_user_id} belongs to user {actual_card_user_id}", ip_address))
        
        log_audit_event(
            event_type="SCAD_ALERT",
            description=f"Card-User mismatch attack: User {requested_user_id} attempted using card {card_uid} registered to another user",
            outcome="BLOCKED",
            severity="CRITICAL",
            user_id=requested_user_id,
            ip_address=ip_address,
            db_conn=conn
        )
        conn.commit()
        conn.close()

    def unlock_card(self, card_id: int, admin_ip: str = "127.0.0.1") -> bool:
        """Admin unlock for locked smart card."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE smart_cards SET status = 'active' WHERE card_id = ?", (card_id,))
        success = cursor.rowcount > 0
        if success:
            self.card_failures[card_id] = 0
            log_audit_event(
                event_type="CARD_UNLOCKED",
                description=f"Smart Card {card_id} unlocked by administrator",
                outcome="SUCCESS",
                severity="INFO",
                ip_address=admin_ip,
                db_conn=conn
            )
        conn.commit()
        conn.close()
        return success

# Global singleton
scad_engine = SCADEngine()
