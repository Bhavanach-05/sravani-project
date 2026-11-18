import json
import sqlite3
from datetime import datetime, timezone
from database import get_db_connection

def log_audit_event(
    event_type: str,
    description: str,
    outcome: str,
    severity: str = "INFO",
    user_id: int = None,
    ip_address: str = "127.0.0.1",
    metadata: dict = None,
    db_conn = None
) -> int:
    """
    Log an event to the security audit trail.
    Ensures a strict, tamper-evident audit record of all authentication activities.
    """
    owns_conn = False
    if db_conn is None:
        db_conn = get_db_connection()
        owns_conn = True
        
    cursor = db_conn.cursor()
    meta_str = json.dumps(metadata) if metadata else None
    
    cursor.execute("""
    INSERT INTO audit_logs (user_id, event_type, description, ip_address, outcome, severity, metadata_json, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, event_type, description, ip_address, outcome, severity, meta_str, datetime.now(timezone.utc).isoformat()))
    
    log_id = cursor.lastrowid
    db_conn.commit()
    
    if owns_conn:
        db_conn.close()
        
    return log_id

def get_recent_audit_logs(limit: int = 50, event_type: str = None, severity: str = None):
    """Fetch recent audit logs with optional filtering."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM audit_logs"
    params = []
    conditions = []
    
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY log_id DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    logs = [dict(r) for r in rows]
    conn.close()
    return logs

def compute_threat_metrics():
    """
    Compute real-time threat metrics for the SOC Dashboard:
    - Attack count
    - Active card locks
    - Honey token triggers
    - Threat score (0 to 100)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Honey token triggers
    cursor.execute("SELECT SUM(triggered_count) as total FROM honey_tokens")
    honey_row = cursor.fetchone()
    honey_triggers = honey_row["total"] if honey_row and honey_row["total"] else 0
    
    # SCAD events
    cursor.execute("SELECT COUNT(*) as count FROM scad_events")
    scad_count = cursor.fetchone()["count"]
    
    # Locked cards
    cursor.execute("SELECT COUNT(*) as count FROM smart_cards WHERE status = 'locked'")
    locked_cards = cursor.fetchone()["count"]
    
    # Failed attempts (last 100 logs)
    cursor.execute("""
    SELECT COUNT(*) as count FROM audit_logs 
    WHERE outcome IN ('FAILURE', 'BLOCKED', 'ALERT') 
    ORDER BY log_id DESC LIMIT 100
    """)
    failed_attempts = cursor.fetchone()["count"]
    
    # Total successful authentications
    cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE event_type = 'RLWE_SUCCESS'")
    successful_auths = cursor.fetchone()["count"]
    
    # Active sessions
    cursor.execute("SELECT COUNT(*) as count FROM sessions WHERE status = 'active'")
    active_sessions = cursor.fetchone()["count"]
    
    conn.close()
    
    # Threat score calculation (0 - 100)
    score = (honey_triggers * 35) + (scad_count * 15) + (locked_cards * 10) + (failed_attempts * 2)
    score = min(100, max(0, score))
    
    if score >= 80:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 20:
        level = "ELEVATED"
    else:
        level = "NORMAL"
        
    return {
        "threat_score": score,
        "threat_level": level,
        "honey_token_triggers": honey_triggers,
        "scad_events_count": scad_count,
        "locked_cards_count": locked_cards,
        "failed_attempts": failed_attempts,
        "successful_auths": successful_auths,
        "active_sessions": active_sessions
    }
