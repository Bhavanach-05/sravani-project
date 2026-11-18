from flask import Blueprint, request, jsonify
from database import get_db_connection
from security.audit_logger import get_recent_audit_logs, compute_threat_metrics, log_audit_event
from security.scad import scad_engine
from security.honey_tokens import HoneyTokenManager

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

@admin_bp.route("/metrics", methods=["GET"])
def metrics():
    """Retrieve high-level SOC security telemetry."""
    data = compute_threat_metrics()
    return jsonify({"success": True, "metrics": data}), 200

@admin_bp.route("/audit-logs", methods=["GET"])
def audit_logs():
    """Stream or filter audit logs."""
    limit = int(request.args.get("limit", 100))
    event_type = request.args.get("event_type", None)
    severity = request.args.get("severity", None)
    
    logs = get_recent_audit_logs(limit=limit, event_type=event_type, severity=severity)
    return jsonify({"success": True, "count": len(logs), "logs": logs}), 200

@admin_bp.route("/scad-events", methods=["GET"])
def scad_events():
    """Fetch SCAD security incidents."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT e.*, u.username, s.card_uid
    FROM scad_events e
    LEFT JOIN users u ON e.user_id = u.user_id
    LEFT JOIN smart_cards s ON e.card_id = s.card_id
    ORDER BY e.event_id DESC LIMIT 50
    """)
    events = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "count": len(events), "events": events}), 200

@admin_bp.route("/honey-tokens", methods=["GET"])
def honey_tokens():
    """Retrieve honey token tripwire decoys and hit counts."""
    tokens = HoneyTokenManager.get_all_honey_tokens()
    return jsonify({"success": True, "tokens": tokens}), 200

@admin_bp.route("/smart-cards", methods=["GET"])
def smart_cards():
    """Retrieve all issued smart cards and their lock status."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT s.card_id, s.user_id, s.card_uid, s.status, s.issued_at, u.username
    FROM smart_cards s
    JOIN users u ON s.user_id = u.user_id
    ORDER BY s.card_id DESC
    """)
    cards = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "cards": cards}), 200

@admin_bp.route("/unlock-card", methods=["POST"])
def unlock_card():
    """Admin unlock for a locked smart card."""
    data = request.get_json() or {}
    card_id = data.get("card_id")
    client_ip = request.remote_addr or "127.0.0.1"
    
    if not card_id:
        return jsonify({"success": False, "message": "card_id is required"}), 400
        
    unlocked = scad_engine.unlock_card(int(card_id), client_ip)
    if unlocked:
        return jsonify({"success": True, "message": f"Smart Card {card_id} successfully unlocked"}), 200
    else:
        return jsonify({"success": False, "message": "Card not found"}), 404

@admin_bp.route("/clear-logs", methods=["POST"])
def clear_logs():
    """Reset audit logs and SCAD events (used for fresh test runs)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM audit_logs")
    cursor.execute("DELETE FROM scad_events")
    cursor.execute("UPDATE honey_tokens SET triggered_count = 0, last_triggered_at = NULL")
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Telemetry logs cleared"}), 200
