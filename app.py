import os
import sys
import io
import socket
from flask import Flask, render_template, send_from_directory, jsonify, send_file, request
from flask_cors import CORS
import qrcode
from config import Config
from database import init_db
from routes.auth_routes import auth_bp
from routes.admin_routes import admin_bp
from routes.test_routes import test_bp
from generate_ssl import get_local_ip, generate_self_signed_cert

def create_app(test_config=None):
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    CORS(app)

    # Initialize SQLite database and seed initial honeypots
    with app.app_context():
        init_db(app.config.get("DATABASE_PATH"))

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(test_bp)

    # Page Routes
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/mobile")
    def mobile_page():
        return render_template("mobile.html")

    @app.route("/admin")
    def admin_page():
        return render_template("admin.html")

    @app.route("/test-suite")
    def test_suite_page():
        return render_template("test_suite.html")

    @app.route("/connect")
    def connect_page():
        local_ip = get_local_ip()
        proto = "https" if os.path.exists("cert.pem") else "http"
        port = int(os.environ.get("PORT", 5000))
        mobile_url = f"{proto}://{local_ip}:{port}/mobile"
        return render_template("qr_connect.html", mobile_url=mobile_url, local_ip=local_ip, port=port)

    @app.route("/api/qr-code")
    def qr_code():
        """Generates dynamic PNG QR code for mobile pairing."""
        local_ip = get_local_ip()
        proto = "https" if os.path.exists("cert.pem") else "http"
        port = int(os.environ.get("PORT", 5000))
        url = f"{proto}://{local_ip}:{port}/mobile"

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png")

    @app.route("/api/health")
    def health_check():
        return jsonify({"status": "ONLINE", "version": "QuantumShield-v2.0-NTAG215", "system": "OPERATIONAL"})

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    local_ip = get_local_ip()

    # Check for SSL certificates (required by mobile Chrome for Web NFC)
    cert_path = "cert.pem"
    key_path = "key.pem"
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        generate_self_signed_cert(cert_path, key_path)

    ssl_context = (cert_path, key_path) if os.path.exists(cert_path) and os.path.exists(key_path) else None
    proto = "https" if ssl_context else "http"

    print("=" * 65)
    print("  QUANTUMSHIELD: Post-Quantum 2FA with Real NTAG215 NFC        ")
    print(f"  Desktop Interface:   {proto}://127.0.0.1:{port}/              ")
    print(f"  Mobile 2FA (Phone):  {proto}://{local_ip}:{port}/mobile       ")
    print(f"  Mobile Pairing QR:   {proto}://127.0.0.1:{port}/connect       ")
    print(f"  SOC Admin Dashboard: {proto}://127.0.0.1:{port}/admin         ")
    print(f"  Security Test Suite: {proto}://127.0.0.1:{port}/test-suite    ")
    print("=" * 65)
    print(f"  Scan the QR code at {proto}://127.0.0.1:{port}/connect on your phone camera!")
    print("=" * 65)

    app.run(host="0.0.0.0", port=port, debug=False, ssl_context=ssl_context)
