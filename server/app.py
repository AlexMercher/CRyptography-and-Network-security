import os
import sys
import secrets
from pathlib import Path
from flask import Flask, render_template, send_from_directory, redirect, url_for, session

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.database.database import init_db
from server.routes.auth import auth_bp
from server.routes.admin import admin_bp
from server.routes.updates import updates_bp
from server.routes.client_ui import client_ui_bp

def create_app(test_config=None):
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static"
    )
    app.config["SECRET_KEY"] = "super-secret-cns-update-security-key-2026"
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB max upload
    # DEMO_MODE defaults to False (Fail Closed) unless explicitly enabled via environment or configuration
    app.config["DEMO_MODE"] = os.environ.get("CNS_DEMO_MODE", "false").lower() in ("true", "1", "yes")
    app.config["ADMIN_RESET_TOKEN"] = os.environ.get("CNS_RESET_TOKEN", "cns-demo-reset-authorized-key-2026")
    
    if test_config:
        app.config.update(test_config)
        
    # Initialize SQLite database and ensure active presentation session exists
    init_db()
    from server.database.database import ensure_canonical_baseline
    ensure_canonical_baseline(force_new_session=False)

    @app.before_request
    def ensure_csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)

    @app.context_processor
    def inject_template_globals():
        return {
            "csrf_token": session.get("csrf_token", ""),
            "demo_mode": app.config.get("DEMO_MODE", False)
        }
    
    # Register API Blueprints
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")
    app.register_blueprint(updates_bp, url_prefix="/api/updates")
    app.register_blueprint(client_ui_bp, url_prefix="/api/client")
    
    # Frontend Routes
    @app.route("/")
    def index():
        return render_template("admin.html")

    @app.route("/admin")
    def admin_page():
        return render_template("admin.html")

    @app.route("/client")
    def client_page():
        return render_template("client.html")

    @app.route("/how-it-works")
    def how_it_works_page():
        return render_template("how_it_works.html")

    return app

if __name__ == "__main__":
    app = create_app()
    # Check if TLS certs exist for HTTPS
    cert_file = PROJECT_ROOT / "certs" / "server.crt"
    key_file = PROJECT_ROOT / "certs" / "server.key"
    
    if cert_file.exists() and key_file.exists():
        print(f"[+] Starting Secure Update Server with HTTPS on https://127.0.0.1:5000 ...")
        app.run(host="127.0.0.1", port=5000, ssl_context=(str(cert_file), str(key_file)), debug=False)
    else:
        print("[!] TLS certs not found, starting server on HTTP http://127.0.0.1:5000 ...")
        app.run(host="127.0.0.1", port=5000, debug=False)
