from functools import wraps
from flask import Blueprint, request, jsonify, session
from werkzeug.security import check_password_hash
from server.database.database import get_db_connection, log_security_event

auth_bp = Blueprint("auth", __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            log_security_event(
                "UNAUTHORIZED_ACCESS",
                f"Unauthorized attempt to access protected endpoint: {request.path}",
                result="BLOCKED",
                related_user="anonymous"
            )
            return jsonify({"error": "Authentication required", "status": 401}), 401
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, status FROM administrators WHERE username = ?", (username,))
    admin = cursor.fetchone()
    conn.close()
    
    if not admin or admin["status"] != "active" or not check_password_hash(admin["password_hash"], password):
        log_security_event(
            "LOGIN_FAILED",
            f"Failed login attempt for username: {username}",
            result="BLOCKED",
            related_user=username or "unknown"
        )
        return jsonify({"error": "Invalid username or password"}), 401
        
    session["user"] = admin["username"]
    log_security_event(
        "LOGIN_SUCCESS",
        f"Administrator '{admin['username']}' logged in successfully",
        result="ALLOWED",
        related_user=admin["username"]
    )
    return jsonify({"message": "Login successful", "user": admin["username"]}), 200

@auth_bp.route("/logout", methods=["POST"])
def logout():
    user = session.pop("user", None)
    if user:
        log_security_event(
            "LOGOUT",
            f"Administrator '{user}' logged out",
            result="ALLOWED",
            related_user=user
        )
    return jsonify({"message": "Logged out successfully"}), 200

@auth_bp.route("/me", methods=["GET"])
def me():
    if "user" in session:
        return jsonify({"authenticated": True, "user": session["user"]})
    return jsonify({"authenticated": False}), 200

