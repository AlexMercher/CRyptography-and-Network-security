import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.app import create_app

def main():
    demo_enabled = "--demo" in sys.argv or os.environ.get("CNS_DEMO_MODE", "false").lower() in ("true", "1", "yes")
    new_session_requested = "--new-demo-session" in sys.argv or "--new-session" in sys.argv
    
    if new_session_requested:
        from server.database.database import ensure_canonical_baseline
        sess = ensure_canonical_baseline(force_new_session=True, actor="cli")
        print(f"[+] Explicit presentation session requested: initialized {sess['session_id']}")

    app = create_app({"DEMO_MODE": demo_enabled})

    from server.database.database import get_active_presentation_session
    active_sess = get_active_presentation_session()
    sess_id = active_sess["session_id"] if active_sess else "None"
    sess_time = active_sess["created_at"] if active_sess else "None"

    cert_file = PROJECT_ROOT / "certs" / "server.crt"
    key_file = PROJECT_ROOT / "certs" / "server.key"
    
    print("\n" + "=" * 60)
    print("   SECURE SOFTWARE UPDATE SYSTEM — SERVER CONTROLLER")
    print("=" * 60)
    print("Default Admin Credentials:")
    print("  Username: admin")
    print("  Password: Admin@SecureUpdate2026!")
    print("-" * 60)
    print(f"Presentation Session: {sess_id}")
    print(f"Session Started:      {sess_time}")
    print("-" * 60)
    if demo_enabled:
        print("[+] Demonstration Mode: ENABLED (Authorized client reset enabled on loopback)")
    else:
        print("[-] Demonstration Mode: DISABLED (Fail-closed default; pass --demo to enable)")
    print("-" * 60)
    
    if cert_file.exists() and key_file.exists():
        print("[+] HTTPS Enabled (TLS 1.3)")
        print(f"    Admin Dashboard:  https://127.0.0.1:5000/admin")
        print(f"    Client Dashboard: https://127.0.0.1:5000/client")
        print(f"    CA Certificate:   {PROJECT_ROOT / 'certs' / 'ca.crt'}")
        print("=" * 60 + "\n")
        app.run(host="127.0.0.1", port=5000, ssl_context=(str(cert_file), str(key_file)), debug=False)
    else:
        print("[!] Warning: TLS certificates not found. Running on HTTP.")
        print(f"    Dashboard: http://127.0.0.1:5000/admin")
        print("=" * 60 + "\n")
        app.run(host="127.0.0.1", port=5000, debug=False)

if __name__ == "__main__":
    main()

