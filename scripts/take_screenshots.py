import os
import sys
import time
import subprocess
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from server.app import create_app

def run_flask_server():
    app = create_app()
    cert_file = PROJECT_ROOT / "certs" / "server.crt"
    key_file = PROJECT_ROOT / "certs" / "server.key"
    ssl_context = (str(cert_file), str(key_file)) if cert_file.exists() and key_file.exists() else None
    app.run(host="127.0.0.1", port=5000, ssl_context=ssl_context, debug=False, use_reloader=False)

def main():
    # 1. Start server in daemon thread
    t = threading.Thread(target=run_flask_server, daemon=True)
    t.start()
    print("[*] Started server in background thread, waiting 3s...")
    time.sleep(3)

    chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    if not os.path.exists(chrome_path):
        print(f"[!] Chrome not found at {chrome_path}")
        return

    screenshots_dir = PROJECT_ROOT / "docs" / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    targets = [
        ("admin_dashboard.png", "https://127.0.0.1:5000/admin"),
        ("client_dashboard.png", "https://127.0.0.1:5000/client"),
        ("how_it_works.png", "https://127.0.0.1:5000/how-it-works"),
    ]

    for fname, url in targets:
        out_path = screenshots_dir / fname
        cmd = [
            chrome_path,
            "--headless=new",
            "--disable-gpu",
            "--ignore-certificate-errors",
            "--window-size=1600,1200",
            f"--screenshot={str(out_path)}",
            url
        ]
        print(f"[*] Capturing screenshot for {url} -> {out_path}...")
        try:
            # Let page execute JS for 3 seconds using virtual-time-budget
            cmd_with_wait = cmd[:-1] + ["--virtual-time-budget=4000", url]
            subprocess.run(cmd_with_wait, timeout=15, check=True)
            print(f"[+] Saved {fname} ({out_path.stat().st_size} bytes)")
        except Exception as e:
            print(f"[!] Headless capture failed with virtual time, trying standard: {e}")
            subprocess.run(cmd, timeout=15, check=True)
            print(f"[+] Saved {fname}")

    print("[+] All screenshots successfully captured!")

if __name__ == "__main__":
    main()

