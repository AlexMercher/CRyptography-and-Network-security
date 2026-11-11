import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common.crypto_engine import generate_ed25519_keypair

def generate_keys():
    keys_dir = PROJECT_ROOT / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    
    trusted_keys_dir = PROJECT_ROOT / "client" / "trusted_keys"
    trusted_keys_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Genuine Publisher Key Pair
    pub_priv_path = keys_dir / "publisher_private.pem"
    pub_pub_path = keys_dir / "publisher_public.pem"
    client_pub_path = trusted_keys_dir / "publisher_public.pem"
    
    priv_bytes, pub_bytes = generate_ed25519_keypair()
    pub_priv_path.write_bytes(priv_bytes)
    pub_pub_path.write_bytes(pub_bytes)
    client_pub_path.write_bytes(pub_bytes)
    
    # 2. Rogue / Attacker Key Pair (for unauthorized key test TC07)
    atk_priv_path = keys_dir / "attacker_private.pem"
    atk_pub_path = keys_dir / "attacker_public.pem"
    
    atk_priv_bytes, atk_pub_bytes = generate_ed25519_keypair()
    atk_priv_path.write_bytes(atk_priv_bytes)
    atk_pub_path.write_bytes(atk_pub_bytes)
    
    print("[+] Generated Publisher Ed25519 Keys:")
    print(f"    Private: {pub_priv_path}")
    print(f"    Public:  {pub_pub_path}")
    print(f"    Client Trusted Copy: {client_pub_path}")
    print("[+] Generated Attacker Ed25519 Keys:")
    print(f"    Private: {atk_priv_path}")
    print(f"    Public:  {atk_pub_path}")

if __name__ == "__main__":
    generate_keys()

