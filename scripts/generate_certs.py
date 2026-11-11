import os
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def generate_ca(common_name: str, out_key: Path, out_cert: Path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Update Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    
    out_key.parent.mkdir(parents=True, exist_ok=True)
    out_key.write_bytes(ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    out_cert.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return ca_key, ca_cert

def generate_server_cert(server_cn: str, ca_key, ca_cert, out_key: Path, out_cert: Path):
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Update Server Instance"),
        x509.NameAttribute(NameOID.COMMON_NAME, server_cn),
    ])
    
    now = datetime.now(timezone.utc)
    san_list = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    
    out_key.parent.mkdir(parents=True, exist_ok=True)
    out_key.write_bytes(server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    out_cert.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

def generate_all_certs():
    certs_dir = PROJECT_ROOT / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)
    
    client_trusted_certs = PROJECT_ROOT / "client" / "trusted_certs"
    client_trusted_certs.mkdir(parents=True, exist_ok=True)
    
    # 1. Genuine CA and Server Cert
    ca_key_path = certs_dir / "ca.key"
    ca_cert_path = certs_dir / "ca.crt"
    server_key_path = certs_dir / "server.key"
    server_cert_path = certs_dir / "server.crt"
    
    ca_key, ca_cert = generate_ca("Secure Update Root CA", ca_key_path, ca_cert_path)
    generate_server_cert("localhost", ca_key, ca_cert, server_key_path, server_cert_path)
    
    # Copy trusted CA to client
    (client_trusted_certs / "ca.crt").write_bytes(ca_cert_path.read_bytes())
    
    # 2. Rogue CA and Rogue Server Cert (for TC18 invalid cert testing)
    rogue_ca_key_path = certs_dir / "rogue_ca.key"
    rogue_ca_cert_path = certs_dir / "rogue_ca.crt"
    rogue_server_key_path = certs_dir / "rogue_server.key"
    rogue_server_cert_path = certs_dir / "rogue_server.crt"
    
    rca_key, rca_cert = generate_ca("Untrusted Rogue Root CA", rogue_ca_key_path, rogue_ca_cert_path)
    generate_server_cert("localhost", rca_key, rca_cert, rogue_server_key_path, rogue_server_cert_path)
    
    print("[+] Generated Genuine CA & Server TLS Certificates:")
    print(f"    CA Cert:     {ca_cert_path}")
    print(f"    Server Cert: {server_cert_path}")
    print(f"    Client Copy: {client_trusted_certs / 'ca.crt'}")
    print("[+] Generated Rogue Untrusted CA & Server TLS Certificates (for TC18):")
    print(f"    Rogue Server Cert: {rogue_server_cert_path}")

if __name__ == "__main__":
    generate_all_certs()

