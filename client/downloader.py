import os
import requests
from pathlib import Path
from typing import Tuple, Optional

DEFAULT_CA_CERT = Path(__file__).resolve().parent / "trusted_certs" / "ca.crt"
DOWNLOADS_DIR = Path(__file__).resolve().parent / "storage" / "downloads"

class Downloader:
    def __init__(self, ca_cert_path: Path = None, base_url: str = "https://127.0.0.1:5000"):
        self.ca_cert_path = ca_cert_path or DEFAULT_CA_CERT
        self.base_url = base_url.rstrip("/")
        DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

    def download_package(
        self,
        package_filename: str,
        expected_size: Optional[int] = None,
        simulate_interruption: bool = False,
        custom_verify: Optional[str] = None
    ) -> Tuple[bool, Optional[Path], str]:
        """
        FR10 / SR03 / SR08: Downloads package over HTTPS with strict TLS verification.
        Handles network drop, interruption, and size validation.
        """
        download_url = f"{self.base_url}/api/updates/download/{package_filename}"
        dest_path = DOWNLOADS_DIR / package_filename
        part_path = DOWNLOADS_DIR / f"{package_filename}.part"

        verify_cert = custom_verify if custom_verify is not None else str(self.ca_cert_path)
        
        try:
            response = requests.get(download_url, stream=True, verify=verify_cert, timeout=10)
            if response.status_code != 200:
                return False, None, f"Server returned HTTP error {response.status_code} while downloading."

            downloaded_bytes = 0
            with open(part_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=1024):
                    if not chunk:
                        continue
                    f.write(chunk)
                    downloaded_bytes += len(chunk)
                    # TC12: Simulate interrupted download after writing initial chunk
                    if simulate_interruption and downloaded_bytes >= 256:
                        break

            if simulate_interruption:
                # Keep partial file for TC12 inspection
                return False, part_path, f"Download interrupted artificially after {downloaded_bytes} bytes."

            if expected_size is not None and downloaded_bytes != expected_size:
                part_path.unlink(missing_ok=True)
                return False, None, f"Incomplete package: expected {expected_size} bytes, received {downloaded_bytes} bytes."

            # Move .part to final destination
            if dest_path.exists():
                dest_path.unlink()
            part_path.rename(dest_path)
            return True, dest_path, f"Successfully downloaded {downloaded_bytes} bytes."

        except requests.exceptions.SSLError as ssl_err:
            part_path.unlink(missing_ok=True)
            return False, None, f"TLS Certificate verification failed: {ssl_err}"
        except requests.exceptions.RequestException as req_err:
            part_path.unlink(missing_ok=True)
            return False, None, f"Network communication error during download: {req_err}"

