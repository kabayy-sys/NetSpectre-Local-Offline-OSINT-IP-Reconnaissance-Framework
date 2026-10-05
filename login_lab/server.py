"""Server web latihan login (Basic Auth) untuk menguji tool brute-http.

Ini adalah target lab TULEN milikmu sendiri, berjalan hanya di localhost:
  1. Buat password rahasia:   python login_lab/make_password.py
  2. Jalankan server:         python login_lab/server.py           (port default 8099)
                               atau  python login_lab/server.py 9000
  3. Latih menemukannya:      python main.py -t http://127.0.0.1:8099 --brute-http
                                     --users login_lab/users.txt
                                     --passwords login_lab/passwords.txt --confirm-lab

Saat kredensial benar, server menampilkan flag.txt sebagai "hadiah".
"""

from __future__ import annotations

import base64
import hashlib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).parent
HASH_FILE = BASE_DIR / "password.hash"
FLAG_FILE = BASE_DIR / "flag.txt"
REQUIRED_USER = "admin"


def expected_hash() -> str:
    """Baca hash password terbaru dari file (kosong bila belum dibuat)."""
    try:
        return HASH_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def check_credentials(auth_header: str, digest: str) -> bool:
    """Kembalikan True bila Basic Auth sesuai (user & password benar)."""
    if digest and auth_header.startswith("Basic "):
        try:
            token = auth_header[6:].strip()
            decoded = base64.b64decode(token.encode()).decode()
        except Exception:
            return False
        user, _, pwd = decoded.partition(":")
        return user == REQUIRED_USER and hashlib.sha256(pwd.encode()).hexdigest() == digest
    return False


def flag_page() -> str:
    """Susun halaman HTML yang tampil setelah login berhasil."""
    flag = (
        FLAG_FILE.read_text(encoding="utf-8").strip()
        if FLAG_FILE.exists()
        else "SELAMAT!"
    )
    return f"""<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>NetSpectre Training Lab</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0;
           display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
    .card {{ background: #1e293b; padding: 32px 40px; border-radius: 12px;
            text-align: center; border: 1px solid #334155; }}
    h1 {{ color: #34d399; font-size: 26px; }}
    .flag {{ font-size: 18px; margin-top: 12px; color: #fbbf24; }}
    .hint {{ margin-top: 20px; font-size: 12px; color: #94a3b8; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Login Berhasil</h1>
    <p class="flag">{flag}</p>
    <p class="hint">Flag ini hanya tampil bila kredensial benar (Basic Auth).</p>
  </div>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    """Menangani request; melindungi halaman dengan Basic Auth."""

    def do_GET(self) -> None:
        if check_credentials(self.headers.get("Authorization", ""), expected_hash()):
            body = flag_page().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="NetSpectre Training Lab"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args) -> None:
        pass


def main(argv: "list[str] | None" = None) -> int:
    if argv and argv[0].isdigit():
        port = int(argv[0])
    else:
        port = 8099

    if not HASH_FILE.exists():
        print("[-] password.hash belum ada. Jalankan dulu: python login_lab/make_password.py")
        return 1

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[ + ] Lab latihan berjalan di http://127.0.0.1:{port}")
    print(f"[ i ] User login = '{REQUIRED_USER}'. Tekan Ctrl+C untuk berhenti.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[ i ] Server dihentikan.")
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))