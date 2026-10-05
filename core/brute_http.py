"""Pengujian login HTTP (Basic Auth) untuk target lab yang sah.

Mencoba kombinasi nama pengguna dan kata sandi terhadap sebuah endpoint
yang menggunakan Basic Auth. Modul ini HANYA untuk laboratorium pribadi
atau target yang sudah diizinkan; penggunaan mengharuskan konfirmasi
scope (dipaksa dari `main.py`).
"""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT = 5.0
USER_AGENT = "NetSpectre-Lab/1.0"
# Respons yang menandakan autentikasi diterima (sukses / redirect login).
_SUCCESS_CODES = {200, 201, 204, 301, 302, 303, 307, 308}


def _auth_headers(username: str, password: str) -> dict:
    """Susun header Authorization Basic untuk sepasang kredensial."""
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}", "User-Agent": USER_AGENT}


def try_credentials(url: str, username: str, password: str, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Kembalikan True bila kombinasi kredensial diterima oleh server."""
    req = Request(url, headers=_auth_headers(username, password))
    try:
        resp = urlopen(req, timeout=timeout)
        code = resp.getcode()
        resp.close()
        return code in _SUCCESS_CODES
    except HTTPError as exc:
        return exc.code in _SUCCESS_CODES
    except (URLError, OSError):
        return False


def brute_basic_auth(
    url: str,
    usernames: list[str],
    passwords: list[str],
    threads: int = 5,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[dict]:
    """Uji semua kombinasi kredensial dan kembalikan pasangan yang berhasil."""
    found: list[dict] = []
    if not usernames or not passwords:
        return found

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures: dict = {}
        for user in usernames:
            for pwd in passwords:
                fut = executor.submit(try_credentials, url, user, pwd, timeout)
                futures[fut] = (user, pwd)

        for future in as_completed(futures):
            user, pwd = futures[future]
            try:
                accepted = future.result()
            except Exception:
                continue
            if accepted:
                found.append({"username": user, "password": pwd})

    return found