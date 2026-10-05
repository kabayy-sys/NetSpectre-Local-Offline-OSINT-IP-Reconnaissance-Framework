"""Enumerasi direktori dan file web (directory bruteforce) untuk target lab.

Membandingkan status HTTP setiap jalur dari wordlist untuk mengetahui
jalur apa saja yang benar-benar ada di server web target.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

DEFAULT_WORDLIST = [
    "robots.txt",
    "sitemap.xml",
    "index",
    "home",
    "admin",
    "login",
    "config",
    "config.php",
    "db",
    "backup",
    "uploads",
    "assets",
    "css",
    "js",
    "images",
    "phpinfo.php",
    "api",
]

DEFAULT_TIMEOUT = 5.0
USER_AGENT = "NetSpectre-Lab/1.0"
# Status yang dianggap menandakan jalur tersebut "ada".
_FOUND_CODES = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403}


def normalize_url(base_url: str) -> str:
    """Pastikan URL diawali skema dan diakhiri garis miring."""
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url
    return base_url.rstrip("/") + "/"


def probe_path(base_url: str, path: str, timeout: float = DEFAULT_TIMEOUT) -> dict | None:
    """Periksa status HTTP sebuah jalur; None bila koneksi gagal."""
    url = urljoin(base_url, path)
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = urlopen(req, timeout=timeout)
        status = resp.getcode()
        resp.close()
    except HTTPError as exc:
        status = exc.code
    except (URLError, OSError):
        return None
    return {"path": path, "status": status}


def find_web_resources(
    base_url: str,
    wordlist: list[str] | None = None,
    threads: int = 10,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[dict]:
    """Uji jalur dari wordlist secara paralel; kembalikan yang dianggap ada."""
    base_url = normalize_url(base_url)
    words = wordlist or DEFAULT_WORDLIST
    discovered: list[dict] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probe_path, base_url, word, timeout): word for word in words}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception:
                continue
            if result and result["status"] in _FOUND_CODES:
                result["url"] = urljoin(base_url, result["path"])
                discovered.append(result)

    discovered.sort(key=lambda item: item["path"])
    return discovered