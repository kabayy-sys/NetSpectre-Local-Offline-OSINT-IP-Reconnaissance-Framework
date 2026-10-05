"""Diagnostik jaringan (Ping & Traceroute) menggunakan utilitas sistem operasi.

Modul ini memanggil perintah bawaan OS (``ping``, ``tracert`` /
``traceroute``) melalui ``subprocess`` dan menangani perbedaan sintaks
antara Windows dan sistem berbasis Unix/Linux.
"""

from __future__ import annotations

import platform
import subprocess

# Batas waktu (detik) untuk setiap perintah agar program tidak menggantung.
_COMMAND_TIMEOUT = 20


def _is_windows() -> bool:
    """Kembalikan True jika program berjalan di sistem operasi Windows."""
    return platform.system().lower() == "windows"


def build_ping_command(target_ip: str) -> list[str]:
    """Susun perintah ping sesuai platform (4 kali percobaan)."""
    count_param = "-n" if _is_windows() else "-c"
    return ["ping", count_param, "4", target_ip]


def build_traceroute_command(target_ip: str) -> list[str]:
    """Susun perintah traceroute sesuai platform (maksimal 10 hop)."""
    max_hops = "10"
    if _is_windows():
        return ["tracert", "-h", max_hops, target_ip]
    return ["traceroute", "-m", max_hops, target_ip]


def _run_command(command: list[str], description: str) -> str:
    """Jalankan sebuah perintah dan kembalikan output sebagai teks."""
    try:
        output = subprocess.check_output(
            command,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=_COMMAND_TIMEOUT,
        )
        return output.strip()
    except subprocess.TimeoutExpired:
        return f"[-] {description} melebihi batas waktu ({_COMMAND_TIMEOUT} dtk)."
    except subprocess.CalledProcessError as exc:
        detail = exc.output.strip() if exc.output else "status tidak diketahui"
        return f"[-] {description} gagal: {detail}"
    except FileNotFoundError:
        return f"[-] Utilitas untuk {description} tidak ditemukan di sistem ini."
    except OSError as exc:
        return f"[-] Kesalahan saat menjalankan {description}: {exc}."


def run_diagnostics(target_ip: str) -> dict:
    """Jalankan ping dan traceroute ke alamat IP target.

    Kembalikan dict berisi kunci ``ping`` dan ``traceroute`` beserta
    hasil mentah (atau pesan kesalahan) masing-masing.
    """
    ping = _run_command(build_ping_command(target_ip), "Ping")
    traceroute = _run_command(build_traceroute_command(target_ip), "Traceroute")
    return {"ping": ping, "traceroute": traceroute}