"""NetSpectre-Local: Framework OSINT & IP Reconnaissance lokal (offline).

Program ini memproses data sepenuhnya di dalam memori (in-memory) dan
tidak menyimpan file log ke disk. Ditujukan untuk edukasi dan pengujian
di lingkungan yang sah.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from urllib.parse import urlparse

from core.banner_grab import grab_banners
from core.brute_http import brute_basic_auth
from core.network import run_diagnostics
from core.port_scan import expand_ports, scan_ports
from core.report import Report
from core.resolver import is_valid_ip, resolve_target
from core.subdomain_brute import bruteforce_subdomains
from core.web_probe import find_web_resources, normalize_url
from core.whois_raw import DEFAULT_SERVER, extract_summary, query_whois

BANNER = r"""
 +------------------------------------------------------------------+
 |                                                                  |
 |    N E T S P E C T R E   -   L O C A L                           |
 |                                                                  |
 |    Offline OSINT & IP Reconnaissance Framework                   |
 |    in-memory  |  stdlib-only  |  authorized lab / CTF            |
 |                                                                  |
 +------------------------------------------------------------------+
"""


def parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    """Siapkan dan kembalikan argumen baris perintah (CLI)."""
    parser = argparse.ArgumentParser(
        prog="netspectre-local",
        description="Framework OSINT & IP Reconnaissance lokal (offline, in-memory).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Contoh penggunaan (recon):\n"
            "  python main.py -t example.com\n"
            "  python main.py -t example.com --brute --threads 50\n"
            "Contoh penggunaan (lab/CTF):\n"
            "  python main.py -t 192.168.1.5 --scan --ports 1-1024\n"
            "  python main.py -t 192.168.1.5 --banner --ports 22,80,443\n"
            "  python main.py -t http://192.168.1.5 --webscan --wordlist dir.txt\n"
            "  python main.py -t http://192.168.1.5/login --brute-http "
            "--users u.txt --passwords p.txt --confirm-lab"
        ),
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="Domain atau alamat IP target yang ingin diselidiki.",
    )
    parser.add_argument(
        "--brute", action="store_true",
        help="Aktifkan enumerasi subdomain (bruteforce).",
    )
    parser.add_argument(
        "--wordlist", default=None,
        help="Path file wordlist kustom (satu kata per baris).",
    )
    parser.add_argument(
        "--threads", type=int, default=20,
        help="Jumlah thread untuk bruteforce (default: 20).",
    )
    parser.add_argument(
        "--whois-server", default=DEFAULT_SERVER,
        help=f"Server WHOIS yang digunakan (default: {DEFAULT_SERVER}).",
    )
    parser.add_argument(
        "--skip-whois", action="store_true",
        help="Lewati langkah query WHOIS.",
    )
    parser.add_argument(
        "--skip-diagnostic", action="store_true",
        help="Lewati langkah ping & traceroute.",
    )
    parser.add_argument(
        "--full-whois", action="store_true",
        help="Tampilkan hasil WHOIS secara utuh (bukan ringkasan).",
    )

    # ---- Aksi lab / CTF (pengujian pada target yang sah) ----
    parser.add_argument(
        "--scan", action="store_true",
        help="Pindai port TCP pada target (gunakan --ports).",
    )
    parser.add_argument(
        "--banner", action="store_true",
        help="Baca banner layanan pada port terbuka (gunakan --ports).",
    )
    parser.add_argument(
        "--webscan", action="store_true",
        help="Enumerasi direktori web pada URL target (gunakan --wordlist).",
    )
    parser.add_argument(
        "--brute-http", action="store_true",
        help="Uji login HTTP (Basic Auth) pada URL target (butuh --confirm-lab).",
    )
    parser.add_argument(
        "--ports", default="1-1024",
        help="Daftar/rentang port, mis. '22,80,443' atau '1-1024' (default: 1-1024).",
    )
    parser.add_argument(
        "--users", default=None,
        help="File nama pengguna (satu per baris) untuk --brute-http.",
    )
    parser.add_argument(
        "--passwords", default=None,
        help="File kata sandi (satu per baris) untuk --brute-http.",
    )
    parser.add_argument(
        "--confirm-lab", action="store_true",
        help="Konfirmasi bahwa target berada di lab sendiri / sudah diizinkan.",
    )
    parser.add_argument(
        "--save-report", default=None,
        help="Path untuk menyimpan laporan JSON (opsional).",
    )
    parser.add_argument(
        "--report-password", default=None,
        help="Kata sandi untuk menyimpan laporan terenkripsi (opsional).",
    )
    return parser.parse_args(argv)
def load_wordlist(path: str) -> list[str]:
    """Baca wordlist dari file; abaikan baris kosong dan komentar (#)."""
    with open(path, "r", encoding="utf-8") as fh:
        words = [
            line.strip()
            for line in fh
            if line.strip() and not line.strip().startswith("#")
        ]
    # Hapus duplikat sambil mempertahankan urutan kemunculan.
    return list(dict.fromkeys(words))


def print_header(text: str) -> None:
    """Cetak baris pemisah dengan teks judul."""
    print("-" * 55)
    print(text)


def run_subdomain_scan(args: argparse.Namespace) -> None:
    """Muat wordlist dan jalankan enumerasi subdomain bila target berupa domain."""
    if is_valid_ip(args.target):
        print("[-] Enumerasi subdomain membutuhkan domain, bukan alamat IP.")
        return

    wordlist = None
    if args.wordlist:
        try:
            wordlist = load_wordlist(args.wordlist)
            print(f"[ + ] Memuat {len(wordlist)} kata dari '{args.wordlist}'.")
        except OSError as exc:
            print(f"[-] Gagal membaca wordlist: {exc}. Memakai wordlist bawaan.")

    print_header(f"Enumerasi Subdomain ({args.target})")
    print(f"[ i ] Menggunakan {args.threads} thread. Mengecek ...")

    def on_found(item: dict) -> None:
        print(f"[ + ] ditemukan: {item['subdomain']:<40} -> {item['ip']}")

    found = bruteforce_subdomains(
        args.target,
        wordlist=wordlist,
        threads=args.threads,
        on_found=on_found,
    )

    if not found:
        print("[ - ] Tidak ada subdomain aktif yang ditemukan.")
        return

    print()
    print(f"[ + ] Total {len(found)} subdomain aktif ditemukan:")
    for item in found:
        print(f"      - {item['subdomain']} -> {item['ip']}")


def parse_ports_spec(ports_spec: str) -> list[int] | None:
    """Ubah spec port menjadi daftar; None bila formatnya salah."""
    try:
        return expand_ports(ports_spec)
    except ValueError as exc:
        print(f"[-] Port tidak valid: {exc}")
        return None


def _host_from_target(target: str) -> str:
    """Ambil nama host dari target, termasuk saat target berupa URL."""
    if target.startswith(("http://", "https://")):
        return urlparse(target).hostname or target
    return target


def _is_lab_host(host: str) -> bool:
    """True bila host berada pada rentang lokal/loopback (milik sendiri)."""
    if is_valid_ip(host):
        address = ipaddress.ip_address(host)
        return address.is_loopback or address.is_private or address.is_link_local
    return False


def _print_authorization(action: str) -> None:
    """Cetak pengingat etika sebelum aksi pengujian dijalankan."""
    print("-" * 55)
    print(f"[ i ] Otorisasi '{action}': pastikan target milikmu (VM/lab) atau")
    print("      sudah mendapat izin tertulis. Gunakan hanya untuk belajar.")
    print("-" * 55)


def require_scope(args: argparse.Namespace, host: str, action: str) -> bool:
    """Periksa apakah target boleh dipindai; kembalikan True bila boleh.

    Target pada rentang lokal langsung diizinkan. Target publik hanya
    diizinkan dengan flag ``--confirm-lab``.
    """
    if _is_lab_host(_host_from_target(host)):
        return True
    if not args.confirm_lab:
        print("[-] Blokir: target bukan rentang lokal & tanpa --confirm-lab.")
        print("    Untuk target lab yang sah, tambahkan --confirm-lab.")
        return False
    _print_authorization(action)
    return True


def require_brute_confirm(args: argparse.Namespace, host: str) -> bool:
    """Bruteforce selalu butuh konfirmasi eksplisit, termasuk di lokal."""
    if not args.confirm_lab:
        print("[-] Aksi --brute-http butuh konfirmasi --confirm-lab.")
        return False
    _print_authorization("brute HTTP")
    return True


def run_scan(args: argparse.Namespace, report: Report) -> None:
    """Resolve host lalu pindai daftar port secara paralel."""
    host = args.target
    ports = parse_ports_spec(args.ports)
    if ports is None:
        return
    if not require_scope(args, host, "port scan"):
        return

    result = resolve_target(host)
    if result["status"] == "error":
        print(f"[-] {result['message']}")
        return
    ip = result["ip"]

    print_header(f"Port Scan pada {host} ({ip})")
    print(f"[ i ] Memindai {len(ports)} port dengan {args.threads} thread ...")
    open_ports = scan_ports(ip, ports, threads=args.threads)
    report.add("port_scan", {"host": host, "open_ports": open_ports})

    if not open_ports:
        print("[ - ] Tidak ada port terbuka yang ditemukan.")
        return
    print(f"[ + ] Ditemukan {len(open_ports)} port terbuka:")
    for port in open_ports:
        print(f"      - {port}/tcp  (terbuka)")


def run_banner(args: argparse.Namespace, report: Report) -> None:
    """Baca banner layanan pada port yang dipilih (maks. 100 port)."""
    host = args.target
    if not require_scope(args, host, "banner grab"):
        return
    ports = parse_ports_spec(args.ports)
    if ports is None:
        return
    ports = ports[:100]

    print_header(f"Banner Grab pada {host}")
    banners = grab_banners(host, ports)
    report.add("banner_grab", {str(p): b for p, b in banners.items()})

    if not banners:
        print("[ - ] Tidak ada banner yang terbaca.")
        return
    for port, banner in banners.items():
        one_line = " ".join(banner.splitlines())[:120]
        print(f"      - {port}: {one_line}")
def run_webscan(args: argparse.Namespace, report: Report) -> None:
    """Enumerasi direktori web pada URL target dari wordlist lokal."""
    host = _host_from_target(args.target)
    if not require_scope(args, host, "enumerasi web"):
        return

    wordlist = None
    if args.wordlist:
        try:
            wordlist = load_wordlist(args.wordlist)
            print(f"[ + ] Memuat {len(wordlist)} kata dari '{args.wordlist}'.")
        except OSError as exc:
            print(f"[-] Gagal membaca wordlist: {exc}. Memakai wordlist bawaan.")

    url = normalize_url(args.target)
    print_header(f"Enumerasi Web ({url})")
    found = find_web_resources(url, wordlist=wordlist, threads=args.threads)
    report.add("web_scan", found)

    if not found:
        print("[ - ] Tidak ada jalur web yang ditemukan.")
        return
    print(f"[ + ] Ditemukan {len(found)} jalur:")
    for item in found:
        print(f"      - {item['path']:<18} {item['status']}  {item['url']}")


def run_brute(args: argparse.Namespace, report: Report) -> None:
    """Uji login HTTP (Basic Auth) setelah konfirmasi otorisasi lab."""
    host = _host_from_target(args.target)
    if not require_brute_confirm(args, host):
        return
    if not (args.users and args.passwords):
        print("[-] --brute-http butuh opsi --users dan --passwords (file).")
        return
    try:
        usernames = load_wordlist(args.users)
        passwords = load_wordlist(args.passwords)
    except OSError as exc:
        print(f"[-] Gagal membaca wordlist: {exc}")
        return
    if not usernames or not passwords:
        print("[-] Wordlist kosong; bruteforce dibatalkan.")
        return

    url = args.target
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    total = len(usernames) * len(passwords)
    print_header(f"Uji Login HTTP (Basic Auth) pada {url}")
    print(f"[ i ] {total} kombinasi, {args.threads} thread ...")

    found = brute_basic_auth(url, usernames, passwords, threads=args.threads)
    report.add("brute_http", found)

    if not found:
        print("[ - ] Tidak ada kredensial valid yang ditemukan pada wordlist.")
        return
    print(f"[ ! ] Ditemukan {len(found)} kombinasi kredensial valid:")
    for item in found:
        print(f"      - {item['username']} : {item['password']}")


def run_ctf_actions(args: argparse.Namespace, report: Report) -> None:
    """Jalankan satu atau lebih aksi lab/CTF sesuai flag yang diberikan."""
    if args.scan:
        run_scan(args, report)
    if args.banner:
        run_banner(args, report)
    if args.webscan:
        run_webscan(args, report)
    if args.brute_http:
        run_brute(args, report)


def run_recon(args: argparse.Namespace, report: Report) -> None:
    """Alur recon default: resolusi, WHOIS, diagnostik, & subdomain bruto."""
    print(f"[ + ] Memulai investigasi in-memory untuk target: {args.target}")
    print("=" * 55)

    result = resolve_target(args.target)
    if result["status"] == "error":
        print(f"[-] {result['message']}")
        return

    hostname = result["target"]
    ip = result["ip"]
    report.add("resolved", {"hostname": hostname, "ip": ip})
    print(f"[ + ] Hostname target : {hostname}")
    print(f"[ + ] IP hasil resolve: {ip}")

    if not args.skip_whois:
        print_header("WHOIS (TCP port 43)")
        whois_text = query_whois(ip, server=args.whois_server)
        if args.full_whois:
            print(whois_text)
        else:
            summary = extract_summary(whois_text)
            print(summary if summary else whois_text)
        report.add("whois", whois_text)
    else:
        print("[ i ] Langkah WHOIS dilewati (--skip-whois).")

    if not args.skip_diagnostic:
        print_header("Diagnostik Jaringan (Ping & Traceroute)")
        diagnostics = run_diagnostics(ip)
        report.add("diagnostics", diagnostics)

        print("[ Ping ]")
        print(diagnostics["ping"])
        print()
        print("[ Traceroute ]")
        print(diagnostics["traceroute"])
    else:
        print("[ i ] Langkah diagnostik jaringan dilewati (--skip-diagnostic).")

    if args.brute:
        run_subdomain_scan(args)
def main(argv: "list[str] | None" = None) -> int:
    """Titik masuk utama: memilih alur recon atau aksi lab/CTF."""
    args = parse_args(argv)
    print(BANNER)

    report = Report(args.target)
    ctf_requested = any((args.scan, args.banner, args.webscan, args.brute_http))

    if ctf_requested:
        run_ctf_actions(args, report)
    else:
        run_recon(args, report)

    if args.save_report:
        print_header("Simpan Laporan")
        print(report.save(args.save_report, args.report_password))

    print()
    print("=" * 55)
    print("[ OK ] Sesi selesai (data default diproses murni di RAM).")
    if not args.save_report:
        print("[ OK ] Tidak ada file log yang disimpan ke disk.")
    print("=" * 55)
    return 0


if __name__ == "__main__":
    sys.exit(main())