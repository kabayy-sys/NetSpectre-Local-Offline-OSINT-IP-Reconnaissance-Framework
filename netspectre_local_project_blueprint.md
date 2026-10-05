# NetSpectre-Local: Offline OSINT & IP Reconnaissance Framework

## 1. Project Overview

**NetSpectre-Local** adalah kerangka kerja (*framework*) investigasi digital berbasis Python yang dirancang untuk melakukan pengumpulan informasi open-source (*OSINT*), pemetaan jaringan, dan enumerasi target secara lokal **tanpa bergantung pada API pihak ketiga** atau layanan berbayar eksternal. 

Proyek ini dibangun khusus untuk kebutuhan pembelajaran mendalam (*hands-on learning*) bagi calon penyelidik siber (*cyber crime investigator*), dengan fokus pada pemahaman protokol jaringan tingkat rendah seperti TCP/IP, Socket Programming, dan pengelolaan memori lokal.

---

## 2. Prinsip Etika & Koridor Hukum (*Rules of Engagement*)

Sebagai bagian dari persiapan berkarier di bidang penegak hukum (Kepolisian Siber/TIK), standar etika dan kepatuhan hukum adalah fondasi utama:
* **Zero External Dependencies / Self-Reliance:** Seluruh proses berjalan di atas pustaka standar (*built-in libraries*) Python dan utilitas sistem operasi asli.
* **Ephemeral & Clean Execution:** Mendukung mode eksekusi murni di dalam memori (*in-memory/RAM*) tanpa meninggalkan jejak file log di perangkat lokal jika diinginkan.
* **Authorized Scope Only:** Alat ini ditujukan untuk edukasi, pengujian di lab pribadi, atau target yang memiliki izin sah. Dilarang keras menggunakan teknik ini untuk aktivitas ilegal atau merusak infrastruktur pihak lain.

---

## 3. Struktur Direktori Proyek

Proyek ini dirancang secara modular agar mudah dikembangkan dan dipelihara:

```text
netspectre/
│
├── core/
│   ├── __init__.py
│   ├── resolver.py         # Modul resolusi DNS dan IP (Socket)
│   ├── whois_raw.py        # Modul query WHOIS langsung via TCP Port 43
│   ├── network.py          # Modul diagnostik jaringan (Ping & Traceroute via Subprocess)
│   └── subdomain_brute.py  # Modul enumerasi subdomain (Local Bruteforce/Fuzzing)
│
├── main.py                 # File eksekusi utama (CLI Controller & Argument Parser)
└── README.md               # Dokumentasi manual penggunaan
```

---

## 4. Spesifikasi & Implementasi Modul Inti

### A. Modul Resolusi Target (`core/resolver.py`)
Berfungsi untuk menerjemahkan input pengguna (baik domain maupun alamat IP) menjadi informasi host yang valid menggunakan pustaka bawaan `socket`.

```python
import socket

def resolve_target(target):
    """Menerjemahkan domain ke IP atau mendapatkan hostname dari IP."""
    try:
        if target.replace('.', '').isdigit():
            hostname = socket.gethostbyaddr(target)[0]
            ip = target
        else:
            ip = socket.gethostbyname(target)
            hostname = target
        return {"status": "success", "target": hostname, "ip": ip}
    except Exception as e:
        return {"status": "error", "message": str(e)}
```

### B. Modul WHOIS Raw Socket (`core/whois_raw.py`)
Melakukan komunikasi langsung dengan server registri pusat (ARIN, RIPE, IANA) melalui port 43 TCP tanpa menggunakan API pihak ketiga.

```python
import socket

def query_whois(ip_address, server="whois.iana.org"):
    """Mengambil data WHOIS langsung via port 43 TCP tanpa API."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, 43))
        s.send((ip_address + "\r\n").encode('utf-8'))
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        
        raw_text = response.decode('utf-8', errors='ignore')
        return raw_text
    except Exception as e:
        return f"[-] Gagal melakukan query WHOIS: {str(e)}"
```

### C. Modul Diagnostik Jaringan (`core/network.py`)
Memanfaatkan utilitas sistem operasi dasar untuk menguji latensi dan jalur rute jaringan (*routing path*) ke target.

```python
import subprocess
import platform

def run_diagnostics(target_ip):
    """Menjalankan Ping dan Traceroute menggunakan utilitas bawaan OS."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command_ping = ["ping", param, "2", target_ip]
    
    try:
        ping_result = subprocess.check_output(command_ping, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        ping_result = f"Ping gagal: {e.output}"
        
    tracert_cmd = ["tracert", "-h", "10", target_ip] if platform.system().lower() == "windows" else ["traceroute", "-m", "10", target_ip]
    
    try:
        tracert_result = subprocess.check_output(tracert_cmd, stderr=subprocess.STDOUT, text=True)
    except Exception:
        tracert_result = "Traceroute dibatasi atau tidak didukung di environment ini."
        
    return {"ping": ping_result, "traceroute": tracert_result}
```

### D. Modul Subdomain Enumeration / Bruteforce (`core/subdomain_brute.py`)
Melakukan pencarian aset digital tersembunyi (*subdomain*) menggunakan daftar kata bawaan berbasis penyelesaian socket lokal secara *realtime*.

```python
import socket

def bruteforce_subdomains(domain, wordlist=None):
    """Melakukan pencarian subdomain (recon) menggunakan wordlist lokal berbasis socket."""
    if wordlist is None:
        wordlist = ["www", "mail", "siakad", "elearning", "portal", "pmb", "student", "staff", "library", "jurnal", "api", "admin", "test", "dev", "vpn"]
    
    discovered = []
    for word in wordlist:
        subdomain = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            discovered.append({"subdomain": subdomain, "ip": ip})
        except socket.gaierror:
            pass
    return discovered
```

### E. Pengontrol Utama (`main.py`)
Mengatur interaksi Command Line Interface (CLI) dan menjalankan pemrosesan data secara *in-memory* tanpa meninggalkan file log di hard drive laptop.

```python
import argparse
from core.resolver import resolve_target
from core.whois_raw import query_whois
from core.network import run_diagnostics
from core.subdomain_brute import bruteforce_subdomains

def main():
    parser = argparse.ArgumentParser(description="NetSpectre-Local: Ephemeral Recon Tool")
    parser.add_argument("-t", "--target", required=True, help="Masukkan Domain Target")
    parser.add_argument("--brute", action="store_true", help="Aktifkan fitur subdomain enumeration")
    args = parser.parse_args()
    
    target = args.target
    print(f"\n[ + ] Memulai investigasi *in-memory* untuk target: {target}")
    print("=" * 50)
    
    res = resolve_target(target)
    if res["status"] == "error":
        print(f"[-] Kesalahan: {res['message']}")
        return
        
    ip = res["ip"]
    print(f"[ + ] Target Hostname : {res['target']}")
    print(f"[ + ] Resolved IP     : {ip}")
    print("-" * 50)
    
    whois_data = query_whois(ip)
    print("[ + ] Data WHOIS berhasil ditarik.")
    
    net_data = run_diagnostics(ip)
    
    if args.brute:
        clean_domain = target if not target.replace('.', '').isdigit() else "ubsi.ac.id"
        subs = bruteforce_subdomains(clean_domain)
        print(f"[ + ] Ditemukan {len(subs)} subdomain aktif.")
        
    print("\n" + "=" * 50)
    print("[ ✔ ] Investigasi Selesai (Data diproses murni di RAM).")
    print("[ ✔ ] Tidak ada file log yang disimpan ke disk.")
    print("=" * 50)

if __name__ == "__main__":
    main()
```

---

## 5. Panduan Penggunaan CLI

1. **Menjalankan Recon Standar (Resolusi, WHOIS, Ping):**
   ```bash
   python main.py -t targetdomain.ac.id
   ```

2. **Menjalankan Recon + Subdomain Bruteforce:**
   ```bash
   python main.py -t targetdomain.ac.id --brute
   ```

---

## 6. Rencana Pengembangan Lanjutan (Roadmap)
* Implementasi *Multi-threading* agar proses pengecekan subdomain berjalan jauh lebih cepat secara paralel.
* Penambahan modul enkripsi lokal untuk menyimpan laporan forensik terenkripsi jika penyimpanan lokal diperlukan di masa mendatang.