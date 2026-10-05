# NetSpectre-Local

**NetSpectre-Local** adalah alat baris perintah (CLI) untuk investigasi
informasi open-source (OSINT) dan penelusuran alamat IP. Alat ini berjalan
sepenuhnya **lokal dan offline**, hanya memakai pustaka bawaan Python.
Tidak ada API pihak ketiga, tidak ada layanan berbayar, dan tidak ada file
log yang disimpan ke komputer Anda (semua diproses sementara di dalam RAM).

> ⚠️ Alat ini dibuat untuk **edukasi, pembelajaran, dan pengujian di lab
> pribadi** atau target yang memiliki izin sah. Dilarang menggunakannya
> untuk hal ilegal atau merusak sistem pihak lain.

## Fitur Utama

- Menerjemahkan domain menjadi alamat IP (dan sebaliknya).
- Menarik data WHOIS langsung melalui port 43 TCP (milik siapa, di negara mana).
- Memeriksa kondisi jaringan dengan ping dan traceroute.
- Mencari subdomain tersembunyi secara cepat dengan multi-threading.
- Untuk lab pribadi: pemindaian port, pembacaan banner layanan, enumerasi
  direktori web, dan uji login HTTP — semuanya dengan gerbang otorisasi.

## Cara Memulai

Pastikan Anda sudah menginstal Python 3.10 ke atas. Buka terminal (Command
Prompt atau PowerShell), lalu pindah ke folder proyek dan jalankan:

```bash
python main.py -h
```

Perintah di atas menampilkan daftar semua opsi yang tersedia.

## Cara Menggunakan

### Investigasi Dasar

Jalankan resolusi domain, cek WHOIS, dan diagnostik jaringan dengan:

```bash
python main.py -t contoh.com
```

Ganti `contoh.com` dengan domain yang ingin diperiksa. Anda juga bisa
memasukkan alamat IP langsung, misalnya `-t 8.8.8.8`.

### Menambahkan Pencarian Subdomain

Tambahkan kata `--brute` untuk mencari subdomain aktif (seperti `mail.`,
`api.`, `admin.`):

```bash
python main.py -t contoh.com --brute
```

Agar lebih cepat, perbesar jumlah thread:

```bash
python main.py -t contoh.com --brute --threads 50
```

Jika Anda punya daftar kata sendiri dalam file teks (satu kata per baris),
pakai `--wordlist`:

```bash
python main.py -t contoh.com --brute --wordlist nama.txt
```

### Opsi Tambahan yang Berguna

| Opsi | Fungsinya |
|------|-----------|
| `--skip-whois` | Lewati pemeriksaan WHOIS (lebih cepat). |
| `--skip-diagnostic` | Lewati ping dan traceroute. |
| `--full-whois` | Tampilkan seluruh isi hasil WHOIS, bukan ringkasan. |
| `--whois-server whois.arin.net` | Ganti server WHOIS (misal: ARIN, RIPE, APNIC). |
| `-h` / `--help` | Tampilkan bantuan semua opsi. |

## Contoh Hasil

```text
[ + ] Memulai investigasi in-memory untuk target: contoh.com
=======================================================
[ + ] Hostname target : contoh.com
[ + ] IP hasil resolve: 93.184.216.34
-------------------------------------------------------
WHOIS (TCP port 43)
inetnum:     93.184.216.0 - 93.184.216.255
netname:     EDGECAST-NETBLOCK
country:     US
-------------------------------------------------------
Diagnostik Jaringan (Ping & Traceroute)
[ Ping ]
Pinging 93.184.216.34 ... Reply from ...
[ Traceroute ]
...
=======================================================
[ OK ] Investigasi selesai (data diproses murni di RAM).
[ OK ] Tidak ada file log yang disimpan ke disk.
=======================================================
```

## Struktur Proyek

- `main.py` — pintu masuk program dan pengatur perintah CLI.
- `core/resolver.py` — menerjemahkan domain menjadi IP (dan sebaliknya).
- `core/whois_raw.py` — mengambil data WHOIS melalui TCP port 43.
- `core/network.py` — menjalankan ping dan traceroute.
- `core/subdomain_brute.py` — mencari subdomain secara paralel.
- `core/port_scan.py` — memindai port TCP yang terbuka.
- `core/banner_grab.py` — membaca banner layanan (fingerprinting).
- `core/web_probe.py` — enumerasi direktori dan file web.
- `core/brute_http.py` — uji login HTTP (Basic Auth) untuk target lab.
- `core/report.py` — laporan in-memory, bisa disimpan JSON/terenkripsi.

## Pengujian Lab Pribadi (CTF)

Fitur-fitur berikut untuk menguji mesin di dalam lab pribadimu (misalnya VM).
Aksi apa pun **otomatis diblokir** untuk alamat IP publik, kecuali kamu
menambahkan `--confirm-lab` sebagai penegasan bahwa target itu sah.

**Memindai port terbuka**

```bash
python main.py -t 192.168.1.50 --scan --ports 22,80,443,8000-9000
```

Tanpa `--ports`, dipindai port `1-1024`.

**Melihat banner layanan (nama & versi server)**

```bash
python main.py -t 192.168.1.50 --banner --ports 22,80,443
```

**Menemukan halaman dan direktori web**

```bash
python main.py -t http://192.168.1.50 --webscan --wordlist direktori.txt
```

**Menguji login halaman (Basic Auth)**

```bash
python main.py -t http://192.168.1.50/admin --brute-http --users nama.txt --passwords kata.txt --confirm-lab
```

**Menyimpan laporan**

```bash
python main.py -t 192.168.1.50 --scan --save-report hasil.json
python main.py -t 192.168.1.50 --scan --save-report hasil.bin --report-password rahasia
```

Enkripsi laporan memakai pustaka `cryptography`; bila belum terpasang,
laporan otomatis disimpan sebagai JSON polos dengan peringatan. Opsi
`--save-report` bisa digabung dengan aksi mana pun. File `--wordlist`,
`--users`, dan `--passwords` adalah file teks satu kata per baris.

## Latihan dengan Login yang Kamu Sendiri Tidak Tahu Passwordnya

Folder `login_lab/` berisi web login sederhana (Basic Auth di `localhost`)
untuk melatih `--brute-http`. Password sengaja disembunyikan (hanya hash
SHA-256 yang disimpan), jadi kamu pun tidak tahu kata sandinya.

```bash
# 1. Buat password rahasia (kata asli dibuang, hash disimpan)
python login_lab/make_password.py

# 2. Jalankan server lab (port default 8099, atau ganti angka)
python login_lab/server.py

# 3. Buka terminal lain, latih menemukan password-nya
python main.py -t http://127.0.0.1:8099 --brute-http \
  --users login_lab/users.txt --passwords login_lab/passwords.txt --confirm-lab
```

Baru buka browser ke `http://127.0.0.1:8099` setelah berhasil — halaman
rahasia (`flag.txt`) hanya tampil bila kredensial benar. Untuk reset ulang
password, jalankan `make_password.py` lagi; tambahkan `--with-number` bila
ingin ditambah angka acak, atau `--show` bila perlu melihat kata aslinya.

## Pemecahan Masalah

**Perintah tidak dikenali.** Pastikan Anda menjalankan dari folder proyek
dan sudah menginstal Python. Cek dengan `python --version`.

**WHOIS gagal / waktu habis.** Mungkin koneksi ke port 43 diblokir.
Gunakan `--skip-whois` atau ganti dengan `--whois-server` lain.

**Traceroute dibatasi.** Sebagian jaringan memblokir traceroute. Ini normal;
bagian ini hanyalah diagnostik dan tidak menghentikan program.

## Catatan Etika

Alat ini bersifat pasif dan hanya mengumpulkan informasi yang sudah publik.
Meski demikian, gunakanlah dengan penuh tanggung jawab — hanya pada target
yang memang sah untuk diuji, dan untuk tujuan belajar.