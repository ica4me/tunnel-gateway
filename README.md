# 🚀 Tunnel Gateway — Ansible

Script gratis dan otomatis untuk menginstal VPN Gateway di server Anda. Dikelola sepenuhnya melalui antarmuka CLI yang ringan dan interaktif, tanpa menggunakan panel web yang memakan banyak resource.

![Menu Tunnel Gateway](https://private-user-images.githubusercontent.com/122198219/691370136-8643fa2d-3715-4d71-b4b7-71458440dd82.png?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3OTM1MjA0MzAsIm5iZiI6MTc5MzUyMDEzMCwicGF0aCI6Ii8xMjIxOTgyMTkvNjkxMzcwMTM2LTg2NDNmYTJkLTM3MTUtNGQ3MS1iNGI3LTcxNDU4NDQwZGQ4Mi5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjYxMTAxJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI2MTEwMVQwODAyMTBaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT00NzRkZGJkNTM4MjBjMzlkMjE2ZDI4NWE4ZmVlNmQ0NmFlNmNhZWNkNmFkZjFhN2Q0ODI4YWQyNWMwY2IyMzQ2JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCZyZXNwb25zZS1jb250ZW50LXR5cGU9aW1hZ2UlMkZwbmcifQ.p1rL_iw83wv_5pP-TJ-EhGv38lrS3ZqpjdDc8THDB2g)

## ✨ Fitur Utama

* **Penegakan Otomatis:** Limit IP/Login bersamaan & Limit Kuota Bandwidth.

* **Trial Akun:** Pembuatan akun uji coba yang otomatis terhapus saat kedaluwarsa.

* **Keamanan:** Banned/Lock otomatis untuk pengguna yang melanggar batasan.

* **Notifikasi:** Terintegrasi dengan Bot Telegram (opsional).

* **Aman & Fleksibel:** Fitur Backup & Restore database akun ke file terenkripsi.

* **Manajemen Mudah:** CLI interaktif (`menu`) atau perintah langsung (`tunnelctl`).

## 🛡️ Protokol yang Didukung

* SSH WebSocket (WS)

* SSH Stunnel (TLS)

* Xray VMess

* Xray VLESS

* Xray Trojan

* Xray Shadowsocks

## 🖥️ Dukungan Sistem Operasi

Script ini secara spesifik **hanya mendukung** sistem operasi berikut (amd64/arm64):

* **Ubuntu 22.04** (✅ *Sangat Direkomendasikan & Sudah Teruji*)

* Ubuntu 24.04

* Ubuntu 26.04

* Debian 12

* Debian 13

*OS di luar daftar ini (seperti CentOS, Alpine, dll) tidak didukung.*

## ⚙️ Persiapan & Instalasi Paket

Login ke VPS Anda sebagai `root` dan jalankan perintah berikut secara berurutan:

```
# 1. Update dan install dependensi dasar
apt-get update
apt-get install -y tmux python3-venv python3-pip openssh-client

# 2. Buka sesi tmux agar proses aman meski koneksi SSH terputus
tmux new -s install

# 3. Clone repositori ke dalam folder /root
git clone https://github.com/ica4me/tunnel-gateway.git /root/tunnel-gateway
cd /root/tunnel-gateway

# 4. Siapkan environment Python & Ansible
python3 -m venv .venv
.venv/bin/python -m pip install -r release/requirements.txt
.venv/bin/ansible-galaxy collection install -r requirements.yml

# 5. Verifikasi sintaks playbook (Pastikan tidak ada error)
for p in prepare-server site commit-server; do
  .venv/bin/ansible-playbook playbooks/$p.yml --syntax-check || break
done

# 6. (Opsional) Cek konfigurasi target inventory Anda
.venv/bin/ansible-inventory --host worker-test1 | grep -E 'domain|cert_mode|connection'

```

### ▶️ Mulai Deploy Server

Setelah mengedit file konfigurasi host Anda di folder `inventories/` (misal mengganti domain, email, dll), jalankan perintah deploy utama:

```
# Ganti path inventory sesuai dengan konfigurasi Anda
BOOTSTRAP_PYTHON=python3 bash release/bootstrap.sh inventories/new-server/hosts.yml

```

## 🛠️ Manajemen Server & Akun

Semua pengelolaan dilakukan melalui CLI langsung di dalam VPS target.

**Buka Menu Interaktif Utama:**

```
sudo menu

```

**Contoh Perintah Cepat (`tunnelctl`):**

```
# Mengecek kesehatan komponen server
sudo tunnelctl doctor --json

# Membuat akun VLESS
sudo tunnelctl account create --proto vless --user pelanggan --days 30 --quota 10G --limit 2

# Melihat daftar akun & status online
sudo tunnelctl account list
sudo tunnelctl account online

# Melakukan backup server manual
sudo tunnelctl backup create

```

## 📄 Lisensi

Proyek ini dirilis di bawah lisensi **WTFPL v2.0**. Silakan lihat file [LICENSING.md](docs/LICENSING.md) untuk informasi lebih lanjut.
