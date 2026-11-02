# 🚀 Tunnel Gateway — Ansible

Script gratis dan otomatis untuk membangun **VPN/Tunnel Gateway** di VPS: SSH WebSocket, SSH SSL,
dan Xray (VMess, VLESS, Trojan, Shadowsocks) dalam **satu server, port 80 & 443**. Dikelola penuh lewat
menu CLI yang ringan dan interaktif — tanpa panel web yang memakan resource.

Satu perintah instalasi, sama untuk semua OS yang didukung. Aman dijalankan ulang kapan saja.

![Menu Tunnel Gateway](docs/menu.png)

## ✨ Fitur Utama

### 🔌 Koneksi & protokol

* **Semua protokol di port 80 & 443** — HAProxy -> (SSH WS, SSH-SSL, Xray WS, Xray gRPC).
* **SSH WebSocket** Support payload injector, termasuk payload **split** `[split]` dan
  multi-request.
* **SSH SSL/TLS** (stunnel-style) dan **SSH WS lewat TLS** di port 443.
* **Xray VMess, VLESS, Trojan, Shadowsocks** lewat WebSocket (port 80 & 443) dan **gRPC** (port 443).
* **UDPGW** (badvpn) untuk game online, voice call, dan DNS lewat tunnel SSH.
* **Host/bug host bebas** — routing memakai path, jadi header `Host` apa pun (termasuk subdomain
  wildcard) diterima.
* **Kompatibel dengan aplikasi tunnel lama** (HTTP Custom, HTTP Injector, dll.) — Dropbear dibangun
  dari source dengan algoritma lama tetap tersedia, sementara klien modern otomatis memakai algoritma
  terkuat (post-quantum `sntrup761` + `chacha20-poly1305`).
* **Situs kamuflase** — browser yang membuka domain Anda melihat halaman web biasa.

### 👤 Manajemen akun

* Buat akun **reguler** dan **trial** (trial terhapus otomatis setelah kedaluwarsa).
* Perpanjang, hapus, kunci/buka kunci, ganti password/UUID, ubah kuota & limit, reset pemakaian.
* **Detail akun lengkap** dalam tabel: link VMess/VLESS/Trojan/SS siap salin, contoh payload SSH, port,
  path, serviceName — bisa disimpan ke file atau dikirim ke Telegram.
* Default akun bisa diatur: masa aktif, limit IP/login, kuota (mis. 30 hari, 3 IP, 30 GB).
* Daftar akun, daftar hampir kedaluwarsa, dan **cek pengguna online** per protokol.

### 🛡️ Penegakan otomatis

* **Limit IP** (Xray) dan **limit login bersamaan** (SSH) — pelanggar dikunci otomatis, sesi diputus,
  dan dibuka kembali otomatis setelah masa kunci.
* **Limit kuota bandwidth** per akun Xray — akun berhenti otomatis saat kuota habis.
* **Masa aktif** ditegakkan otomatis; akun kedaluwarsa dinonaktifkan, trial dihapus.

### 🌐 Domain & sertifikat

* **Instal tanpa domain** — server langsung jalan memakai IP publik + sertifikat selfsigned.
* **Atur atau ganti domain kapan saja dari menu**, sertifikat **Let's Encrypt** diterbitkan otomatis,
  dengan pemeriksaan DNS & port 80 sebelum mulai dan **pemulihan otomatis** jika gagal.
* **Perpanjangan sertifikat otomatis**.

### 📊 Monitoring & sistem

* **Ringkasan server**: IP publik, ISP & lokasi, kecocokan DNS, masa berlaku sertifikat, status semua
  service, jumlah klien & yang online, backup terakhir, trafik hari ini, plus daftar **masalah yang
  terdeteksi**.
* Status service & timer, restart service (dengan keterangan dampaknya), log service.
* **Bandwidth harian & bulanan** (vnstat) dan **Speedtest Ookla** dari menu.
* **Doctor** — cek kesehatan otomatis (service, database, port, sertifikat, sinkron waktu, config).
* **Auto-reboot terjadwal** dengan pengaman (tidak reboot dalam 15 menit setelah menyala).
* Banner SSH bisa diubah dari menu.

### 🔔 Notifikasi Telegram

* Info akun dikirim otomatis ke Telegram saat **akun dibuat** (reguler & trial), dan opsional saat
  **melihat detail akun**.
* Hasil Speedtest bisa dikirim ke Telegram.
* Pengaturan lewat menu: token bot, deteksi chat ID otomatis, pesan uji.

### 💾 Backup & restore

* Backup database akun & konfigurasi, **opsional terenkripsi** (age).
* Verifikasi arsip sebelum restore, **snapshot otomatis** sebelum restore, dan pemulihan jika restore
  gagal.

### ⚡ Tuning server

* **TCP BBR + fq**, buffer socket besar, backlog koneksi besar, optimasi untuk klien seluler.
* Batas open files **1.048.576** untuk semua service.
* Menonaktifkan service yang tidak perlu (snapd, apport, ModemManager — dengan pengaman).
* **Pemeliharaan per jam yang aman**: restart service yang gagal, laporan proses zombie, pelepasan
  cache hanya saat RAM benar-benar menipis.
* **Log senyap** (log akses Xray/HAProxy/Nginx dimatikan) dan batas ukuran journal — disk tidak penuh.

### 🔒 Keamanan

* **Firewall nftables** dengan **rollback otomatis** — jika instalasi gagal, akses SSH tidak terkunci.
* Semua layanan internal hanya mendengar di `127.0.0.1`; publik hanya port 80, 443, dan SSH admin.
* Akun tunnel **tidak bisa login** ke SSH admin; **fail2ban** melindungi SSH admin.
* Service berjalan dengan pengamanan systemd; semua unduhan diverifikasi dengan **checksum**.
* Dikelola **Ansible** — idempoten, bisa di-update dan di-uninstall dengan bersih.

## 🔗 Protokol & port

| Layanan | Port | Keterangan |
|---|---|---|
| SSH WebSocket | 80 | Payload injector, include split |
| SSH WebSocket TLS | 443 | Payload di dalam TLS |
| SSH SSL | 443 | SSH murni di dalam TLS |
| Xray WS (VMess/VLESS/Trojan/SS) | 80 & 443 | Path `/vmess`, `/vless`, `/trojan`, `/ss` |
| Xray gRPC (VMess/VLESS/Trojan) | 443 | serviceName `vmess-grpc`, `vless-grpc`, `trojan-grpc` |
| UDPGW | 7300 | `127.0.0.1:7300` lewat tunnel SSH |

## 🖥️ Dukungan Sistem Operasi

Hanya OS berikut (amd64/arm64), dengan **langkah instalasi yang sama**:

| OS | Status |
|---|---|
| Debian 12 | ✅ Direkomendasikan #1 |
| Ubuntu 22.04 | ✅ Direkomendasikan #2 |
| Debian 13 | ✅ OK |
| Ubuntu 24.04 | ⚠️ Perlu verifikasi ulang |
| Ubuntu 26.04 | ⚠️ Perlu verifikasi ulang |

Perbedaan antar-OS ditangani otomatis: sintaks HTTP/2 Nginx, Dropbear, dan manifest
persi paket per OS.

## 🧹 Persiapan: rebuild OS (jika server tidak bersih)

Instalasi butuh **server bersih**. Jika VPS sudah berisi script/panel lain atau OS-nya bukan salah satu
di atas, instal ulang OS memakai [bin456789/reinstall](https://github.com/bin456789/reinstall):

> [!CAUTION]
> Perintah ini **menghapus seluruh isi disk** (termasuk partisi lain). Backup data terlebih dulu.
> Salah jalankan? Batalkan **sebelum reboot** dengan `bash reinstall.sh reset`.

```bash
curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh || wget -O ${_##*/} $_

# Pilih SATU:
bash reinstall.sh debian 12
bash reinstall.sh debian 13
bash reinstall.sh ubuntu 22.04
bash reinstall.sh ubuntu 24.04
bash reinstall.sh ubuntu 26.04

reboot
```

- Skrip akan **menanyakan username & password**. Jika dikosongkan, dipakai `root` dengan **password
  acak** — catat password yang ditampilkan, atau set sendiri: `bash reinstall.sh debian 12 --password 'PasswordAnda'`.
- Proses instalasi OS berlangsung beberapa menit setelah reboot; SSH kembali dengan password tersebut.
- OS baru belum diperbarui. Login lalu jalankan `apt-get update && apt-get -y upgrade`.

## ⚙️ Instalasi

Syarat: server bersih, login `root`, port **22, 80, 443** terbuka di firewall/security group provider.

### Instalasi normal (domain diatur nanti dari menu)

```bash
apt-get update && apt-get install -y git tmux
tmux new -s install                 # proses aman walau SSH terputus
git clone https://github.com/ica4me/tunnel-gateway.git /root/tunnel-gateway
cd /root/tunnel-gateway
bash bootstrap.sh 2>&1 | tee /root/install.log
```

`bootstrap.sh` menjalankan 5 tahap: paket OS → Speedtest (opsional) → rollback firewall → konfigurasi
service → verifikasi. Saat diminta, pilih mode paket **1 (pinned)**. Instalasi pertama sekitar
10–20 menit.

Server berjalan dalam **mode IP** (IP publik + sertifikat selfsigned). Atur domain kapan saja lewat menu
(lihat [Domain & sertifikat](#-domain--sertifikat-setelah-instalasi)).

Sebelum menjalankan, cek `inventories/new-server/hosts.yml`:

- `ssh_admin_port` = port SSH yang sedang Anda pakai; port SSH lain masukkan ke `ssh_admin_extra_ports`,
  mis. `[2026]`.

### Opsional: atur domain & sertifikat sebelum instalasi

Buat A record domain → IP server di Cloudflare (**DNS only**, awan abu-abu), lalu:

```bash
apt-get update && apt-get install -y git tmux
git clone https://github.com/ica4me/tunnel-gateway.git /root/tunnel-gateway
cd /root/tunnel-gateway

mkdir -p inventories/my-server
cp inventories/new-server/hosts.yml inventories/my-server/hosts.yml

DOMAIN=vpn.domainanda.com
EMAIL=admin@domainanda.com
sed -i "s|^\(\s*tunnel_domain:\s*\)\"[^\"]*\"|\1\"$DOMAIN\"|" inventories/my-server/hosts.yml
sed -i "s|^\(\s*admin_email:\s*\)\"[^\"]*\"|\1\"$EMAIL\"|"   inventories/my-server/hosts.yml
grep -E '^\s+(tunnel_domain|admin_email|cert_mode):' inventories/my-server/hosts.yml

tmux new -s install
bash bootstrap.sh inventories/my-server/hosts.yml 2>&1 | tee /root/install.log
```

Selalu pakai inventory yang sama untuk update: `bash bootstrap.sh inventories/my-server/hosts.yml`.
Folder `inventories/my-server/` berisi domain asli Anda — jangan di-commit ke repo publik.

Jika penerbitan sertifikat gagal (DNS belum aktif / port 80 tertutup), perbaiki lalu jalankan ulang
perintah yang sama, atau kosongkan `tunnel_domain` untuk instal dalam mode IP dan atur domain lewat menu.

### Reconfigure / update server yang sudah berjalan

Pakai langkah ini jika server **sudah berisi akun pelanggan** dan Anda ingin menerapkan ulang konfigurasi,
misalnya setelah `git pull` atau setelah mengubah setelan di inventory.

> [!IMPORTANT]
> Inventory yang disalin dari `inventories/new-server/hosts.yml` masih berisi setelan instalasi baru:
>
> - `tunnelctl_fresh_install: true`
> - `tunnelctl_accounts_imported: false`
>
> Setelan ini **tidak** langsung menghapus database akun, tetapi untuk server produksi lebih aman diubah
> menjadi:
>
> - `tunnelctl_fresh_install: false`
> - `tunnelctl_accounts_imported: true`

```bash
cd /root/tunnel-gateway
git pull                                   # opsional: ambil versi terbaru

tunnelctl backup create                    # disarankan: backup akun sebelum reconfigure

INV=inventories/my-server/hosts.yml
sed -i 's|^\(\s*tunnelctl_fresh_install:\s*\).*|\1false|'    "$INV"
sed -i 's|^\(\s*tunnelctl_accounts_imported:\s*\).*|\1true|' "$INV"
grep -E '^\s+tunnelctl_(fresh_install|accounts_imported):' "$INV"

tmux new -s install                        # proses aman walau SSH terputus
set -o pipefail
bash bootstrap.sh inventories/my-server/hosts.yml 2>&1 | tee /root/install.log
```

- `set -o pipefail` membuat perintah di atas ikut **gagal** jika `bootstrap.sh` gagal. Tanpa ini, status
  yang terbaca adalah status `tee`, yang selalu sukses.
- Jika server dulu diinstal dengan inventory bawaan (`inventories/new-server/hosts.yml`), salin dulu ke
  `inventories/my-server/hosts.yml` seperti di atas. Mengedit file bawaan langsung bisa bentrok saat
  `git pull`.
- Selalu pakai inventory yang sama dengan instalasi sebelumnya agar domain dan setelan tidak berubah.

### Opsi tambahan

| Perintah | Fungsi |
|---|---|
| `PACKAGE_MODE=pinned bash bootstrap.sh` | Tanpa pertanyaan mode paket |
| `SPEEDTEST=0 bash bootstrap.sh` | Lewati instalasi Speedtest |
| `bash bootstrap.sh --setup-only` | Hanya siapkan Ansible, tanpa deploy |

## 🌐 Domain & sertifikat (setelah instalasi)

1. Buat A record domain → IP server di Cloudflare (**DNS only**, awan abu-abu). Tanpa record AAAA.
2. `menu` → **7 Menu Sistem** → **4 Domain & Sertifikat TLS** → isi domain & email.

Menu memeriksa DNS dan akses port 80 lebih dulu, menerbitkan sertifikat Let's Encrypt, lalu memulihkan
setelan lama otomatis jika ada yang gagal. Sertifikat diperpanjang otomatis. Setelah domain berubah,
link akun ikut berubah — bagikan ulang ke pelanggan dari menu Detail akun.

## ✅ Verifikasi setelah instalasi

```bash
menu                                    # header menampilkan domain/IP dan status service ✔
tunnelctl doctor --json                 # "ok": true
sysctl -n net.ipv4.tcp_congestion_control   # bbr
```

## 🔄 Update

```bash
cd /root/tunnel-gateway
git pull
bash bootstrap.sh                       # atau: bash bootstrap.sh inventories/my-server/hosts.yml
```

Data akun tetap aman; update hanya memperbarui konfigurasi dan komponen.

## 🛠️ Manajemen Server & Akun

```bash
menu                                   # menu interaktif
tunnelctl doctor --json                # cek kesehatan
tunnelctl account create --proto vless --user pelanggan --days 30 --quota 10G --limit 2
tunnelctl account list
tunnelctl account online
tunnelctl backup create
```

### Pengaturan lanjutan (inventory)

Tambahkan di `hosts.yml` lalu jalankan ulang `bash bootstrap.sh`:

| Variabel | Default | Fungsi |
|---|---|---|
| `tuning_enabled` | `true` | Tuning server (BBR, sysctl, ulimit, pemeliharaan) |
| `gateway_quiet_logs` | `true` | `false` = nyalakan log untuk diagnosis |
| `tuning_disable_snapd` | `true` | Matikan snapd di Ubuntu (dilewati bila ada snap lain) |
| `dropbear_legacy_algorithms` | `true` | Kompatibilitas aplikasi tunnel lama |
| `ssh_admin_extra_ports` | `[]` | Port SSH admin tambahan |

## 🐞 Laporkan Masalah

Menemukan bug, error saat instalasi, atau punya saran fitur? Silakan buka issue di
[github.com/ica4me/tunnel-gateway/issues](https://github.com/ica4me/tunnel-gateway/issues).

Agar cepat ditangani, sertakan:

- OS dan versinya (`cat /etc/os-release`) serta arsitektur (amd64/arm64),
- langkah yang dijalankan dan pesan error yang muncul,
- potongan `/root/install.log` dan output `tunnelctl doctor --json`.

> [!WARNING]
> Sebelum menempelkan log, samarkan dulu domain asli, IP server, password/UUID akun, dan token bot Telegram.

## 📄 Lisensi

Kode proyek ini (playbook, role, `tunnelctl`) dirilis di bawah **WTFPL v2.0**. Komponen pihak ketiga
memakai lisensinya masing-masing, Lihat
[docs/LICENSING.md](docs/LICENSING.md).
