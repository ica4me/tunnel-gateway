# Tunnel Gateway — Ansible
SSH WebSocket/SSH-TLS, Xray VMess/VLESS/Trojan/Shadowsocks, HAProxy 80/443,
backend loopback dan CLI `tunnelctl`/`menu`; tanpa panel web.
**Teruji hanya Ubuntu 22.04 amd64 LAN + selfsigned.** OS lain, arm64,
ACME publik/Cloudflare dan migrasi lintas domain belum diverifikasi.
Pin Ansible 2.17.14 sudah EOL; untuk reproduksi, bukan jaminan keamanan produksi.

## Persiapan controller dan inventory
Target bersih: systemd, root/sudo, SSH berbasis kunci, konsol pemulihan,
port 80/443 kosong dan internet untuk apt/GitHub/go.dev. Controller Python
3.10–3.12, venv/pip/SSH; verifikasi fingerprint SSH lewat kanal tepercaya.
```bash
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip openssh-client
python3 -m venv .venv
.venv/bin/python -m pip install -r release/requirements.txt
.venv/bin/ansible-galaxy collection install -r requirements.yml
cp -a inventories/new-server inventories/my-server
$EDITOR inventories/my-server/hosts.yml
```
Ganti host/user/port, domain/email dan domain/path sertifikat di
`tunnelctl_settings`. Pertahankan SSH admin yang sudah aktif; port tambahan
masuk `ssh_admin_extra_ports`. Jangan aktifkan `openssh_admin_change_access`.
Template `tunnelctl_fresh_install=true` hanya untuk server bersih. Server berakun
wajib sudah diimpor: `tunnelctl_fresh_install=false`, `tunnelctl_accounts_imported=true`.
Untuk LAN gunakan `selfsigned` + `acme_enabled=false`; klien wajib pin sertifikat.
Jangan taruh rahasia di inventory, argumen shell, Git atau ZIP; gunakan Vault:
```bash
mkdir -p inventories/my-server/group_vars/all
.venv/bin/ansible-vault create inventories/my-server/group_vars/all/vault.yml
```
Backup timer default **mati**. Isi `backup_age_recipient` dengan public recipient
age Anda dan `backup_enabled=true`; prepare memvalidasi serta memasang recipient.
Simpan private identity offline; untuk restore otomatis, isi
`vault_backup_age_identity` di Vault (dipasang Ansible mode 0600/no_log).
Tidak ada private identity yang dibuat/disertakan ZIP. Path key CLI harus cocok.

## Deploy, verifikasi, rerun
```bash
BOOTSTRAP_PYTHON=python3 bash release/bootstrap.sh inventories/my-server/hosts.yml --ask-vault-pass
# Atau langkah eksplisit (tambahkan --ask-vault-pass bila memakai Vault):
.venv/bin/ansible-playbook -i inventories/my-server/hosts.yml playbooks/prepare-server.yml
.venv/bin/ansible-playbook -i inventories/my-server/hosts.yml playbooks/site.yml
.venv/bin/ansible-playbook -i inventories/my-server/hosts.yml playbooks/commit-server.yml
```
Bootstrap menjalankan prepare → site → commit. Prepare menyimpan policy milik
paket dan memasang rollback timer nyata 20 menit. Gagal/terputus: timer tetap
aktif, mengembalikan table/policy sebelumnya tanpa flush firewall lain.
Commit menjalankan `verify.yml`, koneksi SSH baru dan CLI doctor sebelum cancel.
Jangan cancel manual setelah deploy gagal. Konsol pemulihan tetap diperlukan.
Rerun dengan tiga langkah yang sama: site normal diharapkan `changed=0`, akun tetap.
Prepare/commit berubah karena arm/cancel timer; bukan perubahan runtime layanan.
Verify memeriksa layanan/listener/validator/waktu, bukan seluruh E2E internet.
Recovery notifikasi terputus: site `-e gateway_reconcile_restart=true`, lalu rerun.

## CLI dan backup/restore (root di target)
```bash
sudo menu
sudo tunnelctl doctor --json
sudo tunnelctl system status --json
sudo tunnelctl account create --proto vless --user pelanggan --days 30 --quota 10G --limit 2
sudo tunnelctl account list --json
sudo tunnelctl backup create --json
sudo tunnelctl backup list --json
sudo tunnelctl backup verify /var/backups/tunnel/ARSIP.tar.zst.age --json
sudo tunnelctl backup restore /var/backups/tunnel/ARSIP.tar.zst.age --yes --json
```
Wrapper controller: `ansible-playbook -i INVENTORY playbooks/backup.yml` fetch ke
`backups/<host>/`; restore: `ansible-playbook -i INVENTORY playbooks/restore.yml
-e backup_file=/path/ARSIP.tar.zst.age -e restore_confirm=true` (+ opsi Vault).
Restore mengubah data: verifikasi dahulu, simpan key terpisah, uji pada VM disposable.
Credential/link akun jangan disalin ke log. Restart Xray memutus koneksi aktif.
SSH payload split/multi-request gunakan IP VPS, bukan proxy Cloudflare.
Paket berisi source/migrasi/role/pin; tanpa key, DB, backup, lab inventory atau log.
[LISENSI](docs/LICENSING.md) · [Build/audit](docs/RELEASE.md)
