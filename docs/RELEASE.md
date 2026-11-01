# Proses Paket Rilis Portabel

## Tujuan

Membuat ZIP sumber yang aman untuk deploy server baru tanpa membawa data lab, secret, atau artefak runtime.

## Perintah audit (tanpa membuat ZIP final)

```bash
python3 release/build-release.py --audit-only
python3 -m unittest discover -s tests/release -v
```

## Perintah build ZIP (jalankan hanya saat parent/owner sudah izinkan)

```bash
python3 release/build-release.py --output /root/tunnel-gateway-release.zip
```

## Cek integritas arsip

```bash
python3 - <<'PY'
import zipfile
z = zipfile.ZipFile('/root/tunnel-gateway-release.zip')
print('crc_ok=', z.testzip() is None)
print('entries=', len(z.namelist()))
PY
```

## Cek sintaks setelah ekstrak (opsional verifikasi rilis final)

```bash
mkdir -p $HOME/tg-release-check
unzip -o /root/tunnel-gateway-release.zip -d $HOME/tg-release-check
cd $HOME/tg-release-check/tunnel-gateway
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
ansible-galaxy collection install -r requirements.yml
ansible-playbook -i inventories/new-server/hosts.yml playbooks/site.yml --syntax-check
ansible-playbook -i inventories/new-server/hosts.yml playbooks/verify.yml --syntax-check
ansible-playbook -i inventories/new-server/hosts.yml playbooks/backup.yml --syntax-check
ansible-playbook -i inventories/new-server/hosts.yml playbooks/restore.yml --syntax-check
```
