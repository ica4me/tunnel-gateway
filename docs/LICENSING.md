# Ringkasan Lisensi Komponen

Dokumen ini untuk paket rilis sumber (`tunnel-gateway-release.zip`).

## Komponen utama

- **Xray-core**: Mozilla Public License 2.0 (MPL-2.0).
  - Referensi: `https://raw.githubusercontent.com/XTLS/Xray-core/main/LICENSE`
- **badvpn** (`udpgw`): lisensi BSD 3-Clause.
  - Referensi: `https://raw.githubusercontent.com/ambrop72/badvpn/master/COPYING`
- **Ansible / ansible-core**: GPLv3+ (mengikuti distribusi resmi paket Python).

## Catatan Ws-Epro

Repositori rujukan `ica4me/Ws-Epro` saat inspeksi tidak menyediakan file lisensi yang jelas pada URL LICENSE standar.

Konsekuensi operasional:

- gunakan hanya commit yang dipin untuk kebutuhan internal/deploy,
- jangan redistribusi binary Ws-Epro ke pihak ketiga sebelum lisensi upstream dipastikan,
- pastikan review legal internal jika paket akan didistribusikan lebih luas.

## Isi paket rilis

Paket rilis ini hanya memuat:

- playbook/role Ansible yang dibutuhkan deploy,
- source Python `tunnelctl`,
- template inventory aman (`inventories/new-server`),
- dokumen teknis rilis.

Paket **tidak** memuat bundle source pihak ketiga eksternal (Xray/Ws-Epro/badvpn) karena diunduh saat deploy sesuai versi pin.
