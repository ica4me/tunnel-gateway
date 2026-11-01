"""Backup & restore menu: numbered archive list, verify-before-restore, confirmations."""
import datetime
import os
import re
from pathlib import Path

from . import menu_ui as ui


def _files(settings_override=None):
    conf = ui.settings(settings_override)
    directory = Path(conf.get('backup_dir', '/var/backups/tunnel'))
    try:
        files = sorted((p for p in directory.glob('tunnel-backup-*') if p.is_file() and not p.is_symlink()),
                       key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        files = []
    return files, directory


def show_backups(settings_override=None):
    files, directory = _files(settings_override)
    ui.write('Lokasi backup : {0}'.format(directory))
    if not files:
        ui.write('Belum ada backup. Buat dulu lewat menu 1.')
        return []
    ui.write('Jumlah backup : {0}\n'.format(len(files)))
    rows = []
    for index, path in enumerate(files, 1):
        stat = path.stat()
        encrypted = path.name.endswith('.age')
        match = re.match(r'^tunnel-backup-.+-(\d{8}-\d{6}-[0-9a-f]+\..+)$', path.name)
        rows.append([str(index), datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                     ui.size(stat.st_size), ('ya', ui.GREEN) if encrypted else ('TIDAK', ui.YELLOW),
                     match.group(1) if match else path.name])
    ui.write_lines(ui.table(['No', 'Waktu', 'Ukuran', 'Enkripsi', 'File (tanpa awalan tunnel-backup-HOST-)'],
                            rows, [2, 16, 7, 8, 38], right=(0, 2)))
    return files


def pick_backup(settings_override=None):
    files = show_backups(settings_override)
    ui.write('\nKetik NOMOR dari tabel, atau PATH LENGKAP file backup.')
    ui.write('Contoh path: /var/backups/tunnel/tunnel-backup-HOST-YYYYmmdd-HHMMSS-xxxxxxxx.tar.zst')
    ui.write('             (berakhiran .tar.zst, atau .tar.zst.age jika terenkripsi)')
    while True:
        choice = ui.ask('Pilihan (kosong/0 = batal): ')
        if choice in ('', '0', 'q', 'Q'):
            return None
        if choice.isdigit():
            if 1 <= int(choice) <= len(files):
                return str(files[int(choice) - 1])
            ui.write('Nomor tidak ada di tabel.')
            continue
        if os.path.isfile(choice):
            return choice
        ui.write('File tidak ditemukan: {0}'.format(choice))


def _verify(path, settings_override=None, backend=None):
    code, data = ui.run_json(['backup', 'verify', path], settings_override, backend)
    if code != 0 or not isinstance(data, dict):
        ui.fail('arsip TIDAK valid atau tidak bisa dibaca. Sistem tidak diubah.')
        return False
    rows = [('#', 'HASIL VERIFIKASI'),
            ('File', path),
            ('Status', 'valid (checksum cocok)', ui.GREEN),
            ('Terenkripsi', 'ya' if data.get('encrypted') else 'tidak'),
            ('Versi skema DB', data.get('schema_version')),
            ('Isi arsip', ', '.join(f for f in data.get('files', []) if f != 'manifest.json'))]
    ui.write_lines(ui.box(rows))
    return True


def create(settings_override=None, backend=None):
    ui.title('BUAT BACKUP')
    code, data = ui.run_json(['backup', 'create'], settings_override, backend)
    if code != 0 or not isinstance(data, dict):
        ui.fail('backup tidak dibuat (lihat pesan di atas).')
        return
    path = Path(data.get('file', ''))
    rows = [('#', 'BACKUP DIBUAT'),
            ('File', str(path)),
            ('Ukuran', ui.size(path.stat().st_size) if path.exists() else '-'),
            ('Terenkripsi', 'ya' if data.get('encrypted') else 'TIDAK', None if data.get('encrypted') else ui.YELLOW)]
    ui.write_lines(ui.box(rows))
    if data.get('warning'):
        ui.write(ui.paint('Peringatan: ' + data['warning'], ui.YELLOW))


def verify(settings_override=None, backend=None):
    ui.title('VERIFIKASI BACKUP')
    path = pick_backup(settings_override)
    if path:
        _verify(path, settings_override, backend)
    else:
        ui.write('Dibatalkan.')


def restore(settings_override=None, backend=None):
    ui.title('RESTORE BACKUP')
    path = pick_backup(settings_override)
    if not path:
        ui.write('Dibatalkan.')
        return
    ui.write('\nMemeriksa arsip sebelum restore...')
    if not _verify(path, settings_override, backend):
        return
    try:
        current = ui.accounts(settings_override, backend)
        ui.write('Data saat ini: {0} akun akan DIGANTI dengan isi backup.'.format(len(current)))
    except Exception:
        pass
    ui.write(ui.paint('PERINGATAN: restore mengganti seluruh data akun saat ini dengan isi backup.', ui.RED))
    ui.write('Snapshot keadaan sekarang dibuat otomatis sebelum restore.')
    ui.write('Koneksi Xray dan SSH yang aktif akan terputus sesaat.')
    ui.write('Catatan: ganti domain saat restore belum didukung.')
    if not ui.ask_yes('Lanjutkan restore? [y/N]: '):
        ui.write('Restore dibatalkan.')
        return
    code, data = ui.run_json(['backup', 'restore', path, '--yes'], settings_override, backend)
    if code != 0 or not isinstance(data, dict):
        ui.fail('restore gagal; sistem dikembalikan ke keadaan sebelum restore (lihat pesan di atas).')
        return
    rows = [('#', 'RESTORE SELESAI'),
            ('Dari file', path),
            ('Snapshot sebelum', data.get('pre_restore_backup', '-'))]
    try:
        rows.append(('Akun sekarang', len(ui.accounts(settings_override, backend))))
    except Exception:
        pass
    ui.write_lines(ui.box(rows))


ITEMS = [('1', 'Buat backup', create),
         ('2', 'Daftar backup', lambda s, b: show_backups(s)),
         ('3', 'Verifikasi backup', verify),
         ('4', 'Restore backup', restore)]


def backup_menu(settings_override=None, backend=None):
    actions = dict((key, fn) for key, _, fn in ITEMS)
    while True:
        ui.clear()
        ui.title('BACKUP & RESTORE')
        for key, label, _ in ITEMS:
            ui.write(' {0}. {1}'.format(key, label))
        ui.write(' 0. Kembali')
        choice = ui.ask('Pilih: ')
        if choice in ('0', 'q', 'Q'):
            return
        ui.clear()
        if choice in actions:
            if choice == '2':
                ui.title('DAFTAR BACKUP')
            actions[choice](settings_override, backend)
        else:
            ui.write('Pilihan tidak valid.')
        ui.pause()
