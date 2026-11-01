"""Menu interaktif Indonesia tanpa curses."""
import os
import sys

from .cli import run


def _clear():
    if sys.stdout.isatty() and os.environ.get('TERM'):
        sys.stdout.write('\033[2J\033[H')


def _pause():
    input('Tekan Enter untuk kembali...')


def _header():
    sys.stdout.write('=========== TUNNEL GATEWAY ===========\n')
    sys.stdout.write(' 1. Menu SSH WebSocket\n')
    sys.stdout.write(' 2. Menu VMess\n')
    sys.stdout.write(' 3. Menu VLESS\n')
    sys.stdout.write(' 4. Menu Trojan\n')
    sys.stdout.write(' 5. Menu Shadowsocks\n')
    sys.stdout.write(' 6. Cek user online (semua)\n')
    sys.stdout.write(' 7. Menu Sistem\n')
    sys.stdout.write(' 8. Backup & Restore\n')
    sys.stdout.write(' 9. Info port & path\n')
    sys.stdout.write(' 0. Keluar\n')


def _account_menu(name, protocol, settings_override=None, backend=None):
    while True:
        _clear()
        sys.stdout.write('=== MENU {0} ===\n'.format(name.upper()))
        sys.stdout.write(' 1. Buat akun\n')
        sys.stdout.write(' 2. Buat trial\n')
        sys.stdout.write(' 3. Perpanjang akun\n')
        sys.stdout.write(' 4. Hapus akun\n')
        sys.stdout.write(' 5. Kunci/Buka akun\n')
        sys.stdout.write(' 6. Ubah password/UUID\n')
        sys.stdout.write(' 7. Ubah kuota\n')
        sys.stdout.write(' 8. Ubah limit IP/login\n')
        sys.stdout.write(' 9. Reset pemakaian\n')
        sys.stdout.write('10. Detail akun\n')
        sys.stdout.write('11. Daftar akun\n')
        sys.stdout.write('12. Cek online\n')
        sys.stdout.write('13. Daftar hampir expired\n')
        sys.stdout.write(' 0. Kembali\n')
        choice = input('Pilih: ').strip()
        if choice in ('0', 'q', 'Q'):
            return
        if choice == '1':
            user = input('Username: ').strip()
            args = ['account', 'create', '--proto', protocol, '--user', user]
            if protocol == 'ssh':
                password = input('Password: ').strip()
                args += ['--pass', password]
            run(args, settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '2':
            user = input('Username trial: ').strip()
            hours = input('Durasi jam [1]: ').strip() or '1'
            args = ['account', 'create', '--proto', protocol, '--user', user, '--trial', '--hours', hours]
            if protocol == 'ssh':
                password = input('Password: ').strip()
                args += ['--pass', password]
            run(args, settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '3':
            user = input('Username: ').strip()
            days = input('Tambah hari: ').strip()
            run(['account', 'renew', '--proto', protocol, '--user', user, '--days', days], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '4':
            user = input('Username: ').strip()
            confirm = input('Yakin hapus akun? ketik y: ').strip().lower()
            if confirm == 'y':
                run(['account', 'delete', '--proto', protocol, '--user', user, '--yes'], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '5':
            user = input('Username: ').strip()
            mode = input('Ketik k untuk lock, u untuk unlock: ').strip().lower()
            if mode == 'k':
                minutes = input('Durasi lock menit (kosong=manual): ').strip()
                args = ['account', 'lock', '--proto', protocol, '--user', user]
                if minutes:
                    args += ['--minutes', minutes]
                run(args, settings_override=settings_override, backend=backend)
            elif mode == 'u':
                run(['account', 'unlock', '--proto', protocol, '--user', user], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '6':
            user = input('Username: ').strip()
            if protocol in ('vmess', 'vless'):
                regen = input('Regenerate UUID? [y/N]: ').strip().lower()
                if regen == 'y':
                    run(['account', 'update', '--proto', protocol, '--user', user, '--regen'], settings_override=settings_override, backend=backend)
                else:
                    value = input('UUID baru: ').strip()
                    run(['account', 'update', '--proto', protocol, '--user', user, '--uuid', value], settings_override=settings_override, backend=backend)
            else:
                value = input('Password baru: ').strip()
                run(['account', 'update', '--proto', protocol, '--user', user, '--pass', value], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '7':
            user = input('Username: ').strip()
            quota = input('Kuota baru (mis. 10G, 0=tanpa batas): ').strip()
            run(['account', 'update', '--proto', protocol, '--user', user, '--quota', quota], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '8':
            user = input('Username: ').strip()
            limit = input('Limit IP/login baru: ').strip()
            run(['account', 'update', '--proto', protocol, '--user', user, '--limit', limit], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '9':
            user = input('Username: ').strip()
            run(['account', 'reset-usage', '--proto', protocol, '--user', user], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '10':
            user = input('Username: ').strip()
            run(['account', 'show', '--proto', protocol, '--user', user], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '11':
            run(['account', 'list', '--proto', protocol], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '12':
            run(['account', 'online', '--proto', protocol], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '13':
            days = input('Jatuh tempo <= hari ke depan: ').strip() or '3'
            run(['account', 'list', '--proto', protocol, '--expiring-days', days], settings_override=settings_override, backend=backend)
            _pause()
            continue
        input('Pilihan tidak valid. Tekan Enter...')


def _system_menu(settings_override=None, backend=None):
    while True:
        _clear()
        sys.stdout.write('=== MENU SISTEM ===\n')
        sys.stdout.write(' 1. Status service\n')
        sys.stdout.write(' 2. Restart service\n')
        sys.stdout.write(' 3. Info sistem\n')
        sys.stdout.write(' 4. Ganti domain\n')
        sys.stdout.write(' 5. Perpanjang sertifikat\n')
        sys.stdout.write(' 6. Ganti banner SSH\n')
        sys.stdout.write(' 7. Bandwidth harian\n')
        sys.stdout.write(' 8. Bandwidth bulanan\n')
        sys.stdout.write(' 9. Logs service\n')
        sys.stdout.write('10. Auto-reboot set\n')
        sys.stdout.write('11. Auto-reboot off\n')
        sys.stdout.write('12. Bersihkan log\n')
        sys.stdout.write('13. Doctor\n')
        sys.stdout.write('14. Regenerate config\n')
        sys.stdout.write(' 0. Kembali\n')
        choice = input('Pilih: ').strip()
        if choice in ('0', 'q', 'Q'):
            return
        if choice == '1':
            run(['system', 'status'], settings_override=settings_override, backend=backend)
        elif choice == '2':
            service = input('Service (default all): ').strip() or 'all'
            run(['system', 'restart', service], settings_override=settings_override, backend=backend)
        elif choice == '3':
            run(['system', 'info'], settings_override=settings_override, backend=backend)
        elif choice == '4':
            domain = input('Domain baru: ').strip()
            run(['system', 'domain', 'set', domain], settings_override=settings_override, backend=backend)
        elif choice == '5':
            run(['system', 'cert', 'renew'], settings_override=settings_override, backend=backend)
        elif choice == '6':
            text = input('Isi banner: ')
            run(['system', 'banner', 'edit', '--text', text], settings_override=settings_override, backend=backend)
        elif choice == '7':
            run(['system', 'bandwidth', '--daily'], settings_override=settings_override, backend=backend)
        elif choice == '8':
            run(['system', 'bandwidth', '--monthly'], settings_override=settings_override, backend=backend)
        elif choice == '9':
            service = input('Service: ').strip()
            follow = input('Follow? [y/N]: ').strip().lower() == 'y'
            args = ['system', 'logs', service]
            if follow:
                args.append('--follow')
            run(args, settings_override=settings_override, backend=backend)
        elif choice == '10':
            value = input('Jam HH:MM: ').strip()
            run(['system', 'autoreboot', 'set', value], settings_override=settings_override, backend=backend)
        elif choice == '11':
            run(['system', 'autoreboot', 'off'], settings_override=settings_override, backend=backend)
        elif choice == '12':
            run(['system', 'clean-logs'], settings_override=settings_override, backend=backend)
        elif choice == '13':
            run(['doctor'], settings_override=settings_override, backend=backend)
        elif choice == '14':
            run(['config', 'regenerate'], settings_override=settings_override, backend=backend)
        else:
            input('Pilihan tidak valid. Tekan Enter...')
            continue
        _pause()


def _backup_menu(settings_override=None, backend=None):
    while True:
        _clear()
        sys.stdout.write('=== BACKUP & RESTORE ===\n')
        sys.stdout.write(' 1. Buat backup\n')
        sys.stdout.write(' 2. Daftar backup\n')
        sys.stdout.write(' 3. Verifikasi backup\n')
        sys.stdout.write(' 4. Restore backup\n')
        sys.stdout.write(' 0. Kembali\n')
        choice = input('Pilih: ').strip()
        if choice in ('0', 'q', 'Q'):
            return
        if choice == '1':
            run(['backup', 'create'], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '2':
            run(['backup', 'list'], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '3':
            path = input('File backup: ').strip()
            run(['backup', 'verify', path], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '4':
            path = input('File backup: ').strip()
            domain = input('Domain baru (kosongkan jika tidak ganti): ').strip()
            args = ['backup', 'restore', path, '--yes']
            if domain:
                args += ['--new-domain', domain]
            run(args, settings_override=settings_override, backend=backend)
            _pause()
            continue
        input('Pilihan tidak valid. Tekan Enter...')


def run_menu(settings_override=None, backend=None):
    while True:
        _clear()
        _header()
        choice = input('Pilih menu: ').strip()
        if choice in ('0', 'q', 'Q'):
            return 0
        if choice == '1':
            _account_menu('SSH WebSocket', 'ssh', settings_override=settings_override, backend=backend)
            continue
        if choice == '2':
            _account_menu('VMess', 'vmess', settings_override=settings_override, backend=backend)
            continue
        if choice == '3':
            _account_menu('VLESS', 'vless', settings_override=settings_override, backend=backend)
            continue
        if choice == '4':
            _account_menu('Trojan', 'trojan', settings_override=settings_override, backend=backend)
            continue
        if choice == '5':
            _account_menu('Shadowsocks', 'ss', settings_override=settings_override, backend=backend)
            continue
        if choice == '6':
            run(['account', 'online'], settings_override=settings_override, backend=backend)
            _pause()
            continue
        if choice == '7':
            _system_menu(settings_override=settings_override, backend=backend)
            continue
        if choice == '8':
            _backup_menu(settings_override=settings_override, backend=backend)
            continue
        if choice == '9':
            run(['system', 'ports'], settings_override=settings_override, backend=backend)
            _pause()
            continue
        input('Menu tidak valid. Tekan Enter...')
