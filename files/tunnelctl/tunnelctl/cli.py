"""CLI tunnelctl: JSON output + exit code spesifikasi."""
import argparse
import json
import os
import re
import sys
from pathlib import Path

from .backup import Backup
from .enforce import enforce
from .errors import Conflict, InputError, NotFound, TunnelCtlError
from .manager import Manager
from .system import atomic_write


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INPUT = 2
EXIT_NOT_FOUND = 3
EXIT_CONFLICT = 4


def _print(data, as_json=False):
    if as_json:
        sys.stdout.write(json.dumps(data, ensure_ascii=False, sort_keys=True) + '\n')
        return
    if isinstance(data, dict):
        for key in sorted(data.keys()):
            sys.stdout.write('{}: {}\n'.format(key, data[key]))
    elif isinstance(data, list):
        for row in data:
            sys.stdout.write(json.dumps(row, ensure_ascii=False) + '\n')
    else:
        sys.stdout.write(str(data) + '\n')


def _load_settings_file(path):
    if os.path.exists(path):
        try:
            with open(path) as handle:
                raw = json.load(handle)
        except ValueError as exc:
            raise InputError('Format settings.json tidak valid') from exc
        if not isinstance(raw, dict):
            raise InputError('settings.json harus object')
        return raw
    raise InputError('File config tidak ditemukan: {}'.format(path))


def _save_settings_file(path, updates):
    data = _load_settings_file(path)
    data.update(updates)
    atomic_write(path, json.dumps(data, sort_keys=True, indent=2) + '\n')


def _validate_hhmm(value):
    if not re.match(r'^[0-2][0-9]:[0-5][0-9]$', value):
        raise InputError('Format waktu autoreboot harus HH:MM')
    hour = int(value.split(':')[0])
    if hour > 23:
        raise InputError('Jam autoreboot tidak valid')
    return value


def build_parser():
    parser = argparse.ArgumentParser(prog='tunnelctl')
    parser.add_argument('--config', help='Path settings.json override')

    sub = parser.add_subparsers(dest='command')

    account = sub.add_parser('account')
    account_sub = account.add_subparsers(dest='account_command')

    create = account_sub.add_parser('create')
    create.add_argument('--proto', required=True, choices=['ssh', 'vmess', 'vless', 'trojan', 'ss'])
    create.add_argument('--user', required=True)
    create.add_argument('--pass', dest='password')
    create.add_argument('--uuid', dest='uuid_value')
    create.add_argument('--days', type=int)
    create.add_argument('--hours', type=int)
    create.add_argument('--trial', action='store_true')
    create.add_argument('--quota')
    create.add_argument('--limit', type=int)
    create.add_argument('--note')
    create.add_argument('--json', action='store_true')

    show = account_sub.add_parser('show')
    show.add_argument('--proto', required=True, choices=['ssh', 'vmess', 'vless', 'trojan', 'ss'])
    show.add_argument('--user', required=True)
    show.add_argument('--json', action='store_true')

    list_cmd = account_sub.add_parser('list')
    list_cmd.add_argument('--proto', choices=['ssh', 'vmess', 'vless', 'trojan', 'ss'])
    list_cmd.add_argument('--status')
    list_cmd.add_argument('--expiring-days', type=int)
    list_cmd.add_argument('--json', action='store_true')

    delete = account_sub.add_parser('delete')
    delete.add_argument('--proto', required=True, choices=['ssh', 'vmess', 'vless', 'trojan', 'ss'])
    delete.add_argument('--user', required=True)
    delete.add_argument('--yes', action='store_true')

    renew = account_sub.add_parser('renew')
    renew.add_argument('--proto', required=True, choices=['ssh', 'vmess', 'vless', 'trojan', 'ss'])
    renew.add_argument('--user', required=True)
    renew.add_argument('--days', required=True, type=int)
    renew.add_argument('--reset-quota', action='store_true')
    renew.add_argument('--quota')
    renew.add_argument('--json', action='store_true')

    update = account_sub.add_parser('update')
    update.add_argument('--proto', required=True, choices=['ssh', 'vmess', 'vless', 'trojan', 'ss'])
    update.add_argument('--user', required=True)
    update.add_argument('--pass', dest='password')
    update.add_argument('--uuid', dest='uuid_value')
    update.add_argument('--regen', action='store_true')
    update.add_argument('--quota')
    update.add_argument('--limit', type=int)
    update.add_argument('--note')
    update.add_argument('--json', action='store_true')

    lock = account_sub.add_parser('lock')
    lock.add_argument('--proto', required=True, choices=['ssh', 'vmess', 'vless', 'trojan', 'ss'])
    lock.add_argument('--user', required=True)
    lock.add_argument('--minutes', type=int)
    lock.add_argument('--reason')
    lock.add_argument('--json', action='store_true')

    unlock = account_sub.add_parser('unlock')
    unlock.add_argument('--proto', required=True, choices=['ssh', 'vmess', 'vless', 'trojan', 'ss'])
    unlock.add_argument('--user', required=True)
    unlock.add_argument('--json', action='store_true')

    online = account_sub.add_parser('online')
    online.add_argument('--proto', choices=['ssh', 'vmess', 'vless', 'trojan', 'ss'])
    online.add_argument('--activity', action='store_true',
                        help='bedakan aktif trafik / idle dengan dua snapshot counter (tanpa reset)')
    online.add_argument('--interval', type=float, help='lama pengamatan dalam detik (1-10, default 3)')
    online.add_argument('--json', action='store_true')

    usage_top = account_sub.add_parser('usage-top')
    usage_top.add_argument('--day', help='tanggal UTC YYYY-MM-DD (default: hari ini UTC)')
    usage_top.add_argument('--limit', type=int, default=20)
    usage_top.add_argument('--proto', choices=['ssh', 'vmess', 'vless', 'trojan', 'ss'])
    usage_top.add_argument('--json', action='store_true')

    reset_usage = account_sub.add_parser('reset-usage')
    reset_usage.add_argument('--proto', required=True, choices=['ssh', 'vmess', 'vless', 'trojan', 'ss'])
    reset_usage.add_argument('--user', required=True)
    reset_usage.add_argument('--json', action='store_true')

    enforce_cmd = sub.add_parser('enforce')
    enforce_cmd.add_argument('mode', choices=['expiry', 'quota', 'limit', 'all'])
    enforce_cmd.add_argument('--json', action='store_true')

    backup = sub.add_parser('backup')
    backup_sub = backup.add_subparsers(dest='backup_command')
    backup_create = backup_sub.add_parser('create')
    backup_create.add_argument('--output')
    backup_create.add_argument('--json', action='store_true')
    backup_list = backup_sub.add_parser('list')
    backup_list.add_argument('--json', action='store_true')
    backup_verify = backup_sub.add_parser('verify')
    backup_verify.add_argument('file')
    backup_verify.add_argument('--json', action='store_true')
    backup_restore = backup_sub.add_parser('restore')
    backup_restore.add_argument('file')
    backup_restore.add_argument('--new-domain')
    backup_restore.add_argument('--yes', action='store_true')
    backup_restore.add_argument('--json', action='store_true')

    system = sub.add_parser('system')
    system_sub = system.add_subparsers(dest='system_command')

    system_status = system_sub.add_parser('status')
    system_status.add_argument('--json', action='store_true')

    system_restart = system_sub.add_parser('restart')
    system_restart.add_argument('service', nargs='?', default='all')
    system_restart.add_argument('--json', action='store_true')

    system_info = system_sub.add_parser('info')
    system_info.add_argument('--json', action='store_true')

    system_ports = system_sub.add_parser('ports')
    system_ports.add_argument('--json', action='store_true')

    system_domain = system_sub.add_parser('domain')
    domain_sub = system_domain.add_subparsers(dest='domain_command')
    domain_set = domain_sub.add_parser('set')
    domain_set.add_argument('new_domain')
    domain_set.add_argument('--json', action='store_true')

    system_cert = system_sub.add_parser('cert')
    cert_sub = system_cert.add_subparsers(dest='cert_command')
    cert_renew = cert_sub.add_parser('renew')
    cert_renew.add_argument('--json', action='store_true')

    system_banner = system_sub.add_parser('banner')
    banner_sub = system_banner.add_subparsers(dest='banner_command')
    banner_edit = banner_sub.add_parser('edit')
    banner_edit.add_argument('--text')
    banner_edit.add_argument('--json', action='store_true')

    system_bw = system_sub.add_parser('bandwidth')
    mode = system_bw.add_mutually_exclusive_group()
    mode.add_argument('--daily', action='store_true')
    mode.add_argument('--monthly', action='store_true')
    system_bw.add_argument('--json', action='store_true')

    system_logs = system_sub.add_parser('logs')
    system_logs.add_argument('service')
    system_logs.add_argument('--follow', action='store_true')
    system_logs.add_argument('--json', action='store_true')

    system_autoreboot = system_sub.add_parser('autoreboot')
    autoreboot_sub = system_autoreboot.add_subparsers(dest='autoreboot_command')
    autoreboot_set = autoreboot_sub.add_parser('set')
    autoreboot_set.add_argument('time_hhmm')
    autoreboot_set.add_argument('--json', action='store_true')
    autoreboot_off = autoreboot_sub.add_parser('off')
    autoreboot_off.add_argument('--json', action='store_true')
    autoreboot_status = autoreboot_sub.add_parser('status')
    autoreboot_status.add_argument('--json', action='store_true')

    system_clean = system_sub.add_parser('clean-logs')
    system_clean.add_argument('--json', action='store_true')

    config = sub.add_parser('config')
    config_sub = config.add_subparsers(dest='config_command')
    regenerate = config_sub.add_parser('regenerate')
    regenerate.add_argument('--dry-run', action='store_true')
    regenerate.add_argument('--json', action='store_true')

    doctor = sub.add_parser('doctor')
    doctor.add_argument('--json', action='store_true')

    version = sub.add_parser('version')
    version.add_argument('--json', action='store_true')

    sub.add_parser('menu')
    return parser


def _secret_arg(args):
    if args.uuid_value:
        return args.uuid_value
    if args.password:
        return args.password
    return None


def _system_handler(args, manager):
    command = args.system_command
    as_json = getattr(args, 'json', False)

    if command == 'status':
        _print(manager.backend.status(), as_json=as_json)
        return EXIT_OK
    if command == 'info':
        info_fn = getattr(manager.backend, 'info', None)
        value = info_fn(manager.settings) if callable(info_fn) else {'domain': manager.settings.get('domain')}
        _print(value, as_json=as_json)
        return EXIT_OK
    if command == 'ports':
        _print({'ports': manager.backend.ports()}, as_json=as_json)
        return EXIT_OK
    if command == 'restart':
        _print(manager.backend.restart(args.service), as_json=as_json)
        return EXIT_OK

    if command == 'domain' and args.domain_command == 'set':
        domain = args.new_domain.strip().lower()
        if not domain:
            raise InputError('Domain tidak valid')
        migrate = getattr(manager.backend, 'migrate_domain', None)
        if not callable(migrate):
            raise InputError('Hook migrasi domain belum dikonfigurasi')
        with manager.db.lock():
            settings_file = manager.settings['settings_path']
            original_bytes = Path(settings_file).read_bytes() if os.path.exists(settings_file) else None
            old_settings = dict(manager.settings)
            old_domain = old_settings.get('domain')
            preflight = migrate(old_domain, domain, manager.settings, apply=False)
            if not isinstance(preflight, dict) or preflight.get('ok') is not True:
                raise TunnelCtlError('Validasi migrasi domain gagal')
            try:
                _save_settings_file(settings_file, {'domain': domain})
                manager.settings['domain'] = domain
                apply_report = migrate(old_domain, domain, manager.settings, apply=True)
                if not isinstance(apply_report, dict) or apply_report.get('ok') is not True:
                    raise TunnelCtlError('Migrasi domain gagal diterapkan')
                regen = getattr(manager.backend, 'regenerate_config', None)
                if callable(regen):
                    report = regen(manager.rows(), manager.settings, dry_run=False)
                    if report is False or (isinstance(report, dict) and report.get('ok') is False):
                        raise TunnelCtlError('Regenerasi konfigurasi gagal')
                else:
                    manager.backend.reconcile(manager.rows(), manager.rows(), manager.settings)
            except BaseException:
                manager.settings = old_settings
                if original_bytes is None:
                    if os.path.exists(settings_file):
                        os.unlink(settings_file)
                else:
                    atomic_write(settings_file, original_bytes)
                rollback_report = migrate(domain, old_domain, manager.settings, apply=True, rollback=True)
                if not isinstance(rollback_report, dict) or rollback_report.get('ok') is not True:
                    raise TunnelCtlError('Rollback migrasi domain gagal')
                raise
        _print({'domain': domain, 'migrated': True}, as_json=as_json)
        return EXIT_OK

    if command == 'cert' and args.cert_command == 'renew':
        fn = getattr(manager.backend, 'cert_renew', None)
        if not callable(fn):
            raise InputError('Backend tidak mendukung cert renew')
        _print(fn(manager.settings), as_json=as_json)
        return EXIT_OK

    if command == 'banner' and args.banner_command == 'edit':
        text = args.text
        if text is None:
            text = sys.stdin.read()
        if text is None or not str(text).strip():
            raise InputError('Banner tidak boleh kosong')
        with manager.db.lock():
            atomic_write(manager.settings.get('banner_path', '/etc/tunnel/banner.txt'), str(text).rstrip('\n') + '\n')
        _print({'updated': True}, as_json=as_json)
        return EXIT_OK

    if command == 'bandwidth':
        fn = getattr(manager.backend, 'bandwidth', None)
        if not callable(fn):
            raise InputError('Backend tidak mendukung bandwidth')
        mode = 'monthly' if args.monthly else 'daily'
        _print(fn(mode=mode), as_json=as_json)
        return EXIT_OK

    if command == 'logs':
        fn = getattr(manager.backend, 'logs', None)
        if not callable(fn):
            raise InputError('Backend tidak mendukung logs')
        if args.follow and as_json:
            raise InputError('--json tidak didukung saat --follow')
        value = fn(args.service, follow=args.follow)
        if args.follow:
            return EXIT_OK
        _print({'logs': value}, as_json=as_json)
        return EXIT_OK

    if command == 'autoreboot' and args.autoreboot_command == 'status':
        fn = getattr(manager.backend, 'get_autoreboot', None)
        if not callable(fn):
            raise InputError('Backend tidak mendukung autoreboot')
        _print(fn(manager.settings), as_json=as_json)
        return EXIT_OK

    if command == 'autoreboot':
        fn = getattr(manager.backend, 'set_autoreboot', None)
        if not callable(fn):
            raise InputError('Backend tidak mendukung autoreboot')
        value = None
        if args.autoreboot_command == 'set':
            value = _validate_hhmm(args.time_hhmm)
        elif args.autoreboot_command == 'off':
            value = None
        else:
            raise InputError('Subcommand autoreboot tidak valid')
        settings_file = manager.settings['settings_path']
        with manager.db.lock():
            original_bytes = Path(settings_file).read_bytes() if os.path.exists(settings_file) else None
            old_settings = dict(manager.settings)
            try:
                _save_settings_file(settings_file, {'autoreboot': value})
                manager.settings['autoreboot'] = value
                output = fn(manager.settings, value)
            except BaseException:
                manager.settings = old_settings
                if original_bytes is None:
                    if os.path.exists(settings_file):
                        os.unlink(settings_file)
                else:
                    atomic_write(settings_file, original_bytes)
                raise
        _print(output, as_json=as_json)
        return EXIT_OK

    if command == 'clean-logs':
        fn = getattr(manager.backend, 'clean_logs', None)
        if not callable(fn):
            raise InputError('Backend tidak mendukung clean-logs')
        _print(fn(), as_json=as_json)
        return EXIT_OK

    raise InputError('Subcommand system tidak valid')


def run(argv=None, settings_override=None, backend=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    manager = None
    try:
        settings = dict(settings_override or {})
        if args.config:
            selected = _load_settings_file(args.config)
            selected.update(settings)
            settings = selected
            settings['settings_path'] = args.config
        if args.command == 'menu':
            from .menu import run_menu
            return run_menu(settings_override=settings, backend=backend)
        if args.command == 'version':
            from . import __version__
            payload = {'version': __version__}
            _print(payload, as_json=args.json)
            return EXIT_OK

        manager = Manager(settings=settings, backend=backend)

        if args.command == 'account':
            cmd = args.account_command
            if cmd == 'create':
                data = manager.create(
                    args.proto,
                    args.user,
                    secret=_secret_arg(args),
                    days=args.days,
                    hours=args.hours,
                    trial=bool(args.trial),
                    quota=args.quota,
                    limit=args.limit,
                    note=args.note,
                )
                _print(data, as_json=args.json)
                return EXIT_OK
            if cmd == 'show':
                _print(manager.show(args.proto, args.user), as_json=args.json)
                return EXIT_OK
            if cmd == 'list':
                _print(manager.list(protocol=args.proto, status=args.status, expiring_days=args.expiring_days), as_json=args.json)
                return EXIT_OK
            if cmd == 'delete':
                if not args.yes:
                    raise InputError('Gunakan --yes untuk konfirmasi delete')
                _print(manager.delete(args.proto, args.user), as_json=False)
                return EXIT_OK
            if cmd == 'renew':
                _print(manager.renew(args.proto, args.user, args.days, reset_quota=args.reset_quota, quota=args.quota), as_json=args.json)
                return EXIT_OK
            if cmd == 'update':
                _print(
                    manager.update(
                        args.proto,
                        args.user,
                        secret=_secret_arg(args),
                        regen=bool(args.regen),
                        quota=args.quota,
                        limit=args.limit,
                        note=args.note,
                    ),
                    as_json=args.json,
                )
                return EXIT_OK
            if cmd == 'lock':
                _print(manager.lock(args.proto, args.user, minutes=args.minutes, reason=args.reason), as_json=args.json)
                return EXIT_OK
            if cmd == 'unlock':
                _print(manager.unlock(args.proto, args.user), as_json=args.json)
                return EXIT_OK
            if cmd == 'online':
                if args.activity:
                    _print(manager.online_activity(protocol=args.proto, interval=args.interval), as_json=args.json)
                else:
                    _print(manager.online(protocol=args.proto), as_json=args.json)
                return EXIT_OK
            if cmd == 'usage-top':
                _print(manager.usage_top(day=args.day, limit=args.limit, protocol=args.proto), as_json=args.json)
                return EXIT_OK
            if cmd == 'reset-usage':
                _print(manager.reset_usage(args.proto, args.user), as_json=args.json)
                return EXIT_OK
            raise InputError('Subcommand account tidak valid')

        if args.command == 'enforce':
            report = enforce(manager, args.mode, actor='cli')
            _print(report, as_json=args.json)
            return EXIT_OK

        if args.command == 'backup':
            cmd = args.backup_command
            backup = Backup(manager)
            if cmd == 'create':
                out = backup.create(output=args.output)
                data = {'file': str(out), 'encrypted': str(out).endswith('.age')}
                if not data['encrypted']:
                    data['warning'] = 'Backup TIDAK terenkripsi (kunci age belum dipasang). File berisi password/UUID akun; simpan di tempat aman.'
                _print(data, as_json=args.json)
                return EXIT_OK
            if cmd == 'list':
                files = []
                for item in backup.list():
                    stat = item.stat()
                    files.append({'path': str(item), 'size': stat.st_size, 'mtime': int(stat.st_mtime)})
                _print({'files': files}, as_json=args.json)
                return EXIT_OK
            if cmd == 'verify':
                _print(backup.verify(args.file), as_json=args.json)
                return EXIT_OK
            if cmd == 'restore':
                if not args.yes:
                    raise InputError('Gunakan --yes untuk konfirmasi restore')
                _print(backup.restore(args.file, new_domain=args.new_domain), as_json=args.json)
                return EXIT_OK
            raise InputError('Subcommand backup tidak valid')

        if args.command == 'system':
            return _system_handler(args, manager)

        if args.command == 'config':
            if args.config_command == 'regenerate':
                regen = getattr(manager.backend, 'regenerate_config', None)
                with manager.db.lock():
                    if callable(regen):
                        report = regen(manager.rows(), manager.settings, dry_run=args.dry_run)
                    elif args.dry_run:
                        raise InputError('Dry-run regenerate belum didukung backend ini')
                    else:
                        manager.backend.reconcile(manager.rows(), manager.rows(), manager.settings)
                        report = {'ok': True, 'dry_run': False}
                _print(report, as_json=args.json)
                return EXIT_OK
            raise InputError('Subcommand config tidak valid')

        if args.command == 'doctor':
            doctor = getattr(manager.backend, 'doctor', None)
            if not callable(doctor):
                raise InputError('Backend tidak mendukung doctor')
            status = doctor(manager.settings)
            _print(status, as_json=args.json)
            ok = bool(status.get('ok')) if isinstance(status, dict) else False
            return EXIT_OK if ok else EXIT_ERROR

        raise InputError('Perintah tidak valid')

    except Conflict as exc:
        sys.stderr.write(str(exc) + '\n')
        return EXIT_CONFLICT
    except NotFound as exc:
        sys.stderr.write(str(exc) + '\n')
        return EXIT_NOT_FOUND
    except InputError as exc:
        sys.stderr.write(str(exc) + '\n')
        return EXIT_INPUT
    except TunnelCtlError as exc:
        sys.stderr.write(str(exc) + '\n')
        return EXIT_ERROR
    except Exception:
        sys.stderr.write('Kesalahan runtime tidak terduga\n')
        return EXIT_ERROR
    finally:
        if manager is not None:
            manager.db.close()


def main():
    raise SystemExit(run())
