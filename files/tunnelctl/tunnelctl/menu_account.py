import json
from pathlib import Path

from . import menu_ui as ui

LINK_LABELS = ('WS TLS (port 443)', 'WS non-TLS (port 80)', 'gRPC TLS (port 443)')


# ---------------------------------------------------------------- tables

def print_accounts(rows, protocol):
    ssh = protocol == 'ssh'
    headers = ['No', 'Username', 'Expired', 'Sisa', 'Status'] + (['Login'] if ssh else ['Kuota', 'IP'])
    widths = [3, 16, 16, 8, 11] + ([5] if ssh else [13, 5])
    body = []
    trial = False
    for index, row in enumerate(rows, 1):
        status = row.get('status', '')
        trial = trial or bool(row.get('is_trial'))
        limit = int(row.get('ip_limit') or 0)
        line = [str(index), row['username'] + ('*' if row.get('is_trial') else ''),
                ui.local_time(row.get('expires_at')), ui.remaining(row.get('expires_at')),
                (ui.STATUS_LABEL.get(status, status), ui.STATUS_COLOR.get(status))]
        if not ssh:
            quota = int(row.get('quota_bytes') or 0)
            used = int(row.get('used_up') or 0) + int(row.get('used_down') or 0)
            line.append(ui.size(used) + '/' + (ui.size(quota) if quota else ui.UNLIMITED))
        line.append(str(limit) if limit else ui.UNLIMITED)
        body.append(line)
    ui.write_lines(ui.table(headers, body, widths, right=(0, len(widths) - 1)))
    if trial:
        ui.write(' * = akun trial')


def show_accounts(protocol, settings_override=None, backend=None, title='', **filters):
    if title:
        ui.title(title)
    try:
        rows = ui.accounts(settings_override, backend, protocol=protocol, **filters)
    except Exception as exc:
        ui.fail('membaca akun: {0}'.format(exc))
        return []
    if not rows:
        ui.write('Tidak ada akun yang sesuai.' if filters.get('expiring_days') else 'Belum ada akun.')
        return []
    print_accounts(rows, protocol)
    counts = {}
    for row in rows:
        label = ui.STATUS_LABEL.get(row['status'], row['status'])
        counts[label] = counts.get(label, 0) + 1
    ui.write('\nTotal {0} akun: {1}'.format(len(rows), ', '.join('{0} {1}'.format(v, k) for k, v in sorted(counts.items()))))
    return rows


def pick_account(protocol, settings_override=None, backend=None, title=''):
    rows = show_accounts(protocol, settings_override, backend, title=title)
    if not rows:
        return None
    ui.write('\nKetik NOMOR atau USERNAME dari tabel (kosong/0 = batal).')
    while True:
        choice = ui.ask('Pilihan: ')
        if choice in ('', '0', 'q', 'Q'):
            return None
        for row in rows:
            if row['username'] == choice:
                return row
        if choice.isdigit() and 1 <= int(choice) <= len(rows):
            return rows[int(choice) - 1]
        ui.write('Tidak ada di tabel, coba lagi.')


ACTIVITY_VIEW = {'active': ('AKTIF TRAFIK', ui.GREEN), 'idle': ('IDLE', ui.YELLOW),
                 'unmeasured': ('BELUM TERUKUR', ui.YELLOW), 'error': ('GAGAL BACA', ui.RED),
                 'offline': ('OFFLINE', None)}
ACTIVITY_ORDER = {'active': 0, 'idle': 1, 'unmeasured': 2, 'error': 3, 'offline': 4}


def fetch_activity(protocol=None, settings_override=None, backend=None):
    """Satu snapshot untuk semua protokol (atau satu protokol). None jika perintah gagal."""
    args = ['account', 'online', '--activity'] + (['--proto', protocol] if protocol else [])
    code, data = ui.run_json(args, settings_override, backend)
    if code != 0 or not isinstance(data, dict) or not isinstance(data.get('items'), list):
        return None
    return data


def _rate(item, interval):
    delta = item.get('delta_bytes')
    if item.get('state') != 'active' or not delta or not interval:
        return ''
    return '{0}B/s'.format(ui.size(delta / float(interval)))


def render_activity(protocol, items, interval):
    """Tabel satu protokol; mengembalikan hitungan status."""
    ssh = protocol == 'ssh'
    counts = dict((state, 0) for state in ACTIVITY_ORDER)
    connections = 0
    ui.title('ONLINE ' + ui.PROTO_NAME[protocol].upper())
    if not items:
        ui.write('Tidak ada akun aktif.')
        return counts, connections
    items = sorted(items, key=lambda i: (ACTIVITY_ORDER.get(i.get('state'), 9), -int(i.get('connected') or 0), i['username']))
    rows = []
    for index, item in enumerate(items, 1):
        state = item.get('state', 'error')
        counts[state] = counts.get(state, 0) + 1
        connected = int(item.get('connected') or 0)
        connections += connected
        limit = int(item.get('ip_limit') or 0)
        over = bool(limit) and connected > limit
        label, color = ACTIVITY_VIEW.get(state, (state, None))
        usage = ('{0}/{1}'.format(connected, limit if limit else ui.UNLIMITED), ui.RED if over else None)
        if ssh:
            rows.append([str(index), item['username'], usage, (label, color), _rate(item, interval)])
        else:
            extra = 'API Xray gagal dibaca' if state == 'error' else ', '.join(item.get('ips') or [])
            rows.append([str(index), item['username'], usage, (label, color), _rate(item, interval), extra])
    if ssh:
        ui.write_lines(ui.table(['No', 'Username', 'Sesi/Lim', 'Status', 'Laju'], rows, [3, 16, 9, 13, 9], right=(0, 2, 4)))
    else:
        ui.write_lines(ui.table(['No', 'Username', 'IP/Lim', 'Status', 'Laju', 'Alamat IP'],
                                rows, [3, 16, 7, 13, 9, 30], right=(0, 2, 4)))
    return counts, connections


def _summary(counts, connections, ssh_only=False):
    connected = counts['active'] + counts['idle'] + counts['unmeasured']
    unit = 'sesi' if ssh_only else 'IP/sesi'
    ui.write(' Aktif trafik  : {0}'.format(counts['active']))
    ui.write(' Idle          : {0}'.format(counts['idle']))
    if counts['unmeasured']:
        ui.write(' Belum terukur : {0}'.format(counts['unmeasured']))
    ui.write(' Terhubung     : {0} akun ({1} {2})'.format(connected, connections, unit))
    ui.write(' Offline       : {0}'.format(counts['offline']))
    if counts['error']:
        ui.write(ui.paint(' Gagal baca    : {0} (bukan berarti offline)'.format(counts['error']), ui.RED))


def online_view(protocol=None, settings_override=None, backend=None):
    """Menu 6 (semua protokol) dan menu protokol > 12. Data diambil sekali per tampilan/reload."""
    protocols = [protocol] if protocol else list(ui.PROTOCOLS)
    while True:
        ui.clear()
        ui.title('CEK USER ONLINE' + (' - ' + ui.PROTO_NAME[protocol].upper() if protocol else ' (SEMUA)'))
        ui.write('Mengamati trafik beberapa detik...')
        data = fetch_activity(protocol, settings_override, backend)
        ui.clear()
        ui.title('CEK USER ONLINE' + (' - ' + ui.PROTO_NAME[protocol].upper() if protocol else ' (SEMUA)'))
        if data is None:
            ui.fail('data online tidak bisa dibaca (lihat pesan di atas).')
        else:
            interval = data.get('interval') or 0
            ui.write('Diamati {0} detik (pukul {1}).'.format(interval, ui.local_time(data.get('measured_at'), '%H:%M:%S')))
            total = dict((state, 0) for state in ACTIVITY_ORDER)
            total_connections = 0
            for proto in protocols:
                ui.write('')
                items = [i for i in data['items'] if i.get('protocol') == proto]
                counts, connections = render_activity(proto, items, interval)
                total_connections += connections
                for key, value in counts.items():
                    total[key] = total.get(key, 0) + value
            ui.write('')
            ui.write(ui.paint('RINGKASAN', ui.CYAN))
            _summary(total, total_connections, ssh_only=protocol == 'ssh')
            if data.get('interfered'):
                ui.note('Catatan: pencatat kuota atau restart Xray terjadi saat pengamatan; sebagian akun bisa '
                        'tampil BELUM TERUKUR. Tekan 1 untuk mengulang.')
            ui.note('IDLE = koneksi masih tercatat tetapi tanpa trafik ')
        ui.write('')
        ui.write(' 1. Reload')
        ui.write(' 0. Kembali' + (' ke menu utama' if not protocol else ''))
        while True:
            choice = ui.ask('Pilih: ')
            if choice == '1':
                break
            if choice in ('0', 'q', 'Q'):
                return
            ui.write('Pilih 1 atau 0.')


# ---------------------------------------------------------------- detail

def detail_rows(detail, server_ip):
    protocol = detail['protocol']
    ssh = protocol == 'ssh'
    status = detail.get('status', '')
    left = ui.remaining(detail.get('expires_at'))
    expiry = '{0} ({1})'.format(ui.local_time(detail.get('expires_at')),
                                'sudah habis' if left == 'habis' else left + ' lagi')
    limit = int(detail.get('ip_limit') or 0)
    ports = detail.get('ports') or {}
    udpgw = ', '.join('127.0.0.1:{0}'.format(p) for p in (detail.get('udpgw') or ports.get('udpgw') or []))
    rows = [('#', 'AKUN ' + ui.PROTO_NAME[protocol].upper()),
            ('Username', detail['username'])]
    if ssh:
        rows.append(('Password', detail.get('secret')))
    elif protocol in ('vmess', 'vless'):
        rows.append(('UUID', detail.get('secret')))
    else:
        rows.append(('Password', detail.get('secret')))
    if protocol == 'ss':
        rows.append(('Metode', detail.get('ss_method')))
    rows += [('Status', ui.STATUS_LABEL.get(status, status), ui.STATUS_COLOR.get(status)),
             ('Jenis', 'trial' if detail.get('is_trial') else 'reguler'),
             ('Dibuat', ui.local_time(detail.get('created_at'))),
             ('Expired', expiry)]
    if detail.get('lock_until') or detail.get('lock_reason'):
        rows.append(('Alasan kunci', detail.get('lock_reason') or '-'))
        rows.append(('Kunci sampai', ui.local_time(detail.get('lock_until')) if detail.get('lock_until') else 'dibuka manual'))
    if ssh:
        rows += [('Limit login', '{0} sesi bersamaan'.format(limit) if limit else 'tanpa batas'),
                 ('Kuota', 'tidak didukung untuk SSH')]
    else:
        quota = int(detail.get('quota_bytes') or 0)
        used = int(detail.get('used_up') or 0) + int(detail.get('used_down') or 0)
        usage = '{0} / {1}'.format(ui.size(used), ui.size(quota) if quota else 'tanpa batas')
        if quota:
            usage += ' ({0:.0f}%)'.format(100.0 * used / quota)
        rows += [('Kuota terpakai', usage),
                 ('Upload / Download', '{0} / {1}'.format(ui.size(detail.get('used_up')), ui.size(detail.get('used_down')))),
                 ('Limit IP', '{0} IP'.format(limit) if limit else 'tanpa batas')]
    if detail.get('note'):
        rows.append(('Catatan', detail['note']))
    rows += [('#', 'KONEKSI'),
             ('Domain', detail.get('domain')),
             ('IP server', server_ip)]
    if ssh:
        rows += [('SSH WS (HTTP)', ports.get('http', 80)),
                 ('SSH WS (TLS)', ports.get('https', 443)),
                 ('SSH-SSL', ports.get('https', 443))]
    else:
        rows += [('Port TLS', ports.get('https', 443)),
                 ('Port non-TLS', ports.get('http', 80)),
                 ('Path WebSocket', detail.get('ws_path'))]
        if detail.get('grpc_name'):
            rows.append(('gRPC serviceName', detail.get('grpc_name')))
    rows.append(('UDPGW', udpgw or '-'))
    return rows


def detail_extra_lines(detail):
    """Links and payloads stay outside the table so they can be copied intact."""
    lines = []
    if detail['protocol'] == 'ssh':
        lines.append('Contoh payload ([host] = domain atau IP server; [crlf] = baris baru):')
        for index, payload in enumerate(detail.get('payloads') or [], 1):
            lines += ['', ' {0}. {1}'.format(index, payload)]
    else:
        lines.append('Link akun:')
        for index, link in enumerate(detail.get('links') or []):
            label = LINK_LABELS[index] if index < len(LINK_LABELS) else 'Link {0}'.format(index + 1)
            lines += ['', ' [{0}]'.format(label), ' ' + link]
    warnings = detail.get('warnings') or []
    if warnings:
        lines += ['', 'Catatan:'] + [' - ' + item for item in warnings]
    return lines


def show_detail(protocol, username, settings_override=None, backend=None, offer_extras=True, event='detail'):
    code, detail = ui.run_json(['account', 'show', '--proto', protocol, '--user', username], settings_override, backend)
    if code != 0 or not isinstance(detail, dict):
        return
    server_ip = ui.server_ip(allow_network=True)
    rows = detail_rows(detail, server_ip)
    ui.write_lines(ui.box(rows))
    extra = detail_extra_lines(detail)
    ui.write('')
    ui.write_lines(extra)
    ui.write('')
    try:
        from . import menu_telegram
        menu_telegram.notify_account(detail, server_ip, event, settings_override)
    except Exception as exc:  # Telegram must never break the account menu
        ui.write(ui.paint('Telegram: dilewati ({0}).'.format(type(exc).__name__), ui.YELLOW))
    if not offer_extras:
        return
    if protocol != 'ssh' and detail.get('client_config') and ui.ask_yes('\nTampilkan contoh config JSON klien (WS port 80)? [y/N]: '):
        ui.write(json.dumps(detail['client_config'], indent=2))
        ui.write('ADDRESS = IP VPS atau IP Cloudflare; HOST = domain/Host header pilihan.')
    conf = ui.settings(settings_override)
    target = Path(conf.get('exports_dir', '/var/lib/tunnel/exports')) / '{0}-{1}.txt'.format(protocol, username)
    if ui.ask_yes('Simpan detail ke {0}? [y/N]: '.format(target)):
        from .system import atomic_write
        content = ui.box(rows, color=False) + [''] + extra
        if protocol != 'ssh' and detail.get('client_config'):
            content += ['', 'Contoh config klien (WS port 80):', json.dumps(detail['client_config'], indent=2)]
        try:
            atomic_write(target, '\n'.join(content) + '\n')
            ui.ok('tersimpan di {0} (mode 0600)'.format(target))
        except Exception as exc:
            ui.fail('menyimpan file: {0}'.format(exc))


def current_box(account, fields):
    labels = {
        'expires_at': ('Expired saat ini', lambda a: '{0} ({1})'.format(ui.local_time(a['expires_at']), ui.remaining(a['expires_at']))),
        'status': ('Status saat ini', lambda a: ui.STATUS_LABEL.get(a['status'], a['status'])),
        'lock': ('Info kunci', lambda a: '{0}; sampai {1}'.format(a.get('lock_reason') or '-', ui.local_time(a['lock_until']) if a.get('lock_until') else 'dibuka manual')),
        'quota': ('Kuota saat ini', lambda a: '{0} (terpakai {1})'.format(
            ui.size(a['quota_bytes']) if int(a.get('quota_bytes') or 0) else 'tanpa batas',
            ui.size(int(a.get('used_up') or 0) + int(a.get('used_down') or 0)))),
        'limit': ('Limit saat ini', lambda a: str(a['ip_limit']) if int(a.get('ip_limit') or 0) else 'tanpa batas'),
        'usage': ('Pemakaian saat ini', lambda a: 'upload {0} / download {1}'.format(ui.size(a.get('used_up')), ui.size(a.get('used_down')))),
        'secret': ('Nilai saat ini', lambda a: a.get('secret') or '-'),
    }
    rows = [('#', 'AKUN: ' + account['username'])]
    for field in fields:
        label, render = labels[field]
        rows.append((label, render(account)))
    ui.write_lines(ui.box(rows))


# ---------------------------------------------------------------- actions

def _report(code, data, protocol, message):
    if code != 0:
        ui.fail('perintah ditolak (lihat pesan di atas).')
        return
    ui.write('')
    ui.ok(message)
    if isinstance(data, dict) and 'username' in data:
        ui.write('')
        print_accounts([data], protocol)


def create_account(name, protocol, trial, settings_override=None, backend=None):
    ssh = protocol == 'ssh'
    conf = ui.settings(settings_override)
    defaults = conf.get('defaults', {})
    ui.title('BUAT AKUN {0}{1}'.format('TRIAL ' if trial else '', name.upper()))
    user = ui.ask_username()
    if not user:
        ui.write('Dibatalkan.')
        return
    args = ['account', 'create', '--proto', protocol, '--user', user]
    if protocol in ('ssh', 'trojan', 'ss'):
        secret = ui.ask('Password (kosong = dibuat acak): ')
        if secret:
            args += ['--pass', secret]
    if trial:
        hours = ui.ask_int('Durasi trial dalam jam [{0}]: '.format(defaults.get('trial_hours', 1)),
                           default=int(defaults.get('trial_hours', 1)))
        args += ['--trial', '--hours', str(hours)]
    else:
        days = ui.ask_int('Masa aktif dalam hari [{0}]: '.format(defaults.get('days', 30)),
                          default=int(defaults.get('days', 30)))
        args += ['--days', str(days)]
    default_limit = int(defaults.get('ip_limit', 0) or 0)
    limit = ui.ask_int('Limit {0} (0 = tanpa batas) [{1}]: '.format('login' if ssh else 'IP', default_limit),
                       minimum=0, default=default_limit)
    args += ['--limit', str(limit)]
    if not ssh:
        try:
            from .util import parse_size
            default_quota = parse_size(defaults.get('quota_bytes', 0)) or 0
        except Exception:
            default_quota = 0
        quota = ui.ask_quota('Kuota (mis. 30G, 500M; 0 = tanpa batas) [{0}]: '.format(
            ui.size(default_quota) if default_quota else 'tanpa batas'))
        if quota is not None:
            args += ['--quota', quota]
    code, data = ui.run_json(args, settings_override, backend)
    if code != 0:
        ui.fail('akun tidak dibuat (lihat pesan di atas).')
        return
    ui.write('')
    ui.ok('akun {0} dibuat.'.format(user))
    ui.write('')
    show_detail(protocol, user, settings_override, backend, event='create')


def account_action(choice, account, protocol, settings_override=None, backend=None):
    user = account['username']
    target = ['--proto', protocol, '--user', user]

    def call(args, message, json_flag=True):
        code, data = ui.run_json(args, settings_override, backend, json_flag)
        _report(code, data, protocol, message)
        return code, data

    ui.write('')
    if choice == '3':
        current_box(account, ['status', 'expires_at'])
        ui.note('Jika belum habis, hari ditambahkan ke tanggal expired; jika sudah habis, dihitung dari sekarang.')
        days = ui.ask_int('Tambah berapa hari? (kosong = batal): ')
        if days:
            call(['account', 'renew'] + target + ['--days', str(days)], '{0} diperpanjang {1} hari'.format(user, days))
    elif choice == '4':
        current_box(account, ['status', 'expires_at'])
        if ui.ask_yes('Yakin hapus akun {0}? Tindakan ini permanen. [y/N]: '.format(user)):
            call(['account', 'delete'] + target + ['--yes'], 'akun {0} dihapus'.format(user), json_flag=False)
    elif choice == '5':
        locked = account['status'] in ('locked', 'limit_locked')
        current_box(account, ['status', 'lock'] if locked else ['status'])
        if locked:
            if ui.ask_yes('Akun sedang terkunci. Buka kunci sekarang? [y/N]: '):
                call(['account', 'unlock'] + target, 'kunci {0} dibuka'.format(user))
        elif ui.ask_yes('Kunci akun {0}? [y/N]: '.format(user)):
            minutes = ui.ask_int('Berapa menit? (kosong = sampai dibuka manual): ')
            args = ['account', 'lock'] + target + (['--minutes', str(minutes)] if minutes else [])
            call(args, '{0} dikunci'.format(user) + (' {0} menit'.format(minutes) if minutes else ''))
    elif choice == '6':
        code, detail = ui.run_json(['account', 'show'] + target, settings_override, backend)
        if code != 0 or not isinstance(detail, dict):
            return
        current_box(detail, ['secret'])
        if protocol in ('vmess', 'vless'):
            if ui.ask_yes('Buat UUID baru secara acak? [Y/n]: ', default=True):
                args = ['--regen']
            else:
                value = ui.ask('UUID baru (kosong = batal): ')
                args = ['--uuid', value] if value else None
        else:
            value = ui.ask('Password baru (kosong = batal): ')
            args = ['--pass', value] if value else None
        if args:
            code, data = call(['account', 'update'] + target + args, 'kredensial {0} diganti'.format(user))
            if code == 0 and isinstance(data, dict):
                ui.write('Nilai lama : {0}'.format(detail.get('secret')))
                ui.write('Nilai baru : {0}'.format(data.get('secret')))
                ui.note('Klien harus memakai nilai baru; link lama tidak berlaku lagi.')
    elif choice == '7':
        current_box(account, ['quota', 'status'])
        quota = ui.ask_quota('Kuota baru (mis. 30G, 500M; 0 = tanpa batas; kosong = batal): ')
        if quota:
            call(['account', 'update'] + target + ['--quota', quota], 'kuota {0} menjadi {1}'.format(user, quota))
    elif choice == '8':
        current_box(account, ['limit'])
        limit = ui.ask_int('Limit baru (0 = tanpa batas; kosong = batal): ', minimum=0)
        if limit is not None:
            call(['account', 'update'] + target + ['--limit', str(limit)], 'limit {0} menjadi {1}'.format(user, limit))
    elif choice == '9':
        current_box(account, ['usage', 'quota'])
        if ui.ask_yes('Reset pemakaian {0} ke 0? [y/N]: '.format(user)):
            call(['account', 'reset-usage'] + target, 'pemakaian {0} direset'.format(user))
    elif choice == '10':
        show_detail(protocol, user, settings_override, backend)


# ---------------------------------------------------------------- menu

def account_menu(protocol, settings_override=None, backend=None):
    ssh = protocol == 'ssh'
    name = ui.PROTO_NAME[protocol]
    titles = {'3': 'PERPANJANG AKUN', '4': 'HAPUS AKUN', '5': 'KUNCI / BUKA AKUN',
              '6': 'UBAH UUID' if protocol in ('vmess', 'vless') else 'UBAH PASSWORD',
              '7': 'UBAH KUOTA', '8': 'UBAH LIMIT ' + ('LOGIN' if ssh else 'IP'),
              '9': 'RESET PEMAKAIAN', '10': 'DETAIL AKUN'}
    items = (' 1. Buat akun', ' 2. Buat trial', ' 3. Perpanjang akun', ' 4. Hapus akun',
             ' 5. Kunci/Buka akun', ' 6. Ubah ' + ('UUID' if protocol in ('vmess', 'vless') else 'password'),
             ' 7. Ubah kuota' + (' (tidak didukung untuk SSH)' if ssh else ''),
             ' 8. Ubah limit ' + ('login' if ssh else 'IP'), ' 9. Reset pemakaian' + (' (tidak berlaku untuk SSH)' if ssh else ''),
             '10. Detail akun', '11. Daftar akun', '12. Cek online', '13. Daftar hampir expired',
             ' 0. Kembali')
    while True:
        ui.clear()
        ui.title('MENU ' + name.upper())
        ui.write_lines(items)
        choice = ui.ask('Pilih: ')
        if choice in ('0', 'q', 'Q'):
            return
        ui.clear()
        if choice in ('1', '2'):
            create_account(name, protocol, choice == '2', settings_override, backend)
        elif choice in ('7', '9') and ssh:
            ui.write('Kuota/pemakaian tidak didukung untuk SSH: trafik tunnel Dropbear tidak bisa dihitung per akun.')
        elif choice in titles:
            account = pick_account(protocol, settings_override, backend, titles[choice] + ' - ' + name.upper())
            if account is None:
                ui.write('Dibatalkan.')
            else:
                account_action(choice, account, protocol, settings_override, backend)
        elif choice == '11':
            show_accounts(protocol, settings_override, backend, title='DAFTAR AKUN ' + name.upper())
        elif choice == '12':
            online_view(protocol, settings_override, backend)
            continue
        elif choice == '13':
            days = ui.ask_int('Tampilkan yang habis dalam berapa hari? [3]: ', default=3)
            ui.clear()
            show_accounts(protocol, settings_override, backend,
                          title='HAMPIR EXPIRED (<= {0} HARI) - {1}'.format(days, name.upper()), expiring_days=days)
        else:
            ui.write('Pilihan tidak valid.')
        ui.pause()
