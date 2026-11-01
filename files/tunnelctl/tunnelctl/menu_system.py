"""System menu: every view is a table, every change shows the current value first."""
import json
import os
import re
import shutil
import signal
import subprocess
from pathlib import Path

from . import menu_info as info
from . import menu_ui as ui

RESTARTABLE = [('haproxy', 'SEMUA koneksi klien putus sesaat'),
               ('xray', 'koneksi VMess/VLESS/Trojan/SS putus'),
               ('ws-epro', 'koneksi SSH WebSocket putus'),
               ('dropbear-tunnel', 'SEMUA sesi SSH putus'),
               ('nginx', 'gRPC & situs kamuflase putus sesaat'),
               ('tunnel-firewall', 'aturan firewall dimuat ulang'),
               ('chrony', 'aman'),
               ('vnstat', 'aman')]
CHECK_LABEL = {'services': 'Service wajib aktif', 'db': 'Database akun', 'ports': 'Port & listener',
               'cert': 'Sertifikat TLS', 'time': 'Sinkron waktu', 'configs': 'Validasi config'}


def _service_table(conf):
    services = info.core_services(conf) + info.SUPPORT_SERVICES
    states = ui.unit_states([unit for unit, _ in services])
    rows = []
    for index, (unit, label) in enumerate(services, 1):
        state = states[unit]
        rows.append([str(index), unit, label, ui.state_label(state),
                     ui.short_ts(state.get('ActiveEnterTimestamp')), ui.memory(state)])
    ui.write_lines(ui.table(['No', 'Service', 'Fungsi', 'Status', 'Aktif sejak', 'Memori'],
                            rows, [2, 18, 19, 9, 16, 6], right=(0, 5)))


def _timer_table():
    states = ui.unit_states([unit for unit, _ in info.TIMERS])
    rows = []
    for unit, label in info.TIMERS:
        state = states[unit]
        rows.append([unit.replace('.timer', ''), label, ui.state_label(state),
                     ui.short_ts(state.get('LastTriggerUSec')), ui.short_ts(state.get('NextElapseUSecRealtime'))])
    ui.write_lines(ui.table(['Timer', 'Fungsi', 'Status', 'Terakhir jalan', 'Berikutnya'],
                            rows, [17, 16, 9, 16, 16]))


def status(settings_override=None, backend=None):
    conf = ui.settings(settings_override)
    ui.title('STATUS SERVICE')
    _service_table(conf)
    ui.write('')
    ui.title('TIMER OTOMATIS')
    _timer_table()


def restart(settings_override=None, backend=None):
    def show():
        states = ui.unit_states([unit for unit, _ in RESTARTABLE])
        rows = [[str(i), unit, ui.state_label(states[unit]), effect] for i, (unit, effect) in enumerate(RESTARTABLE, 1)]
        ui.write_lines(ui.table(['No', 'Service', 'Status', 'Dampak restart'], rows, [2, 16, 9, 46], right=(0,)))
    ui.title('RESTART SERVICE')
    show()
    choice = ui.ask('\nPilih NOMOR, atau "a" untuk semua (kosong = batal): ').lower()
    if not choice:
        ui.write('Dibatalkan.')
        return
    if choice == 'a':
        service, effect = 'all', 'SEMUA service di atas di-restart; semua klien putus sesaat'
    elif choice.isdigit() and 1 <= int(choice) <= len(RESTARTABLE):
        service, effect = RESTARTABLE[int(choice) - 1]
    else:
        ui.write('Pilihan tidak valid.')
        return
    ui.write('Dampak: ' + effect)
    if not ui.ask_yes('Restart {0}? [y/N]: '.format(service)):
        ui.write('Dibatalkan.')
        return
    code, _ = ui.run_json(['system', 'restart', service], settings_override, backend)
    if code == 0:
        ui.ok('{0} di-restart. Status terbaru:'.format(service))
        ui.write('')
        show()


def system_info(settings_override=None, backend=None):
    ui.title('INFO SISTEM')
    ui.write_lines(ui.box(info.system_rows(info.system_facts())))


DOMAIN_HELPER = '/usr/local/sbin/tunnel-domain-change'
DOMAIN_RE = re.compile(r'^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$')
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$')


def _inventory_state():
    """Current inventory values via the helper (domain may be empty = IP mode)."""
    code, out, _ = ui.sh([DOMAIN_HELPER, '--show'], timeout=15)
    try:
        return json.loads(out) if code == 0 else {}
    except ValueError:
        return {}


def _run_helper(args):
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        return subprocess.call([DOMAIN_HELPER] + args)
    finally:
        signal.signal(signal.SIGINT, previous)


def _domain_cert_rows(conf, ip):
    domain = conf.get('domain', '-')
    ip_mode = ui.is_ip(domain)
    cert = info.cert_info(info.cert_path(conf))
    rows = [('#', 'DOMAIN & SERTIFIKAT SAAT INI'),
            ('Domain', 'BELUM DIATUR (memakai IP {0})'.format(domain) if ip_mode else domain,
             ui.YELLOW if ip_mode else None),
            ('IP publik server', ip or '-')]
    if not ip_mode:
        dns = info.dns_lookup(domain)
        match = bool(ip) and ip in dns
        rows.append(('DNS A record', '{0} ({1})'.format(', '.join(dns) or 'tidak ditemukan', 'cocok' if match else 'TIDAK cocok'),
                     ui.GREEN if match else ui.RED))
    rows += info.cert_rows(cert, conf)[1:]
    state = ui.unit_states(['tunnel-acme-renew.timer'])['tunnel-acme-renew.timer']
    if state.get('LoadState') not in ('not-found', 'unknown'):
        rows += [('Renew otomatis', '{0}; berikutnya {1}'.format(ui.state_label(state)[0],
                                                              ui.short_ts(state.get('NextElapseUSecRealtime'))))]
    return rows, ip_mode


def _set_domain(conf, ip, current, ip_mode, inventory):
    ui.title('ATUR / GANTI DOMAIN + SERTIFIKAT LET\'S ENCRYPT')
    ui.write('Langkah sebelum mengisi domain:')
    ui.write('  1. Buat A record domain -> {0} di Cloudflare (DNS only / awan abu-abu).'.format(ip))
    ui.write('  2. Tunggu DNS aktif (biasanya 1-5 menit).')
    ui.write('')
    new = ui.ask_text('Domain {0}(0 = batal): '.format('baru ' if not ip_mode else ''), ui.as_domain, 'vpn.domainanda.com')
    if not new:
        ui.write('Dibatalkan.')
        return
    ui.write('Domain: {0}'.format(new))
    email = ui.as_email(inventory.get('admin_email') or '')
    if not email:
        email = ui.ask_text('Email untuk Let\'s Encrypt (0 = batal): ', ui.as_email, 'admin@domainanda.com')
        if not email:
            ui.write('Dibatalkan.')
            return
    ui.write('Email Let\'s Encrypt: {0}'.format(email))
    dns = info.dns_lookup(new)
    match = bool(ip) and ip in dns
    ui.write_lines(ui.box([('#', 'PEMERIKSAAN DOMAIN'), ('Domain', new), ('IP server', ip or '-'),
                           ('DNS A record', '{0} ({1})'.format(', '.join(dns) or 'tidak ditemukan', 'cocok' if match else 'TIDAK cocok'),
                            ui.GREEN if match else ui.RED)]))
    args = [new, '--cert-mode', 'http01', '--email', email, '--yes']
    if not match:
        ui.write(ui.paint('DNS domain belum mengarah ke server ini.', ui.RED))
        ui.note('Let\'s Encrypt (http01) WAJIB bisa menjangkau domain di port 80. Perbaiki DNS lalu ulangi. '
                'Lewati pemeriksaan hanya jika memakai Cloudflare proxied.')
        if not ui.ask_yes('Tetap lanjut tanpa pemeriksaan DNS/HTTP? [y/N]: '):
            ui.write('Dibatalkan.')
            return
        args.append('--skip-dns-check')
    ui.write('\nYang akan terjadi:')
    for step in ('domain & email disimpan ke inventory (cadangan otomatis dibuat);',
                 'prepare -> site -> commit dijalankan; sertifikat Let\'s Encrypt diterbitkan;',
                 'port 443 sempat terputus beberapa saat selama penerbitan sertifikat;',
                 'jika gagal, setelan lama dipulihkan otomatis;',
                 'link semua akun berubah ke domain ini (bagikan ulang ke pelanggan).'):
        ui.write('  - ' + step)
    ui.note('Perkiraan 3-10 menit. Jangan tutup terminal; sebaiknya jalankan menu di dalam tmux.')
    if not ui.ask_yes('Mulai? [y/N]: '):
        ui.write('Dibatalkan.')
        return
    code = _run_helper(args)
    ui.write('')
    rows, _ = _domain_cert_rows(ui.settings(), ip)
    ui.write_lines(ui.box(rows))
    (ui.ok if code == 0 else ui.fail)('domain & sertifikat diperbarui.' if code == 0 else 'proses tidak selesai (lihat keluaran di atas).')


def _issue_for_current(conf, ip, current, inventory):
    ui.title('TERBITKAN SERTIFIKAT LET\'S ENCRYPT UNTUK {0}'.format(current))
    email = ui.as_email(inventory.get('admin_email') or '')
    if not email:
        email = ui.ask_text('Email untuk Let\'s Encrypt (0 = batal): ', ui.as_email, 'admin@domainanda.com')
        if not email:
            ui.write('Dibatalkan.')
            return
    if not ui.ask_yes('Ganti sertifikat selfsigned {0} dengan Let\'s Encrypt? [y/N]: '.format(current)):
        ui.write('Dibatalkan.')
        return
    code = _run_helper([current, '--cert-mode', 'http01', '--email', email, '--yes'])
    (ui.ok if code == 0 else ui.fail)('sertifikat diterbitkan.' if code == 0 else 'penerbitan gagal (lihat keluaran di atas).')


def _renew_now():
    ui.title('PERPANJANG SERTIFIKAT SEKARANG')
    ui.note('acme.sh hanya memperbarui jika sertifikat tinggal <= 30 hari; di luar itu pengecekan dilewati.')
    if not ui.ask_yes('Jalankan pengecekan perpanjangan sekarang? [y/N]: '):
        return
    code, _, _ = ui.sh(['systemctl', 'start', 'tunnel-acme-renew.service'], timeout=300)
    _, log, _ = ui.sh(['journalctl', '-u', 'tunnel-acme-renew.service', '-n', '12', '--no-pager', '-o', 'cat'])
    ui.write_lines(['  ' + line for line in log.splitlines()])
    (ui.ok if code == 0 else ui.fail)('pengecekan selesai' if code == 0 else 'pengecekan gagal (lihat log di atas)')


def domain_cert(settings_override=None, backend=None):
    while True:
        ui.clear()
        conf = ui.settings(settings_override)
        ip = ui.server_ip(allow_network=True)
        ui.title('DOMAIN & SERTIFIKAT TLS')
        rows, ip_mode = _domain_cert_rows(conf, ip)
        ui.write_lines(ui.box(rows))
        helper = os.path.exists(DOMAIN_HELPER)
        if not helper:
            ui.write('')
            ui.write('Server ini dikelola dari controller terpisah. Ubah tunnel_domain/cert_mode/admin_email')
            ui.write('di inventory controller, lalu jalankan prepare-server.yml, site.yml, commit-server.yml.')
            return
        inventory = _inventory_state()
        current = conf.get('domain', '')
        selfsigned_domain = not ip_mode and conf.get('cert_mode') == 'selfsigned'
        acme = not ip_mode and conf.get('cert_mode') in ('http01', 'dns_cloudflare')
        items = [('1', 'Atur domain + sertifikat Let\'s Encrypt' if ip_mode else 'Ganti domain + sertifikat Let\'s Encrypt')]
        if selfsigned_domain:
            items.append(('2', 'Terbitkan sertifikat Let\'s Encrypt untuk domain saat ini'))
        if acme:
            items.append(('3', 'Perpanjang sertifikat sekarang (cek renew)'))
        for key, label in items:
            ui.write(' {0}. {1}'.format(key, label))
        ui.write(' 0. Kembali')
        choice = ui.ask('Pilih: ')
        if choice in ('', '0', 'q', 'Q'):
            return
        ui.clear()
        if choice == '1':
            _set_domain(conf, ip, current, ip_mode, inventory)
        elif choice == '2' and selfsigned_domain:
            _issue_for_current(conf, ip, current, inventory)
        elif choice == '3' and acme:
            _renew_now()
        else:
            ui.write('Pilihan tidak valid.')
        ui.pause()


def _mbps(section):
    return '{0:.2f} Mbps'.format(float((section or {}).get('bandwidth', 0)) * 8 / 1e6)


def speedtest(settings_override=None, backend=None):
    ui.title('SPEEDTEST (OOKLA)')
    binary = shutil.which('speedtest')
    code, out, _ = ui.sh([binary, '--version'], timeout=10) if binary else (1, '', '')
    if not binary or 'Ookla' not in out:
        ui.fail('Speedtest Ookla belum terpasang.')
        ui.note('Pasang dengan: .venv/bin/ansible-playbook playbooks/prepare-speedtest.yml (dari folder repo).')
        return
    base = [binary, '--accept-license', '--accept-gdpr']
    ui.write(' 1. Server otomatis (terdekat)')
    ui.write(' 2. Pilih dari daftar server terdekat')
    choice = ui.ask('Pilih [1]: ') or '1'
    server_args = []
    if choice == '2':
        ui.write('Mengambil daftar server...')
        code, out, err = ui.sh(base + ['--servers', '--format=json'], timeout=60)
        try:
            servers = json.loads(out).get('servers', [])
        except ValueError:
            servers = []
        if not servers:
            ui.fail('daftar server tidak bisa diambil.')
            return
        rows = [[str(i), str(s.get('id')), s.get('name', '-'), s.get('location', '-'), s.get('country', '-')]
                for i, s in enumerate(servers[:15], 1)]
        ui.write_lines(ui.table(['No', 'ID', 'Penyedia', 'Lokasi', 'Negara'], rows, [3, 7, 26, 20, 14], right=(0,)))
        pick = ui.ask_int('Pilih NOMOR (kosong = batal): ')
        if not pick or pick > len(rows):
            ui.write('Dibatalkan.')
            return
        server_args = ['--server-id', rows[pick - 1][1]]
    ui.note('Pengukuran memakai beberapa ratus MB kuota server dan bisa sedikit memperlambat klien selama ~30 detik.')
    ui.write('Mengukur... (20-60 detik)')
    code, out, err = ui.sh(base + ['--format=json', '--progress=no'] + server_args, timeout=180)
    try:
        result = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except (ValueError, IndexError):
        result = {}
    if code != 0 or result.get('type') != 'result':
        ui.fail('speedtest gagal.')
        ui.write((err or out).strip()[-600:])
        return
    server = result.get('server', {})
    ping = result.get('ping', {})
    loss = result.get('packetLoss')
    rows = [('#', 'HASIL SPEEDTEST'),
            ('Server', '{0} - {1}, {2} (id {3})'.format(server.get('name', '-'), server.get('location', '-'),
                                                      server.get('country', '-'), server.get('id', '-'))),
            ('ISP', result.get('isp', '-')),
            ('IP publik', (result.get('interface') or {}).get('externalIp', '-')),
            ('Ping', '{0:.1f} ms (jitter {1:.1f} ms)'.format(float(ping.get('latency', 0)), float(ping.get('jitter', 0)))),
            ('Download', _mbps(result.get('download')), ui.GREEN),
            ('Upload', _mbps(result.get('upload')), ui.GREEN),
            ('Packet loss', '{0:.1f}%'.format(float(loss)) if loss is not None else '-'),
            ('Data terpakai', '{0} unduh / {1} unggah'.format(ui.size((result.get('download') or {}).get('bytes')),
                                                             ui.size((result.get('upload') or {}).get('bytes')))),
            ('Link hasil', (result.get('result') or {}).get('url', '-'))]
    ui.write_lines(ui.box(rows))
    try:
        from . import menu_telegram as tg
        data = tg.load(settings_override)
        if tg.enabled(data) and ui.ask_yes('Kirim hasil ke Telegram? [y/N]: '):
            text = '\U0001F4F6 <b>Speedtest server</b>\n' + '\n'.join(
                '<b>{0}</b> : {1}'.format(tg._e(r[0]), tg._e(r[1])) for r in rows if r[0] != '#') + tg._footer()
            ok, reason = tg.send(data, text)
            (ui.ok if ok else ui.fail)('terkirim ke Telegram.' if ok else 'gagal kirim: {0}'.format(reason))
    except Exception as exc:
        ui.write(ui.paint('Telegram dilewati ({0}).'.format(type(exc).__name__), ui.YELLOW))


def banner(settings_override=None, backend=None):
    conf = ui.settings(settings_override)
    path = conf.get('banner_path', '/etc/tunnel/banner.txt')
    try:
        current = Path(path).read_text().rstrip('\n')
    except OSError:
        current = ''
    ui.title('BANNER SSH')
    rows = [('#', 'BANNER SAAT INI'), ('File', path)]
    for index, line in enumerate(current.splitlines() or ['(kosong)'], 1):
        rows.append(('Baris {0}'.format(index), line))
    ui.write_lines(ui.box(rows))
    ui.note('Catatan: menjalankan ulang site.yml akan mengembalikan banner ke nilai inventory (dropbear_banner).')
    ui.write('\nKetik banner baru. Akhiri dengan baris berisi titik (.) saja. Baris pertama kosong = batal.')
    lines = []
    while True:
        line = ui.ask('> ')
        if not lines and not line:
            ui.write('Dibatalkan.')
            return
        if line == '.':
            break
        lines.append(line)
    text = '\n'.join(lines)
    ui.write_lines(ui.box([('#', 'BANNER BARU')] + [('Baris {0}'.format(i), l) for i, l in enumerate(lines, 1)]))
    if not ui.ask_yes('Simpan banner ini? [y/N]: '):
        ui.write('Dibatalkan.')
        return
    code, _ = ui.run_json(['system', 'banner', 'edit', '--text', text], settings_override, backend)
    if code != 0:
        return
    ui.ok('banner disimpan.')
    ui.note('Dropbear membaca banner saat start. Restart dropbear-tunnel agar berlaku; SEMUA sesi SSH aktif akan putus.')
    if ui.ask_yes('Restart dropbear-tunnel sekarang? [y/N]: '):
        code, _ = ui.run_json(['system', 'restart', 'dropbear-tunnel'], settings_override, backend)
        if code == 0:
            ui.ok('dropbear-tunnel di-restart; banner baru aktif.')


def bandwidth(mode, settings_override=None, backend=None):
    flag = '--monthly' if mode == 'monthly' else '--daily'
    ui.title('BANDWIDTH ' + ('BULANAN' if mode == 'monthly' else 'HARIAN') + ' (vnstat)')
    code, data = ui.run_json(['system', 'bandwidth', flag], settings_override, backend)
    if code != 0 or not isinstance(data, dict):
        return
    stats = data.get('data') or {}
    factor = 1024 if str(stats.get('jsonversion', '2')) == '1' else 1
    found = False
    for iface in stats.get('interfaces', []):
        traffic = iface.get('traffic', {})
        if mode == 'monthly':
            entries = (traffic.get('month') or traffic.get('months') or [])[-12:]
        else:
            entries = (traffic.get('day') or traffic.get('days') or [])[-14:]
        if not entries:
            continue
        found = True
        rows = []
        total_rx = total_tx = 0
        for entry in entries:
            date = entry.get('date', {})
            label = '{0:04d}-{1:02d}'.format(date.get('year', 0), date.get('month', 0))
            if mode != 'monthly':
                label += '-{0:02d}'.format(date.get('day', 0))
            rx, tx = entry.get('rx', 0) * factor, entry.get('tx', 0) * factor
            total_rx += rx
            total_tx += tx
            rows.append([label, ui.size(rx), ui.size(tx), ui.size(rx + tx)])
        rows.append([('Jumlah', ui.CYAN), (ui.size(total_rx), ui.CYAN), (ui.size(total_tx), ui.CYAN), (ui.size(total_rx + total_tx), ui.CYAN)])
        ui.write('Interface: {0}'.format(iface.get('name', '?')))
        ui.write_lines(ui.table(['Periode', 'Masuk (rx)', 'Keluar (tx)', 'Total'], rows, [12, 12, 12, 12], right=(1, 2, 3)))
        ui.write('')
    if not found:
        ui.write('Data vnstat belum tersedia (vnstat butuh beberapa menit setelah instalasi).')


def logs(settings_override=None, backend=None):
    conf = ui.settings(settings_override)
    units = [unit for unit, _ in info.core_services(conf)] + ['tunnel-firewall', 'fail2ban',
             'tunnel-usage.service', 'tunnel-limit.service', 'tunnel-expiry.service',
             'tunnel-backup.service', 'tunnel-acme-renew.service']
    states = ui.unit_states(units)
    rows = [[str(i), unit, ui.state_label(states[unit])] for i, unit in enumerate(units, 1)]
    ui.title('LOG SERVICE')
    ui.write_lines(ui.table(['No', 'Unit', 'Status'], rows, [2, 28, 9], right=(0,)))
    choice = ui.ask('\nPilih NOMOR (kosong = batal): ')
    if not (choice.isdigit() and 1 <= int(choice) <= len(units)):
        ui.write('Dibatalkan.')
        return
    unit = units[int(choice) - 1]
    count = ui.ask_int('Jumlah baris terakhir [40]: ', default=40)
    _, out, _ = ui.sh(['journalctl', '-u', unit, '-n', str(count), '--no-pager', '-o', 'short-iso'], timeout=30)
    ui.title('LOG ' + unit)
    ui.write(out.rstrip() or '(log kosong)')
    if ui.ask_yes('\nIkuti log secara langsung (Ctrl+C untuk berhenti)? [y/N]: '):
        try:
            subprocess.call(['journalctl', '-u', unit, '-f', '-n', '0', '--no-pager', '-o', 'short-iso'])
        except KeyboardInterrupt:
            ui.write('')


HHMM_RE = re.compile(r'^([01][0-9]|2[0-3]):[0-5][0-9]$')


def autoreboot(settings_override=None, backend=None):
    while True:
        ui.clear()
        ui.title('AUTO-REBOOT')
        code, state = ui.run_json(['system', 'autoreboot', 'status'], settings_override, backend)
        if code != 0 or not isinstance(state, dict):
            return
        facts = info.system_facts()
        tz = facts.get('timezone') or '-'
        on = bool(state.get('enabled') and state.get('active'))
        rows = [('#', 'AUTO-REBOOT HARIAN'),
                ('Status', 'AKTIF' if on else 'mati', ui.GREEN if on else None),
                ('Jam reboot', '{0} ({1})'.format(state['time'], tz) if on and state.get('time') else '-'),
                ('Reboot berikutnya', ui.short_ts(state.get('next')) if on else '-'),
                ('Uptime saat ini', ui.duration(facts['uptime']) if facts.get('uptime') is not None else '-')]
        if not state.get('installed'):
            rows.append(('Unit timer', 'BELUM terpasang', ui.YELLOW))
        ui.write_lines(ui.box(rows))
        if not state.get('installed'):
            ui.note('Unit tunnel-autoreboot belum dipasang. Jalankan ulang: bash bootstrap.sh (dari folder repo).')
            return
        ui.note('Reboot memutus semua koneksi pelanggan sekitar 1-2 menit. Pilih jam paling sepi. '
                'Server tidak akan reboot jika baru menyala kurang dari 15 menit.')
        ui.write(' 1. {0} jam reboot harian'.format('Ubah' if on else 'Atur'))
        if on:
            ui.write(' 2. Matikan auto-reboot')
        ui.write(' 0. Kembali')
        choice = ui.ask('Pilih: ')
        if choice in ('', '0', 'q', 'Q'):
            return
        if choice == '1':
            current = state.get('time') if on else None
            if current:
                ui.write('Jam saat ini: {0} ({1})'.format(current, tz))
            value = ui.ask('Jam reboot harian HH:MM, waktu server {0} [{1}] (q = batal): '.format(tz, current or '04:00'))
            if value.lower() == 'q':
                ui.write('Dibatalkan.')
            else:
                value = value or current or '04:00'
                if not HHMM_RE.match(value):
                    ui.fail('format jam harus HH:MM, contoh 04:00.')
                elif ui.ask_yes('Server akan reboot setiap hari pukul {0} ({1}). Lanjutkan? [y/N]: '.format(value, tz)):
                    code, result = ui.run_json(['system', 'autoreboot', 'set', value], settings_override, backend)
                    if code == 0 and isinstance(result, dict):
                        ui.ok('auto-reboot aktif pukul {0}; berikutnya {1}.'.format(value, ui.short_ts(result.get('next'))))
                else:
                    ui.write('Dibatalkan.')
        elif choice == '2' and on:
            if ui.ask_yes('Matikan auto-reboot? [y/N]: '):
                code, _ = ui.run_json(['system', 'autoreboot', 'off'], settings_override, backend)
                if code == 0:
                    ui.ok('auto-reboot dimatikan.')
            else:
                ui.write('Dibatalkan.')
        else:
            ui.write('Pilihan tidak valid.')
        ui.pause()


def _log_sizes():
    rows = []
    _, out, _ = ui.sh(['journalctl', '--disk-usage'])
    match = re.search(r'take up ([0-9.]+\s*[A-Za-z]+)', out)
    rows.append(['journal (systemd)', match.group(1) if match else '-'])
    for directory in ('/var/log/xray', '/var/log/nginx'):
        for path in sorted(Path(directory).glob('*.log')):
            try:
                rows.append([str(path), ui.size(path.stat().st_size)])
            except OSError:
                pass
    return rows


def clean_logs(settings_override=None, backend=None):
    ui.title('BERSIHKAN LOG')
    ui.write_lines(ui.table(['Log', 'Ukuran saat ini'], _log_sizes(), [40, 16], right=(1,)))
    ui.note('Yang dibersihkan: journal lebih tua dari 7 hari, dan isi /var/log/xray/access.log & error.log dikosongkan. '
            'Data akun dan pemakaian kuota tidak terpengaruh.')
    if not ui.ask_yes('Bersihkan sekarang? [y/N]: '):
        ui.write('Dibatalkan.')
        return
    code, _ = ui.run_json(['system', 'clean-logs'], settings_override, backend)
    if code == 0:
        ui.ok('log dibersihkan. Ukuran sekarang:')
        ui.write_lines(ui.table(['Log', 'Ukuran'], _log_sizes(), [40, 16], right=(1,)))


def doctor(settings_override=None, backend=None):
    ui.title('DOCTOR - CEK KESEHATAN')
    code, data = ui.run_json(['doctor'], settings_override, backend)
    if not isinstance(data, dict):
        ui.fail('doctor tidak mengembalikan hasil.')
        return
    errors = dict((item.get('check'), item.get('error')) for item in data.get('errors', []))
    rows = []
    for key, passed in sorted((data.get('checks') or {}).items()):
        rows.append([CHECK_LABEL.get(key, key), (ui.MARK_OK + ' lulus', ui.GREEN) if passed else (ui.MARK_BAD + ' GAGAL', ui.RED),
                     errors.get(key) or ('' if passed else 'lihat Menu Sistem > Status/Log')])
    ui.write_lines(ui.table(['Pemeriksaan', 'Hasil', 'Keterangan'], rows, [22, 9, 40]))
    ui.write('')
    if data.get('ok'):
        ui.ok('semua pemeriksaan wajib lulus.')
    else:
        ui.fail('ada pemeriksaan wajib yang gagal.')


def regenerate(settings_override=None, backend=None):
    ui.title('REGENERATE CONFIG XRAY')
    code, data = ui.run_json(['config', 'regenerate', '--dry-run'], settings_override, backend)
    if code != 0 or not isinstance(data, dict):
        return
    rows = [('#', 'PERBANDINGAN DATABASE vs CONFIG'),
            ('File config', data.get('xray_config_path', '-')),
            ('Hasil', 'ADA perbedaan; config akan dibangun ulang' if data.get('changed') else 'sudah sesuai database',
             ui.YELLOW if data.get('changed') else ui.GREEN)]
    ui.write_lines(ui.box(rows))
    if not data.get('changed'):
        ui.note('Tidak ada yang perlu diterapkan.')
        return
    ui.note('Menerapkan akan me-restart Xray: semua koneksi VMess/VLESS/Trojan/SS putus sesaat.')
    if not ui.ask_yes('Terapkan sekarang? [y/N]: '):
        ui.write('Dibatalkan.')
        return
    code, data = ui.run_json(['config', 'regenerate'], settings_override, backend)
    if code == 0:
        ui.ok('config Xray dibangun ulang dari database.')


ITEMS = [('1', 'Status service & timer', status),
         ('2', 'Restart service', restart),
         ('3', 'Info sistem (CPU/RAM/disk)', system_info),
         ('4', 'Domain & Sertifikat TLS', domain_cert),
         ('5', 'Banner SSH', banner),
         ('6', 'Bandwidth harian', lambda s, b: bandwidth('daily', s, b)),
         ('7', 'Bandwidth bulanan', lambda s, b: bandwidth('monthly', s, b)),
         ('8', 'Log service', logs),
         ('9', 'Auto-reboot', autoreboot),
         ('10', 'Bersihkan log', clean_logs),
         ('11', 'Doctor (cek kesehatan)', doctor),
         ('12', 'Regenerate config Xray', regenerate),
         ('13', 'Speedtest (Ookla)', speedtest)]


def system_menu(settings_override=None, backend=None):
    actions = dict((key, fn) for key, _, fn in ITEMS)
    while True:
        ui.clear()
        ui.title('MENU SISTEM')
        for key, label, _ in ITEMS:
            ui.write('{0:>2}. {1}'.format(key, label))
        ui.write(' 0. Kembali')
        choice = ui.ask('Pilih: ')
        if choice in ('0', 'q', 'Q'):
            return
        ui.clear()
        if choice in ('4', '9'):  # sub-menus with their own loop and pause
            actions[choice](settings_override, backend)
            continue
        if choice in actions:
            actions[choice](settings_override, backend)
        else:
            ui.write('Pilihan tidak valid.')
        ui.pause()
