"""System menu: every view is a table, every change shows the current value first."""
import os
import re
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


def _domain_rows(title, name, ip):
    dns = info.dns_lookup(name)
    match = bool(ip) and ip in dns
    return [('#', title),
            ('Domain', name),
            ('IP publik server', ip or '-'),
            ('DNS A record', '{0} ({1})'.format(', '.join(dns) or 'tidak ditemukan', 'cocok' if match else 'TIDAK cocok'),
             ui.GREEN if match else ui.RED)], match


def domain(settings_override=None, backend=None):
    conf = ui.settings(settings_override)
    current = conf.get('domain', '-')
    ip = ui.server_ip(allow_network=True)
    cert = info.cert_info(info.cert_path(conf))
    rows, _ = _domain_rows('DOMAIN SAAT INI', current, ip)
    rows += [('Sertifikat untuk', cert.get('san') or cert.get('cn') or '-'),
             ('Sertifikat sampai', cert['end'].astimezone().strftime('%Y-%m-%d') if cert.get('end') else '-')]
    ui.title('GANTI DOMAIN')
    ui.write_lines(ui.box(rows))
    if not os.path.exists(DOMAIN_HELPER):
        ui.write('')
        ui.write('Server ini dikelola dari controller terpisah. Jalankan di controller (folder repo):')
        for line in ('sed -i "s/^\\( *tunnel_domain: *\\).*/\\1DOMAIN_BARU/" INVENTORY/hosts.yml',
                     '.venv/bin/ansible-playbook -i INVENTORY/hosts.yml playbooks/prepare-server.yml',
                     '.venv/bin/ansible-playbook -i INVENTORY/hosts.yml playbooks/site.yml',
                     '.venv/bin/ansible-playbook -i INVENTORY/hosts.yml playbooks/commit-server.yml'):
            ui.write('  ' + line)
        return
    ui.write('')
    ui.write('Langkah sebelum ganti domain:')
    ui.write('  1. Buat A record domain baru -> {0} di Cloudflare (DNS only / awan abu-abu).'.format(ip))
    ui.write('  2. Tunggu sampai DNS aktif (biasanya 1-5 menit), lalu isi domain baru di bawah.')
    new = ui.ask('\nDomain baru (kosong = batal): ').lower().rstrip('.')
    if not new:
        ui.write('Dibatalkan.')
        return
    if not DOMAIN_RE.match(new):
        ui.fail('format domain tidak valid: {0}'.format(new))
        return
    if new == current:
        ui.write('Domain baru sama dengan domain saat ini; tidak ada yang diubah.')
        return
    ui.clear()
    ui.title('GANTI DOMAIN: {0} -> {1}'.format(current, new))
    rows, match = _domain_rows('PEMERIKSAAN DOMAIN BARU', new, ip)
    ui.write_lines(ui.box(rows))
    args = [DOMAIN_HELPER, new, '--yes']
    if not match:
        ui.write(ui.paint('DNS domain baru belum mengarah ke server ini.', ui.RED))
        ui.note('Untuk mode http01, Let\'s Encrypt WAJIB bisa menjangkau domain baru di port 80. '
                'Perbaiki DNS lalu ulangi. Lewati pemeriksaan hanya jika memakai Cloudflare proxied atau cert_mode dns_cloudflare.')
        if not ui.ask_yes('Tetap lanjut tanpa pemeriksaan DNS/HTTP? [y/N]: '):
            ui.write('Dibatalkan.')
            return
        args.append('--skip-dns-check')
    ui.write('')
    ui.write('Yang akan terjadi:')
    for step in ('tunnel_domain di inventory diganti (cadangan otomatis dibuat);',
                 'prepare -> site -> commit dijalankan; sertifikat baru diterbitkan;',
                 'port 443 sempat terputus selama penerbitan sertifikat (beberapa detik - menit);',
                 'jika gagal, domain lama otomatis dipulihkan;',
                 'link semua akun berubah ke domain baru (perlu dibagikan ulang).'):
        ui.write('  - ' + step)
    ui.note('Perkiraan 3-10 menit. Jangan tutup terminal; sebaiknya jalankan menu ini di dalam tmux.')
    if not ui.ask_yes('Mulai ganti domain ke {0}? [y/N]: '.format(new)):
        ui.write('Dibatalkan.')
        return
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        code = subprocess.call(args)
    finally:
        signal.signal(signal.SIGINT, previous)
    ui.write('')
    conf = ui.settings(settings_override)
    rows, _ = _domain_rows('DOMAIN SETELAH PROSES', conf.get('domain', '-'), ip)
    cert = info.cert_info(info.cert_path(conf))
    rows.append(('Sertifikat sampai', cert['end'].astimezone().strftime('%Y-%m-%d') if cert.get('end') else '-'))
    ui.write_lines(ui.box(rows))
    (ui.ok if code == 0 else ui.fail)('domain diganti.' if code == 0 else 'ganti domain tidak selesai (lihat keluaran di atas).')


def certificate(settings_override=None, backend=None):
    conf = ui.settings(settings_override)
    def show():
        rows = info.cert_rows(info.cert_info(info.cert_path(conf)), conf)
        state = ui.unit_states(['tunnel-acme-renew.timer'])['tunnel-acme-renew.timer']
        if state.get('LoadState') != 'not-found':
            rows += [('#', 'PERPANJANGAN OTOMATIS'),
                     ('Timer', ui.state_label(state)[0], ui.state_label(state)[1]),
                     ('Cek terakhir', ui.short_ts(state.get('LastTriggerUSec'))),
                     ('Cek berikutnya', ui.short_ts(state.get('NextElapseUSecRealtime')))]
        ui.write_lines(ui.box(rows))
        return state
    ui.title('SERTIFIKAT TLS')
    state = show()
    if conf.get('cert_mode') == 'selfsigned' or state.get('LoadState') == 'not-found':
        ui.note('Mode selfsigned: tidak ada perpanjangan otomatis. Ganti cert_mode di inventory untuk sertifikat publik.')
        return
    ui.note('acme.sh hanya memperbarui jika sertifikat tinggal <= 30 hari; di luar itu pengecekan dilewati.')
    if not ui.ask_yes('Jalankan pengecekan perpanjangan sekarang? [y/N]: '):
        return
    ui.write('Menjalankan tunnel-acme-renew.service ...')
    code, _, _ = ui.sh(['systemctl', 'start', 'tunnel-acme-renew.service'], timeout=300)
    _, log, _ = ui.sh(['journalctl', '-u', 'tunnel-acme-renew.service', '-n', '12', '--no-pager', '-o', 'cat'])
    ui.write_lines(['  ' + line for line in log.splitlines()])
    (ui.ok if code == 0 else ui.fail)('pengecekan selesai' if code == 0 else 'pengecekan gagal (lihat log di atas)')
    ui.write('')
    show()


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


def autoreboot(settings_override=None, backend=None):
    conf = ui.settings(settings_override)
    state = ui.unit_states(['tunnel-autoreboot.timer'])['tunnel-autoreboot.timer']
    available = state.get('LoadState') not in ('not-found', 'unknown')
    rows = [('#', 'AUTO-REBOOT'),
            ('Setelan saat ini', conf.get('autoreboot') or 'mati'),
            ('Unit timer', 'terpasang' if available else 'BELUM terpasang', None if available else ui.YELLOW)]
    if available:
        rows.append(('Jadwal berikutnya', ui.short_ts(state.get('NextElapseUSecRealtime'))))
    ui.title('AUTO-REBOOT')
    ui.write_lines(ui.box(rows))
    if not available:
        ui.note('Fitur auto-reboot belum aktif: unit tunnel-autoreboot.timer belum dipasang oleh Ansible. '
                'Akan ditambahkan pada tahap perbaikan fungsi.')
        return
    value = ui.ask('Jam reboot harian HH:MM, "off" untuk mematikan (kosong = batal): ').lower()
    if not value:
        ui.write('Dibatalkan.')
        return
    args = ['system', 'autoreboot', 'off'] if value == 'off' else ['system', 'autoreboot', 'set', value]
    code, _ = ui.run_json(args, settings_override, backend)
    if code == 0:
        ui.ok('auto-reboot ' + ('dimatikan' if value == 'off' else 'diset ke ' + value))


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
         ('4', 'Ganti domain', domain),
         ('5', 'Sertifikat TLS', certificate),
         ('6', 'Banner SSH', banner),
         ('7', 'Bandwidth harian', lambda s, b: bandwidth('daily', s, b)),
         ('8', 'Bandwidth bulanan', lambda s, b: bandwidth('monthly', s, b)),
         ('9', 'Log service', logs),
         ('10', 'Auto-reboot', autoreboot),
         ('11', 'Bersihkan log', clean_logs),
         ('12', 'Doctor (cek kesehatan)', doctor),
         ('13', 'Regenerate config Xray', regenerate)]


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
        if choice in actions:
            actions[choice](settings_override, backend)
        else:
            ui.write('Pilihan tidak valid.')
        ui.pause()
