"""Server summary (menu 10), port/path info (menu 9) and shared system facts."""
import datetime
import os
import re
import shutil
import socket
import time
from pathlib import Path

from . import menu_ui as ui

CORE_SERVICES = [('haproxy', 'HAProxy (80/443)'), ('xray', 'Xray'), ('ws-epro', 'Ws-Epro (SSH WS)'),
                 ('dropbear-tunnel', 'Dropbear (SSH)'), ('nginx', 'Nginx (web/gRPC)')]
SUPPORT_SERVICES = [('tunnel-firewall', 'Firewall nftables'), ('chrony', 'Sinkron waktu'),
                    ('vnstat', 'Statistik trafik'), ('fail2ban', 'Fail2ban SSH admin')]
TIMERS = [('tunnel-usage.timer', 'Hitung kuota'), ('tunnel-limit.timer', 'Limit IP/login'),
          ('tunnel-expiry.timer', 'Masa aktif'), ('tunnel-backup.timer', 'Backup otomatis'),
          ('tunnel-acme-renew.timer', 'Renew sertifikat')]


def core_services(conf):
    udpgw = [('badvpn-udpgw@{0}'.format(port), 'UDPGW {0}'.format(port))
             for port in conf.get('ports', {}).get('udpgw', [7300])]
    return CORE_SERVICES + udpgw


# ---------------------------------------------------------------- system facts

def _read(path):
    try:
        return Path(path).read_text()
    except OSError:
        return ''


def system_facts():
    facts = {'hostname': socket.gethostname(), 'kernel': os.uname().release}
    match = re.search(r'^PRETTY_NAME="?([^"\n]+)', _read('/etc/os-release'), re.M)
    facts['os'] = match.group(1) if match else '-'
    try:
        facts['uptime'] = float(_read('/proc/uptime').split()[0])
    except (IndexError, ValueError):
        facts['uptime'] = None
    try:
        facts['load'] = os.getloadavg()
    except OSError:
        facts['load'] = None
    facts['cpus'] = os.cpu_count() or 0
    match = re.search(r'^model name\s*:\s*(.+)$', _read('/proc/cpuinfo'), re.M)
    facts['cpu_model'] = match.group(1).strip() if match else '-'
    meminfo = dict((k, int(v.split()[0]) * 1024) for k, v in
                   (line.split(':', 1) for line in _read('/proc/meminfo').splitlines() if ':' in line)
                   if v.split() and v.split()[0].isdigit())
    facts['mem_total'] = meminfo.get('MemTotal', 0)
    facts['mem_avail'] = meminfo.get('MemAvailable', 0)
    facts['swap_total'] = meminfo.get('SwapTotal', 0)
    facts['swap_free'] = meminfo.get('SwapFree', 0)
    try:
        facts['disk'] = shutil.disk_usage('/')
    except OSError:
        facts['disk'] = None
    now = datetime.datetime.now().astimezone()
    facts['now'] = now.strftime('%Y-%m-%d %H:%M:%S %Z')
    code, out, _ = ui.sh(['timedatectl', 'show', '-p', 'Timezone', '-p', 'NTPSynchronized'])
    values = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
    facts['timezone'] = values.get('Timezone', '-')
    facts['ntp'] = values.get('NTPSynchronized') == 'yes'
    return facts


def percent(used, total):
    return (100.0 * used / total) if total else 0.0


def system_rows(facts):
    mem_used = facts['mem_total'] - facts['mem_avail']
    mem_pct = percent(mem_used, facts['mem_total'])
    rows = [('#', 'SERVER'),
            ('Hostname', facts['hostname']),
            ('Sistem operasi', '{0} (kernel {1})'.format(facts['os'], facts['kernel'])),
            ('CPU', '{0} vCPU - {1}'.format(facts['cpus'], facts['cpu_model'])),
            ('RAM', '{0} / {1} terpakai ({2:.0f}%)'.format(ui.size(mem_used), ui.size(facts['mem_total']), mem_pct),
             ui.RED if mem_pct > 90 else None)]
    if facts['swap_total']:
        rows.append(('Swap', '{0} / {1} terpakai'.format(ui.size(facts['swap_total'] - facts['swap_free']), ui.size(facts['swap_total']))))
    if facts['disk']:
        disk_pct = percent(facts['disk'].used, facts['disk'].total)
        rows.append(('Disk /', '{0} / {1} terpakai ({2:.0f}%)'.format(ui.size(facts['disk'].used), ui.size(facts['disk'].total), disk_pct),
                     ui.RED if disk_pct > 90 else None))
    if facts['load']:
        rows.append(('Load (1/5/15 mnt)', '{0:.2f} / {1:.2f} / {2:.2f}'.format(*facts['load'])))
    rows += [('Uptime', ui.duration(facts['uptime']) if facts['uptime'] is not None else '-'),
             ('Waktu server', '{0} ({1})'.format(facts['now'], facts['timezone'])),
             ('Sinkron NTP', 'ya' if facts['ntp'] else 'TIDAK', None if facts['ntp'] else ui.RED)]
    return rows


# ---------------------------------------------------------------- certificate / DNS

def cert_path(conf):
    return conf.get('cert_path', '/etc/haproxy/certs/{0}.pem'.format(conf.get('domain')))


def cert_info(path):
    info = {'path': path, 'exists': Path(path).exists()}
    if not info['exists']:
        return info
    code, out, _ = ui.sh(['openssl', 'x509', '-in', path, '-noout', '-subject', '-issuer',
                          '-startdate', '-enddate', '-ext', 'subjectAltName'])
    if code != 0:
        info['error'] = True
        return info
    match = re.search(r'^subject=.*?CN\s*=\s*([^,/\n]+)', out, re.M)
    info['cn'] = match.group(1).strip() if match else '-'
    issuer = re.search(r'^issuer=(.*)$', out, re.M)
    issuer = issuer.group(1) if issuer else ''
    org = re.search(r'O\s*=\s*([^,/]+)', issuer)
    cn = re.search(r'CN\s*=\s*([^,/]+)', issuer)
    info['issuer'] = ' '.join(x.group(1).strip() for x in (org, cn) if x) or issuer or '-'
    san = re.search(r'Subject Alternative Name:\s*\n\s*(.+)', out)
    info['san'] = san.group(1).replace('DNS:', '').strip() if san else '-'
    for key, label in (('start', 'notBefore'), ('end', 'notAfter')):
        found = re.search(r'^{0}=(.+)$'.format(label), out, re.M)
        try:
            info[key] = datetime.datetime.strptime(' '.join(found.group(1).split()), '%b %d %H:%M:%S %Y %Z').replace(
                tzinfo=datetime.timezone.utc)
        except (AttributeError, ValueError):
            info[key] = None
    if info.get('end'):
        info['days_left'] = int((info['end'] - datetime.datetime.now(datetime.timezone.utc)).total_seconds() // 86400)
    return info


def cert_rows(info, conf):
    rows = [('#', 'SERTIFIKAT TLS'), ('Mode', conf.get('cert_mode', '-')), ('File', info['path'])]
    if not info.get('exists'):
        return rows + [('Status', 'FILE TIDAK ADA', ui.RED)]
    if info.get('error'):
        return rows + [('Status', 'gagal dibaca openssl', ui.RED)]
    days = info.get('days_left')
    color = ui.RED if days is not None and days < 15 else (ui.YELLOW if days is not None and days < 30 else ui.GREEN)
    rows += [('Untuk domain', info.get('san') or info.get('cn')),
             ('Penerbit', info.get('issuer')),
             ('Berlaku sejak', info['start'].astimezone().strftime('%Y-%m-%d %H:%M') if info.get('start') else '-'),
             ('Berlaku sampai', info['end'].astimezone().strftime('%Y-%m-%d %H:%M') if info.get('end') else '-'),
             ('Sisa', '{0} hari'.format(days) if days is not None else '-', color)]
    return rows


def dns_lookup(domain):
    try:
        return sorted(set(item[4][0] for item in socket.getaddrinfo(domain, None, socket.AF_INET)))
    except (socket.gaierror, UnicodeError, OSError):
        return []


# ---------------------------------------------------------------- dashboard

def _service_summary(conf):
    services = core_services(conf) + SUPPORT_SERVICES
    states = ui.unit_states([unit for unit, _ in services] + [unit for unit, _ in TIMERS])
    up, down = [], []
    for unit, label in services:
        (up if states[unit].get('ActiveState') == 'active' else down).append(label.split(' (')[0])
    timer_bits = []
    timers_down = []
    for unit, label in TIMERS:
        state = states[unit]
        if state.get('LoadState') == 'not-found':
            continue
        active = state.get('ActiveState') == 'active'
        timer_bits.append('{0} {1}'.format(unit.replace('tunnel-', '').replace('.timer', ''), ui.MARK_OK if active else ui.MARK_BAD))
        if not active and unit in ('tunnel-usage.timer', 'tunnel-limit.timer', 'tunnel-expiry.timer'):
            timers_down.append(unit)
    return up, down, timer_bits, timers_down


def _traffic_today():
    code, out, _ = ui.sh(['vnstat', '--json', 'd'])
    if code != 0:
        return None
    try:
        import json
        data = json.loads(out)
    except ValueError:
        return None
    factor = 1024 if str(data.get('jsonversion', '2')) == '1' else 1
    best = None
    for iface in data.get('interfaces', []):
        traffic = iface.get('traffic', {})
        days = traffic.get('day') or traffic.get('days') or []
        if not days:
            continue
        last = days[-1]
        total = (last.get('rx', 0) + last.get('tx', 0)) * factor
        if best is None or total > best[3]:
            best = (iface.get('name', '?'), last.get('rx', 0) * factor, last.get('tx', 0) * factor, total)
    return best


def _latest_backup(conf):
    files = sorted((p for p in Path(conf.get('backup_dir', '/var/backups/tunnel')).glob('tunnel-backup-*') if p.is_file()),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return files


def dashboard(settings_override=None, backend=None, refresh=False):
    conf = ui.settings(settings_override)
    ui.title('RINGKASAN SERVER')
    ui.write('Mengumpulkan data...')
    facts = system_facts()
    net = ui.ipinfo(refresh=refresh, allow_network=True)
    public_ip = net.get('ip') or ui.local_ip() or '-'
    domain = conf.get('domain', '-')
    dns = dns_lookup(domain)
    cert = cert_info(cert_path(conf))
    up, down, timer_bits, timers_down = _service_summary(conf)
    issues = []

    rows = system_rows(facts)
    rows += [('#', 'JARINGAN'),
             ('IP publik', public_ip),
             ('ISP / ASN', net.get('org') or '-'),
             ('Lokasi', ', '.join(x for x in (net.get('city'), net.get('region'), net.get('country')) if x) or '-'),
             ('Hostname IP', net.get('hostname') or '-')]
    if not net:
        issues.append('Gagal menghubungi ipinfo.io (cek koneksi keluar server).')

    dns_text = ', '.join(dns) if dns else 'tidak ditemukan'
    dns_match = public_ip in dns
    rows += [('#', 'DOMAIN & SERTIFIKAT'),
             ('Domain', domain),
             ('DNS A record', '{0} ({1})'.format(dns_text, 'cocok dengan IP publik' if dns_match else 'TIDAK cocok'),
              None if dns_match else ui.RED)]
    if not dns_match:
        issues.append('DNS {0} tidak mengarah ke IP publik {1}.'.format(domain, public_ip))
    if not cert.get('exists') or cert.get('error'):
        rows.append(('Sertifikat', 'tidak ditemukan / rusak', ui.RED))
        issues.append('Sertifikat TLS tidak ditemukan atau rusak.')
    else:
        days = cert.get('days_left')
        rows.append(('Sertifikat', '{0}; sampai {1} ({2} hari lagi)'.format(
            cert.get('issuer'), cert['end'].astimezone().strftime('%Y-%m-%d') if cert.get('end') else '-', days),
            ui.RED if days is not None and days < 15 else None))
        if days is not None and days < 15:
            issues.append('Sertifikat habis dalam {0} hari.'.format(days))

    rows += [('#', 'SERVICE'),
             ('Aktif', ', '.join(up) or '-', ui.GREEN),
             ('Mati', ', '.join(down) or '-', ui.RED if down else None),
             ('Timer', '  '.join(timer_bits) or '-')]
    if down:
        issues.append('Service mati: ' + ', '.join(down) + '.')
    if timers_down:
        issues.append('Timer penegakan tidak aktif: ' + ', '.join(timers_down) + '.')

    try:
        all_accounts = ui.accounts(settings_override, backend)
    except Exception:
        all_accounts = None
    code, online_items = ui.run_json(['account', 'online'], settings_override, backend)
    online = {}
    if code == 0 and isinstance(online_items, list):
        for item in online_items:
            if item.get('sessions') or item.get('ips'):
                online[item['protocol']] = online.get(item['protocol'], 0) + 1
    rows.append(('#', 'KLIEN'))
    if all_accounts is None:
        rows.append(('Akun', 'gagal membaca database', ui.RED))
        issues.append('Database akun tidak bisa dibaca.')
    else:
        def describe(items, proto=None):
            counts = {}
            for row in items:
                counts[row['status']] = counts.get(row['status'], 0) + 1
            parts = ['{0} akun'.format(len(items))]
            parts += ['{0} {1}'.format(v, ui.STATUS_LABEL.get(k, k)) for k, v in sorted(counts.items())]
            count_online = sum(online.values()) if proto is None else online.get(proto, 0)
            parts.append('online {0}'.format(count_online))
            return ' | '.join(parts)
        rows.append(('Total', describe(all_accounts)))
        for proto in ui.PROTOCOLS:
            rows.append((ui.PROTO_NAME[proto], describe([a for a in all_accounts if a['protocol'] == proto], proto)))

    rows.append(('#', 'BACKUP & TRAFIK'))
    backups = _latest_backup(conf)
    if backups:
        latest = backups[0]
        rows.append(('Backup terakhir', '{0} ({1}; total {2} file)'.format(latest.name, ui.ago(latest.stat().st_mtime), len(backups))))
    else:
        rows.append(('Backup terakhir', 'belum ada backup', ui.YELLOW))
        issues.append('Belum ada backup.')
    traffic = _traffic_today()
    rows.append(('Trafik hari ini', 'masuk {0} / keluar {1} ({2})'.format(ui.size(traffic[1]), ui.size(traffic[2]), traffic[0])
                 if traffic else 'data vnstat belum tersedia'))

    if not facts['ntp']:
        issues.append('Jam server belum tersinkron NTP (VMess sensitif terhadap selisih waktu).')
    if facts['disk'] and percent(facts['disk'].used, facts['disk'].total) > 90:
        issues.append('Disk / hampir penuh.')
    if facts['mem_total'] and percent(facts['mem_total'] - facts['mem_avail'], facts['mem_total']) > 90:
        issues.append('RAM hampir habis.')

    rows.append(('#', 'PERHATIAN'))
    if issues:
        for index, issue in enumerate(issues, 1):
            rows.append(('Masalah {0}'.format(index), issue, ui.RED))
    else:
        rows.append(('Hasil', 'Tidak ada masalah terdeteksi.', ui.GREEN))

    ui.clear()
    ui.title('RINGKASAN SERVER  ({0})'.format(facts['now']))
    ui.write_lines(ui.box(rows))
    ui.write(' Data ISP dari ipinfo.io (cache 1 jam). Ketik r lalu Enter untuk memperbarui, Enter untuk kembali.')
    if ui.ask('').lower() == 'r':
        ui.clear()
        dashboard(settings_override, backend, refresh=True)


# ---------------------------------------------------------------- ports & paths

def ports_info(settings_override=None, backend=None):
    conf = ui.settings(settings_override)
    ports = conf.get('ports', {})
    http, https = ports.get('http', 80), ports.get('https', 443)
    ws = conf.get('ws_paths', {})
    grpc = conf.get('grpc_names', {})
    udpgw = ', '.join(str(p) for p in ports.get('udpgw', [7300]))
    admin = [conf.get('ssh_admin_port', 22)] + list(conf.get('ssh_admin_extra_ports', []))
    ui.title('INFO PORT & PATH')
    ui.write('Domain: {0}    IP: {1}\n'.format(conf.get('domain', '-'), ui.server_ip()))
    rows = [['SSH WebSocket', str(http), 'payload HTTP; sebaiknya langsung ke IP VPS'],
            ['SSH WebSocket TLS', str(https), 'payload di dalam TLS (SNI bebas)'],
            ['SSH-SSL', str(https), 'SSH murni di dalam TLS, tanpa payload'],
            ['Xray WS non-TLS', str(http), 'VMess/VLESS/Trojan/SS, Host bebas'],
            ['Xray WS TLS', str(https), 'VMess/VLESS/Trojan/SS'],
            ['Xray gRPC TLS', str(https), 'VMess/VLESS/Trojan, ALPN h2'],
            ['UDPGW', udpgw, '127.0.0.1 lewat tunnel (bukan port publik)'],
            ['SSH admin', ', '.join(str(p) for p in admin), 'OpenSSH untuk admin, bukan akun tunnel']]
    extra = list(conf.get('extra_http_ports', [])) + list(conf.get('extra_https_ports', []))
    if extra:
        rows.append(['Port tambahan', ', '.join(str(p) for p in extra), 'listen tambahan HAProxy'])
    ui.write_lines(ui.table(['Layanan', 'Port', 'Keterangan'], rows, [18, 10, 46]))
    ui.write('')
    path_rows = []
    for proto in ('vmess', 'vless', 'trojan', 'ss'):
        path_rows.append([ui.PROTO_NAME[proto], ws.get(proto, '-'), grpc.get(proto, '- (tidak ada)')])
    ui.write_lines(ui.table(['Protokol', 'Path WebSocket', 'gRPC serviceName'], path_rows, [14, 20, 24]))
    ui.write('')
    code, out, _ = ui.sh(['ss', '-H', '-tlnp'])
    listen_rows = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        address = fields[3]
        names = sorted(set(re.findall(r'\("([^"]+)",pid', line)))
        host = address.rsplit(':', 1)[0].strip('[]').split('%')[0]
        public = not (host.startswith('127.') or host == '::1')
        listen_rows.append([address, ', '.join(names) or '-', ('PUBLIK', ui.YELLOW) if public else 'lokal'])
    listen_rows.sort(key=lambda r: (r[2] == 'lokal', int(r[0].rsplit(':', 1)[1]) if r[0].rsplit(':', 1)[-1].isdigit() else 0))
    ui.title('LISTENER TCP AKTIF')
    if listen_rows:
        ui.write_lines(ui.table(['Alamat', 'Proses', 'Akses'], listen_rows, [24, 30, 8]))
    else:
        ui.write('Tidak bisa membaca daftar listener (perintah ss).')
