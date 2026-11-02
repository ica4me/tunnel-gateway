"""Real OS boundary. Only tunnelusers and tunnel services are managed."""
import copy
from typing import Optional
import datetime
import grp
import ipaddress
import json
import os
import pwd
import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from .errors import Conflict, TunnelCtlError
from .util import normalize_ips, parse_utc


def atomic_write(path, content):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.is_symlink():
        raise ValueError('Symlink tidak diizinkan')
    fd, name = tempfile.mkstemp(prefix='.tunnel-', dir=str(target.parent))
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content.encode() if isinstance(content, str) else content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, str(target))
        directory = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        os.chmod(str(target), 0o600)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _parse_journal_line(line):
    line = str(line).strip()
    if line.startswith('['):
        match = re.match(r'^\[([^\]]+)\](?::[0-9]+)?$', line)
        return match.group(1) if match else None
    try:
        ipaddress.ip_address(line)
        return line
    except ValueError:
        pass
    if line.count(':') == 1:
        return line.split(':')[0]
    return None


def generate_xray(base_config, accounts, settings):
    value = copy.deepcopy(base_config)
    active = [a for a in accounts if a['status'] == 'active']
    for inbound in value.get('inbounds', []):
        protocol = {'shadowsocks': 'ss'}.get(inbound.get('protocol'), inbound.get('protocol'))
        if protocol not in ('vmess', 'vless', 'trojan', 'ss'):
            continue
        clients = []
        inbound_settings = inbound.setdefault('settings', {})
        if protocol == 'ss':
            inbound_settings.pop('password', None)
            inbound_settings['method'] = settings.get('ss_method', inbound_settings.get('method', 'chacha20-ietf-poly1305'))
        for account in active:
            if account['protocol'] != protocol:
                continue
            client = {'email': account['username'] + '@' + protocol, 'level': 0}
            if protocol in ('vmess', 'vless'):
                client['id'] = account['secret']
                if protocol == 'vmess':
                    client['alterId'] = 0
            else:
                client['password'] = account['secret']
                if protocol == 'ss':
                    client['method'] = inbound_settings['method']
            clients.append(client)
        inbound_settings['clients'] = clients
        stream = inbound.get('streamSettings', {})
        if stream.get('network') == 'ws' and protocol in settings.get('ws_paths', {}):
            ws = stream.setdefault('wsSettings', {})
            ws['path'] = settings['ws_paths'][protocol]
            ws.pop('headers', None)
        if stream.get('network') == 'grpc' and protocol in settings.get('grpc_names', {}):
            stream.setdefault('grpcSettings', {})['serviceName'] = settings['grpc_names'][protocol]
    value['_comment'] = 'Dikelola tunnelctl dari database; jangan diedit manual'
    return value


class SystemBackend:
    require_root = True
    SERVICES = ('haproxy', 'xray', 'ws-epro', 'dropbear-tunnel', 'nginx', 'chrony', 'tunnel-firewall', 'vnstat')
    TIMERS = ('tunnel-usage.timer', 'tunnel-limit.timer', 'tunnel-expiry.timer', 'tunnel-backup.timer', 'tunnel-cert.timer')

    DROPBEAR_UNIT = 'dropbear-tunnel.service'
    TUNNEL_GROUP = 'tunnelusers'
    LOG_PID_RE = re.compile(r'^\s*\[([0-9]+)\]')
    AUTH_RES = (re.compile(r"Password auth succeeded for '([^']+)'"),
                re.compile(r'Password auth succeeded for ([a-z0-9_]+) from '))

    def __init__(self, runner=None, check_root=True, proc_root='/proc'):
        self.runner = runner or self._run
        self.settings = {}
        self.check_root = check_root
        self.proc_root = Path(proc_root)

    def _run(self, args, input=None, timeout: Optional[int]=60, capture=True, **kwargs):
        try:
            result = subprocess.run(
                args,
                input=input,
                check=True,
                capture_output=bool(capture),
                text=True,
                timeout=timeout,
            )
            return result.stdout.strip() if capture else ''
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            # Never return subprocess output; Xray validators/password tools can print secrets.
            raise TunnelCtlError('Perintah sistem gagal: ' + Path(args[0]).name) from exc

    def _managed_user(self, username):
        try:
            record = pwd.getpwnam(username)
        except KeyError:
            return None
        try:
            group = grp.getgrnam('tunnelusers')
            managed = record.pw_gid == group.gr_gid or username in group.gr_mem
        except KeyError:
            managed = False
        if record.pw_uid == 0 or not managed:
            raise Conflict('Username SSH bentrok dengan user sistem')
        return record

    def _apply_ssh(self, source, target):
        source_map = {a['username']: a for a in source if a['protocol'] == 'ssh'}
        target_map = {a['username']: a for a in target if a['protocol'] == 'ssh'}
        for username, account in target_map.items():
            record = self._managed_user(username)
            if record is None:
                self.runner(['useradd', '-M', '-s', '/bin/false', '-g', 'tunnelusers', username])
            self.runner(['chpasswd'], input=username + ':' + account['secret'] + '\n')
            self.runner(['usermod', '-e', parse_utc(account['expires_at']).date().isoformat(), username])
            self.runner(['usermod', '-U' if account['status'] == 'active' else '-L', username])
        for username in source_map.keys() - target_map.keys():
            if self._managed_user(username) is not None:
                self.runner(['userdel', username])

    def regenerate_config(self, accounts, settings, dry_run=False):
        self.settings = settings
        base = Path(settings['xray_base_path'])
        generated = generate_xray(json.loads(base.read_text()), accounts, settings)
        payload = json.dumps(generated, indent=2) + '\n'
        validate_cmd = list(settings.get('xray_validate_cmd', ['xray', 'run', '-test', '-config']))
        with tempfile.TemporaryDirectory(dir=str(Path(settings['xray_config_path']).parent if settings.get('xray_config_path') else None)) as temporary:
            probe = Path(temporary) / 'xray-config.json'
            atomic_write(probe, payload)
            self.runner(validate_cmd + [str(probe)])
        config = Path(settings['xray_config_path'])
        original = config.read_bytes() if config.exists() else None
        changed = original != payload.encode()
        if dry_run:
            return {'ok': True, 'dry_run': True, 'xray_config_path': settings['xray_config_path'], 'changed': changed}
        if not changed:
            return {'ok': True, 'dry_run': False, 'xray_config_path': settings['xray_config_path'], 'changed': False}
        atomic_write(config, payload)
        try:
            self.runner(['systemctl', 'restart', 'xray'])
        except BaseException:
            if original is None:
                config.unlink()
            else:
                atomic_write(config, original)
            self.runner(['systemctl', 'restart', 'xray'])
            raise
        return {'ok': True, 'dry_run': False, 'xray_config_path': settings['xray_config_path'], 'changed': True}

    def reconcile(self, old_accounts, new_accounts, settings):
        self.settings = settings
        for account in new_accounts + old_accounts:
            if account['protocol'] == 'ssh':
                self._managed_user(account['username'])
        config = Path(settings['xray_config_path'])
        original = config.read_bytes() if config.exists() else None
        ssh_applied = False
        replaced = False
        try:
            self.regenerate_config(new_accounts, settings, dry_run=False)
            replaced = True
            if any(a['protocol'] == 'ssh' for a in old_accounts + new_accounts):
                ssh_applied = True
                self._apply_ssh(old_accounts, new_accounts)
            for old in old_accounts:
                new = next((a for a in new_accounts if a['id'] == old['id']), None)
                if old['protocol'] == 'ssh' and (new is None or new['status'] != 'active' or old['secret'] != new['secret']):
                    self.disconnect_ssh(old['username'])
        except BaseException as original_error:
            failures = []
            if replaced:
                try:
                    if original is None:
                        config.unlink()
                    else:
                        atomic_write(config, original)
                    self.runner(['systemctl', 'restart', 'xray'])
                except Exception:
                    failures.append('xray')
            if ssh_applied:
                try:
                    self._apply_ssh(new_accounts, old_accounts)
                except Exception:
                    failures.append('ssh')
            if failures:
                raise TunnelCtlError('Rollback sistem gagal: ' + ','.join(failures)) from original_error
            raise

    def xray_stats(self, account):
        email = account['username'] + '@' + account['protocol']
        prefix = 'user>>>' + email + '>>>traffic>>>'
        out = self.runner(['xray', 'api', 'statsquery', '--server=' + self.settings.get('xray_api', '127.0.0.1:10085'), '-pattern', prefix, '-reset'])
        parsed = json.loads(out)
        if not isinstance(parsed, dict):
            raise ValueError('Respons stats tidak valid')
        result = {'up': 0, 'down': 0}
        for item in parsed.get('stat', []):
            name = item.get('name')
            if name == prefix + 'uplink':
                key = 'up'
            elif name == prefix + 'downlink':
                key = 'down'
            else:
                continue
            # Protobuf JSON omits scalar fields at their default (zero) value.
            count = int(item.get('value', 0))
            if count < 0:
                raise ValueError('Counter negatif')
            result[key] += count
        return result

    def xray_online_ips(self, account):
        email = account['username'] + '@' + account['protocol']
        try:
            out = self.runner(['xray', 'api', 'statsonlineiplist', '--server=' + self.settings.get('xray_api', '127.0.0.1:10085'), '-email', email])
        except TunnelCtlError as exc:
            cause = exc.__cause__
            detail = ' '.join(str(getattr(cause, k, '') or '') for k in ('stderr', 'stdout')).lower()
            if 'not found' in detail:
                # No online record since Xray last started: the user is offline.
                return []
            raise
        if out.strip().startswith('{'):
            parsed = json.loads(out)
            ips = parsed.get('ips', {})
            if isinstance(ips, dict):
                # Xray online map timestamps record AddIP time, not heartbeat updates.
                # Filtering by ip_window_seconds can undercount long-lived active sessions.
                return normalize_ips(list(ips.keys()))
            return normalize_ips([item.get('ip') if isinstance(item, dict) else item for item in ips])
        return normalize_ips([ip for ip in (_parse_journal_line(line) for line in out.splitlines()) if ip])

    def process_identity(self, pid):
        """Identitas proses Dropbear (None jika bukan Dropbear atau sudah tidak ada)."""
        try:
            proc = self.proc_root / str(int(pid))
            exe = os.readlink(str(proc / 'exe'))
            # Setelah binary diganti (update), link berakhiran " (deleted)".
            if Path(exe.replace(' (deleted)', '')).name != 'dropbear':
                return None
            fields = self._stat_fields((proc / 'stat').read_text())
            uid_line = next(line for line in (proc / 'status').read_text().splitlines() if line.startswith('Uid:'))
            uids = [int(value) for value in uid_line.split()[1:4]]
            return {'start_ticks': fields[19], 'ppid': int(fields[1]),
                    'uid': next((u for u in uids if u != 0), 0), 'boot_id': self._boot_id()}
        except (OSError, ValueError, StopIteration, IndexError):
            return None

    @staticmethod
    def _stat_fields(stat_text):
        """Field /proc/PID/stat setelah nama proses: [0]=state, [1]=ppid, [19]=starttime."""
        return stat_text[stat_text.rfind(')') + 2:].split()

    def _boot_id(self):
        return (self.proc_root / 'sys/kernel/random/boot_id').read_text().strip()

    def _dropbear_main_pid(self):
        try:
            return int(self.runner(['systemctl', 'show', self.DROPBEAR_UNIT, '-p', 'MainPID', '--value']).strip() or 0)
        except (TunnelCtlError, ValueError):
            return 0

    def _dropbear_children(self, main_pid):
        """Proses koneksi yang masih hidup: anak langsung dari proses utama dropbear-tunnel."""
        children = []
        if main_pid <= 0:
            return children
        try:
            entries = list(self.proc_root.iterdir())
        except OSError:
            return children
        for entry in entries:
            if not entry.name.isdigit() or int(entry.name) == main_pid:
                continue
            try:
                if int(self._stat_fields((entry / 'stat').read_text())[1]) != main_pid:
                    continue
            except (OSError, ValueError, IndexError):
                continue
            identity = self.process_identity(entry.name)
            if identity is not None and identity['ppid'] == main_pid:
                children.append(dict(identity, pid=int(entry.name)))
        return children

    def _tunnel_username(self, uid):
        """Username untuk UID anggota grup tunnelusers; None untuk user lain."""
        try:
            record = pwd.getpwuid(uid)
            group = grp.getgrnam(self.TUNNEL_GROUP)
        except KeyError:
            return None
        if record.pw_uid == 0 or not (record.pw_gid == group.gr_gid or record.pw_name in group.gr_mem):
            return None
        return record.pw_name

    @staticmethod
    def _monotonic_to_boottime():
        """Selisih CLOCK_BOOTTIME - CLOCK_MONOTONIC (waktu suspend); 0 di VPS pada umumnya."""
        boottime = getattr(time, 'CLOCK_BOOTTIME', None)
        if boottime is None:
            return 0.0
        try:
            return max(0.0, time.clock_gettime(boottime) - time.clock_gettime(time.CLOCK_MONOTONIC))
        except OSError:
            return 0.0

    def _auth_journal(self):
        """{pid: {username, boot_seconds, boot_id}} dari log login sukses Dropbear sejak boot ini."""
        raw = self.runner(['journalctl', '-u', self.DROPBEAR_UNIT, '-b', '-o', 'json', '--no-pager',
                           '--output-fields=MESSAGE,_PID,_BOOT_ID'], timeout=90)
        offset = self._monotonic_to_boottime()
        found = {}
        for line in raw.splitlines():
            try:
                entry = json.loads(line)
                message = entry.get('MESSAGE', '')
                if isinstance(message, list):  # journald memakai array byte untuk pesan non-UTF-8
                    message = bytes(message).decode('utf-8', 'replace')
                if 'auth succeeded' not in message:
                    continue
                username = None
                for pattern in self.AUTH_RES:
                    match = pattern.search(message)
                    if match:
                        username = match.group(1)
                        break
                if username is None:
                    continue
                prefix = self.LOG_PID_RE.match(message)
                pid = int(prefix.group(1)) if prefix else int(entry['_PID'])
                found[pid] = {'username': username, 'boot_id': entry.get('_BOOT_ID', ''),
                              'boot_seconds': int(entry['__MONOTONIC_TIMESTAMP']) / 1000000.0 + offset}
            except (ValueError, KeyError, TypeError):
                continue
        return found

    def dropbear_sessions(self):
        """Daftar sesi SSH tunnel yang sedang terhubung: [{pid, username, start_ticks, boot_id}]."""
        main_pid = self._dropbear_main_pid()
        sessions = []
        pending = []
        for child in self._dropbear_children(main_pid):
            if child['uid'] != 0:
                username = self._tunnel_username(child['uid'])
                if username:
                    sessions.append(dict(child, username=username))
            else:
                pending.append(child)
        if pending:
            journal = self._auth_journal()
            clock_ticks = float(os.sysconf('SC_CLK_TCK'))
            for child in pending:
                auth = journal.get(child['pid'])
                if auth is None:
                    continue  # koneksi belum login (mis. bot/scan)
                if auth['boot_id'] and auth['boot_id'].replace('-', '') != child['boot_id'].replace('-', ''):
                    continue
                # Log login harus terjadi setelah proses ini dibuat (mencegah PID daur ulang).
                if auth['boot_seconds'] < int(child['start_ticks']) / clock_ticks - 2:
                    continue
                username = auth['username']
                try:
                    if self._managed_user(username) is None:
                        continue
                except Conflict:
                    continue
                sessions.append(dict(child, username=username))
        return [{'pid': s['pid'], 'username': s['username'], 'start_ticks': s['start_ticks'],
                 'boot_id': s['boot_id']} for s in sessions]

    def ssh_sessions(self, journal_lines=None, pid_table=None):
        if journal_lines is None:
            counts = {}
            for session in self.dropbear_sessions():
                counts[session['username']] = counts.get(session['username'], 0) + 1
            return counts
        # Fixture-only plain-text parser. UID tidak lagi harus 0: Dropbear modern turun hak ke user.
        counts = {}
        seen = set()
        for line in journal_lines:
            match = re.search(r"dropbear\[([0-9]+)\]: (?:\[[0-9]+\] .*?)?Password auth succeeded for '?([a-z0-9_]+)'? from ", line)
            if match and match.group(1) in pid_table and match.group(1) not in seen:
                seen.add(match.group(1))
                counts[match.group(2)] = counts.get(match.group(2), 0) + 1
        return counts

    def disconnect_ssh(self, username):
        main_pid = self._dropbear_main_pid()
        for session in self.dropbear_sessions():
            if session['username'] != username or session['pid'] == main_pid:
                continue
            identity = self.process_identity(session['pid'])
            if (identity and identity['ppid'] == main_pid and identity['start_ticks'] == session['start_ticks']
                    and identity['boot_id'] == session['boot_id']):
                try:
                    os.kill(session['pid'], signal.SIGTERM)
                except ProcessLookupError:
                    pass

    def online(self, accounts, settings):
        self.settings = settings
        result = []
        sessions = self.ssh_sessions() if any(a['protocol'] == 'ssh' for a in accounts) else {}
        for account in accounts:
            if account['status'] != 'active':
                continue
            item = {'username': account['username'], 'protocol': account['protocol']}
            if account['protocol'] == 'ssh':
                item['sessions'] = sessions.get(account['username'], 0)
            else:
                try:
                    item['ips'] = self.xray_online_ips(account)
                except TunnelCtlError:
                    item['ips'] = []
                    item['error'] = 'xray_api'
            result.append(item)
        return result

    # ------------------------------------------------------------ aktivitas online (tampilan menu)
    #
    # "Terhubung" dan "aktif trafik" adalah dua hal berbeda:
    #   - terhubung : Xray online-map (statsonlineiplist) / proses sesi Dropbear masih hidup.
    #                 Timestamp online-map adalah waktu koneksi DIBUAT, bukan trafik terakhir,
    #                 jadi tidak boleh dipakai untuk menebak idle.
    #   - aktif     : counter trafik bertambah selama jendela pengamatan singkat.
    # Pengamatan hanya dilakukan saat menu meminta; tidak ada timer/daemon/log tambahan.
    # Counter Xray dibaca TANPA -reset agar tidak mengganggu collector kuota (tunnel-usage).
    # Hasil ini khusus tampilan; enforcement limit tetap menghitung semua koneksi terhubung.

    ACTIVITY_STATES = ('active', 'idle', 'unmeasured', 'offline', 'error')

    def _xray_api_server(self):
        return '--server=' + self.settings.get('xray_api', '127.0.0.1:10085')

    def xray_traffic_counters(self):
        """{email: {'up', 'down'}} untuk SEMUA user dalam satu panggilan, tanpa -reset."""
        out = self.runner(['xray', 'api', 'statsquery', self._xray_api_server(), '-pattern', 'user>>>'], timeout=30)
        parsed = json.loads(out) if out.strip() else {}
        if not isinstance(parsed, dict):
            raise ValueError('Respons stats tidak valid')
        counters = {}
        for item in parsed.get('stat') or []:
            parts = str(item.get('name', '')).split('>>>')
            if len(parts) != 4 or parts[0] != 'user' or parts[2] != 'traffic' or parts[3] not in ('uplink', 'downlink'):
                continue
            value = int(item.get('value', 0) or 0)  # protobuf JSON menghilangkan nilai 0
            if value < 0:
                raise ValueError('Counter negatif')
            entry = counters.setdefault(parts[1], {'up': 0, 'down': 0})
            entry['up' if parts[3] == 'uplink' else 'down'] += value
        return counters

    def _counter_epoch(self):
        """Penanda yang berubah jika Xray restart atau collector kuota (memakai -reset) berjalan.

        Mengembalikan (epoch, busy). epoch None berarti tidak bisa dipastikan."""
        try:
            out = self.runner(['systemctl', 'show', 'xray.service', 'tunnel-usage.service', '--no-pager',
                               '-p', 'Id', '-p', 'MainPID', '-p', 'ExecMainStartTimestampMonotonic',
                               '-p', 'ActiveState'], timeout=10)
        except TunnelCtlError:
            return None, False
        units = {}
        for block in out.strip().split('\n\n'):
            values = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
            if values.get('Id'):
                units[values['Id']] = values
        xray = units.get('xray.service', {})
        usage = units.get('tunnel-usage.service', {})
        busy = usage.get('ActiveState') in ('activating', 'active', 'reloading')
        epoch = (xray.get('MainPID'), xray.get('ExecMainStartTimestampMonotonic'),
                 usage.get('ExecMainStartTimestampMonotonic'))
        return epoch, busy

    def _process_io_bytes(self, pid, start_ticks):
        """rchar+wchar proses sesi Dropbear; None jika proses sudah berganti/hilang/tidak terbaca."""
        identity = self.process_identity(pid)
        if identity is None or identity['start_ticks'] != start_ticks:
            return None
        try:
            proc_root = getattr(self, 'proc_root', Path('/proc'))
            values = dict(line.split(':', 1) for line in (proc_root / str(int(pid)) / 'io').read_text().splitlines()
                          if ':' in line)
            return int(values['rchar']) + int(values['wchar'])
        except (OSError, KeyError, ValueError):
            return None

    @staticmethod
    def classify_xray(ips, before, after, interfered):
        """Status satu akun Xray dari online-map dan dua snapshot counter.

        before/after: {'up','down'} atau None jika snapshot gagal."""
        connected = len(ips)
        if before is None or after is None:
            return ('unmeasured' if connected else 'offline'), None
        delta_up = after['up'] - before['up']
        delta_down = after['down'] - before['down']
        if delta_up < 0 or delta_down < 0:
            # Counter di-reset (collector/restart) di tengah pengamatan: hanya trafik setelah reset yang pasti.
            state = 'active' if after['up'] + after['down'] > 0 else 'unmeasured'
            delta = None
        elif delta_up + delta_down > 0:
            state, delta = 'active', delta_up + delta_down
        elif interfered:
            state, delta = 'unmeasured', None
        else:
            state, delta = 'idle', 0
        if not connected and state != 'active':
            return 'offline', None
        return state, delta

    def online_activity(self, accounts, settings, interval=3.0):
        """Snapshot terhubung + aktivitas trafik untuk akun aktif; satu jendela pengamatan untuk semua."""
        from concurrent.futures import ThreadPoolExecutor
        self.settings = settings
        interval = min(max(float(interval), 1.0), 10.0)
        active = [a for a in accounts if a['status'] == 'active']
        xray_accounts = [a for a in active if a['protocol'] != 'ssh']
        ssh_accounts = [a for a in active if a['protocol'] == 'ssh']
        started = time.monotonic()

        epoch_a, busy_a = self._counter_epoch()
        counters_a = None
        if xray_accounts:
            try:
                counters_a = self.xray_traffic_counters()
            except (TunnelCtlError, ValueError):
                counters_a = None

        ssh_error = False
        ssh_sessions = []
        ssh_io_a = {}
        if ssh_accounts:
            try:
                ssh_sessions = self.dropbear_sessions()
                # Pengaman: sesi yang menunjuk proses UTAMA dropbear-tunnel berarti parser sesi lama
                # (journal _PID) masih terpasang; trafik proses utama = trafik semua user, jadi jangan dipakai.
                main_pid = self.runner(['systemctl', 'show', 'dropbear-tunnel.service', '-p', 'MainPID', '--value'],
                                       timeout=10).strip()
                if any(str(s['pid']) == main_pid for s in ssh_sessions):
                    ssh_error = True
                    ssh_sessions = []
            except (TunnelCtlError, OSError, ValueError):
                ssh_error = True
            for session in ssh_sessions:
                ssh_io_a[session['pid']] = self._process_io_bytes(session['pid'], session['start_ticks'])

        def read_ips(account):
            try:
                return account['id'], self.xray_online_ips(account), None
            except (TunnelCtlError, ValueError) as exc:
                return account['id'], [], type(exc).__name__
        ip_results = {}
        if xray_accounts:
            with ThreadPoolExecutor(max_workers=min(8, len(xray_accounts))) as pool:
                for account_id, ips, error in pool.map(read_ips, xray_accounts):
                    ip_results[account_id] = (ips, error)

        remaining = interval - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)

        counters_b = None
        if xray_accounts and counters_a is not None:
            try:
                counters_b = self.xray_traffic_counters()
            except (TunnelCtlError, ValueError):
                counters_b = None
        ssh_io_b = dict((s['pid'], self._process_io_bytes(s['pid'], s['start_ticks'])) for s in ssh_sessions)
        epoch_b, busy_b = self._counter_epoch()
        elapsed = time.monotonic() - started
        interfered = epoch_a is None or epoch_b is None or epoch_a != epoch_b or busy_a or busy_b

        items = []
        for account in xray_accounts:
            ips, error = ip_results.get(account['id'], ([], 'missing'))
            item = {'username': account['username'], 'protocol': account['protocol'],
                    'ip_limit': int(account.get('ip_limit') or 0), 'ips': ips, 'connected': len(ips)}
            if error:
                item.update(state='error', error='xray_api', delta_bytes=None)
            else:
                email = account['username'] + '@' + account['protocol']
                before = None if counters_a is None else counters_a.get(email, {'up': 0, 'down': 0})
                after = None if counters_b is None else counters_b.get(email, {'up': 0, 'down': 0})
                state, delta = self.classify_xray(ips, before, after, interfered)
                item.update(state=state, delta_bytes=delta)
            items.append(item)

        by_user = {}
        for session in ssh_sessions:
            by_user.setdefault(session['username'], []).append(session)
        for account in ssh_accounts:
            item = {'username': account['username'], 'protocol': 'ssh', 'ip_limit': int(account.get('ip_limit') or 0)}
            if ssh_error:
                item.update(state='error', error='dropbear_sessions', sessions=0, connected=0, delta_bytes=None)
                items.append(item)
                continue
            alive, delta, unknown = 0, 0, False
            for session in by_user.get(account['username'], []):
                a, b = ssh_io_a.get(session['pid']), ssh_io_b.get(session['pid'])
                if b is None and a is not None and self.process_identity(session['pid']) is None:
                    continue  # sesi berakhir selama pengamatan
                alive += 1
                if a is None or b is None or b < a:
                    unknown = True
                else:
                    delta += b - a
            if not alive:
                state = 'offline'
            elif delta > 0:
                state = 'active'
            elif unknown:
                state = 'unmeasured'
            else:
                state = 'idle'
            item.update(state=state, sessions=alive, connected=alive,
                        delta_bytes=delta if state in ('active', 'idle') else None)
            items.append(item)
        return {'interval': round(elapsed, 1), 'interfered': bool(interfered),
                'measured_at': datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
                'items': items}

    def status(self):
        result = {}
        for service in self.SERVICES:
            try:
                result[service] = self.runner(['systemctl', 'is-active', service]) == 'active'
            except TunnelCtlError:
                result[service] = False
        return result

    def doctor(self, settings):
        """Fail closed on missing services, listeners, certificate, time or DB."""
        import sqlite3
        checks = {}
        errors = []
        def probe(name, fn):
            try:
                checks[name] = bool(fn())
            except Exception as exc:
                checks[name] = False
                errors.append({'check': name, 'error': type(exc).__name__})
        required = settings.get('doctor_services', ['haproxy', 'xray', 'dropbear-tunnel'])
        probe('services', lambda: all(self.runner(['systemctl', 'is-active', service]) == 'active' for service in required))
        def database():
            uri = 'file:' + str(Path(settings['db_path']).resolve()) + '?mode=ro'
            connection = sqlite3.connect(uri, uri=True)
            try:
                return (connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
                        and not connection.execute('PRAGMA foreign_key_check').fetchall()
                        and connection.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0] == '1'
                        and os.stat(settings['db_path']).st_mode & 0o777 == 0o600)
            finally:
                connection.close()
        probe('db', database)
        def listeners():
            raw = self.ports()
            expected = {int(settings['ports'][key]) for key in ('http', 'https')}
            internal = {int(p) for p in settings['ports'].get('udpgw', [])}
            base = json.loads(Path(settings['xray_base_path']).read_text())
            internal.update(int(i['port']) for i in base.get('inbounds', []) if 'port' in i)
            internal.update(int(p) for p in settings.get('doctor_internal_ports', []))
            observed = set()
            loopback = set()
            allowed = expected | {int(settings.get('ssh_admin_port', 22))}
            allowed.update(int(p) for p in settings.get('extra_http_ports', []) + settings.get('extra_https_ports', []))
            allowed.update(int(p) for p in settings.get('ssh_admin_extra_ports', []))
            for line in raw.splitlines():
                fields = line.split()
                if len(fields) < 4 or fields[0] != 'LISTEN': continue
                address, port = fields[3].rsplit(':', 1)
                port = int(port)
                observed.add(port)
                host = address.strip('[]').split('%', 1)[0]
                try:
                    is_loopback = ipaddress.ip_address(host).is_loopback
                except ValueError:
                    is_loopback = False
                if is_loopback:
                    loopback.add(port)
                elif port not in allowed:
                    return False
            return expected <= observed and internal <= loopback
        probe('ports', listeners)
        def certificate():
            path = settings.get('cert_path', '/etc/haproxy/certs/' + settings['domain'] + '.pem')
            if Path(path).is_symlink() or os.stat(path).st_mode & 0o777 != 0o600: return False
            self.runner(['openssl', 'x509', '-in', path, '-noout', '-checkend', '0'])
            # IP mode (no domain configured yet): the self-signed certificate carries an IP SAN.
            flag = '-checkip' if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', str(settings['domain'])) else '-checkhost'
            output = self.runner(['openssl', 'x509', '-in', path, '-noout', flag, settings['domain']])
            return 'does match certificate' in output and 'does NOT match' not in output
        probe('cert', certificate)
        probe('time', lambda: self.runner(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value']).strip() == 'yes')
        def configs():
            self.runner(list(settings.get('xray_validate_cmd', ['xray', 'run', '-test', '-config'])) + [settings['xray_config_path']])
            self.runner(['haproxy', '-c', '-f', settings.get('haproxy_config_path', '/etc/haproxy/haproxy.cfg')])
            self.runner(['nginx', '-t'])
            return True
        probe('configs', configs)
        mandatory = settings.get('doctor_required_checks', ['services', 'db', 'ports', 'time'])
        return {'ok': all(checks.get(key, False) for key in mandatory), 'checks': checks, 'errors': errors}

    def info(self, settings):
        return {
            'domain': settings.get('domain'),
            'timezone': settings.get('timezone'),
            'cert_mode': settings.get('cert_mode'),
            'services': self.status(),
        }

    def ports(self):
        return self.runner(['ss', '-tlnp'])

    def restart(self, service):
        selected = self.SERVICES if service == 'all' else (service,)
        if any(item not in self.SERVICES for item in selected):
            raise ValueError('Service tidak diizinkan')
        for item in selected:
            self.runner(['systemctl', 'restart', item])
        return self.status()

    def cert_renew(self, settings):
        script = settings.get('cert_renew_cmd')
        if not script:
            raise TunnelCtlError('Perintah renew sertifikat belum dikonfigurasi')
        if isinstance(script, str):
            args = script.split()
        else:
            args = list(script)
        self.runner(args)
        return {'renewed': True, 'domain': settings.get('domain')}

    def migrate_domain(self, old_domain, new_domain, settings, apply=False, rollback=False):
        command = settings.get('domain_migration_cmd')
        if not command:
            return {'ok': False, 'reason': 'migration_hook_not_configured'}
        args = command.split() if isinstance(command, str) else list(command)
        payload = json.dumps({'old_domain': old_domain, 'new_domain': new_domain, 'apply': bool(apply), 'rollback': bool(rollback)})
        output = self.runner(args, input=payload)
        try:
            report = json.loads(output)
        except (ValueError, TypeError):
            raise TunnelCtlError('Hook migrasi tidak mengembalikan hasil verifikasi')
        if not isinstance(report, dict) or report.get('ok') is not True:
            raise TunnelCtlError('Verifikasi hook migrasi gagal')
        if apply and not all(report.get(key) is True for key in ('cert', 'configs', 'exports', 'runtime')):
            raise TunnelCtlError('Hook migrasi belum memverifikasi semua komponen')
        return report

    def bandwidth(self, mode='daily'):
        if mode not in ('daily', 'monthly'):
            raise ValueError('Mode bandwidth tidak valid')
        args = ['vnstat', '--json']
        if mode == 'monthly':
            args.append('-m')
        else:
            args.append('-d')
        out = self.runner(args)
        data = json.loads(out)
        if not isinstance(data, dict):
            raise TunnelCtlError('Output vnstat tidak valid')
        return {'mode': mode, 'data': data}

    def logs(self, service, follow=False):
        if service not in self.SERVICES and service not in ('tunnel-usage.timer', 'tunnel-limit.timer', 'tunnel-expiry.timer'):
            raise ValueError('Service log tidak diizinkan')
        args = ['journalctl', '-u', service, '--no-pager']
        if follow:
            args.extend(['-n', '200', '-f'])
            self.runner(args, timeout=None, capture=False)
            return ''
        else:
            args.extend(['-n', '200'])
        return self.runner(args)

    def _autoreboot_paths(self, settings):
        unit = settings.get('autoreboot_unit', 'tunnel-autoreboot.timer')
        base = Path(settings.get('systemd_dir', '/etc/systemd/system'))
        return unit, base / unit, base / (unit + '.d') / 'schedule.conf'

    def _systemctl_value(self, args):
        try:
            return self.runner(['systemctl'] + args).strip()
        except TunnelCtlError:
            return ''

    def get_autoreboot(self, settings):
        """Schedule state read from systemd itself (settings.json is rewritten by Ansible)."""
        unit, unit_file, dropin = self._autoreboot_paths(settings)
        schedule = None
        if dropin.exists() and not dropin.is_symlink():
            found = re.findall(r'^OnCalendar=\*-\*-\* (\d{2}:\d{2}):00\s*$', dropin.read_text(), re.M)
            schedule = found[-1] if found else None
        enabled = self._systemctl_value(['is-enabled', unit]) == 'enabled'
        active = self._systemctl_value(['is-active', unit]) == 'active'
        next_run = self._systemctl_value(['show', unit, '-p', 'NextElapseUSecRealtime', '--value']) or None
        return {'unit': unit, 'installed': unit_file.exists(), 'enabled': enabled, 'active': active,
                'time': schedule, 'next': next_run if (enabled and active) else None}

    def set_autoreboot(self, settings, value):
        unit, unit_file, dropin = self._autoreboot_paths(settings)
        if not unit_file.exists():
            raise TunnelCtlError('Unit {0} belum terpasang; jalankan ulang bootstrap.sh atau site.yml.'.format(unit))
        legacy = dropin.parent / 'override.conf'  # written by the previous implementation (Persistent=true)
        if legacy.exists() and not legacy.is_symlink():
            legacy.unlink()
        if value is None:
            self.runner(['systemctl', 'disable', '--now', unit])
            if dropin.exists() and not dropin.is_symlink():
                dropin.unlink()
            self.runner(['systemctl', 'daemon-reload'])
        else:
            dropin.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            atomic_write(dropin, '# Managed by tunnelctl (menu Auto-reboot)\n[Timer]\nOnCalendar=\n'
                                 'OnCalendar=*-*-* {0}:00\n'.format(value))
            os.chmod(str(dropin), 0o644)
            self.runner(['systemctl', 'daemon-reload'])
            self.runner(['systemctl', 'enable', unit])
            self.runner(['systemctl', 'restart', unit])  # recompute the next elapse from the new schedule
        result = self.get_autoreboot(settings)
        result['autoreboot'] = value
        return result

    def clean_logs(self):
        self.runner(['journalctl', '--vacuum-time=7d'])
        for log in (Path('/var/log/xray/access.log'), Path('/var/log/xray/error.log')):
            if log.exists() and not log.is_symlink():
                # Truncate in place: Xray keeps its file descriptor, so replacing the file would hide new logs.
                with open(str(log), 'r+b') as handle:
                    handle.truncate(0)
        return {'cleaned': True}

    def timers(self, action):
        if action not in ('start', 'stop'):
            raise ValueError('Aksi timer tidak valid')
        available = []
        for unit in self.TIMERS:
            state = self.runner(['systemctl', 'show', unit, '-p', 'LoadState', '--value']).strip()
            if state == 'not-found':
                continue
            if state != 'loaded':
                raise TunnelCtlError('Status unit timer tidak valid: ' + unit)
            available.append(unit)
        if available:
            self.runner(['systemctl', action] + available)
        return {'ok': True, 'units': available}
