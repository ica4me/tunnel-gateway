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

    def __init__(self, runner=None, check_root=True):
        self.runner = runner or self._run
        self.settings = {}
        self.check_root = check_root

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
        try:
            proc = Path('/proc') / str(int(pid))
            if Path(os.readlink(str(proc / 'exe'))).name != 'dropbear':
                return None
            stat = (proc / 'stat').read_text()
            fields = stat[stat.rfind(')') + 2:].split()
            start_ticks = fields[19]
            uid_line = next(line for line in (proc / 'status').read_text().splitlines() if line.startswith('Uid:'))
            if int(uid_line.split()[1]) != 0:
                return None
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            return {'start_ticks': start_ticks, 'boot_id': boot}
        except (OSError, ValueError, StopIteration, IndexError):
            return None

    def dropbear_sessions(self):
        raw = self.runner(['journalctl', '-u', 'dropbear-tunnel.service', '-b', '-o', 'json', '--no-pager'])
        sessions = {}
        clock_ticks = os.sysconf('SC_CLK_TCK')
        uptime = float(Path('/proc/uptime').read_text().split()[0])
        boot_time = time.time() - uptime
        for line in raw.splitlines():
            try:
                entry = json.loads(line)
                message = entry.get('MESSAGE', '')
                match = re.search(r"Password auth succeeded for '([^']+)'", message)
                if match is None:
                    match = re.search(r'Password auth succeeded for ([a-z0-9_]+) from ', message)
                if match is None:
                    continue
                pid = int(entry['_PID'])
                identity = self.process_identity(pid)
                if identity is None or entry.get('_BOOT_ID', '').replace('-', '') != identity['boot_id'].replace('-', ''):
                    continue
                auth_time = int(entry['__REALTIME_TIMESTAMP']) / 1000000.0
                if auth_time < boot_time + int(identity['start_ticks']) / clock_ticks - 1:
                    continue
                sessions[pid] = dict(identity, pid=pid, username=match.group(1))
            except (ValueError, KeyError, TypeError):
                continue
        return list(sessions.values())

    def ssh_sessions(self, journal_lines=None, pid_table=None):
        if journal_lines is None:
            counts = {}
            for session in self.dropbear_sessions():
                counts[session['username']] = counts.get(session['username'], 0) + 1
            return counts
        # Fixture-only plain-text parser; live path requires journal boot/start checks.
        counts = {}
        seen = set()
        for line in journal_lines:
            match = re.search(r"dropbear\[([0-9]+)\]: Password auth succeeded for '?([a-z0-9_]+)'? from ", line)
            if match and match.group(1) in pid_table and pid_table[match.group(1)]['uid'] == 0 and match.group(1) not in seen:
                seen.add(match.group(1))
                counts[match.group(2)] = counts.get(match.group(2), 0) + 1
        return counts

    def disconnect_ssh(self, username):
        for session in self.dropbear_sessions():
            if session['username'] != username:
                continue
            identity = self.process_identity(session['pid'])
            if identity and identity['start_ticks'] == session['start_ticks'] and identity['boot_id'] == session['boot_id']:
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

    def set_autoreboot(self, settings, value):
        unit = settings.get('autoreboot_unit', 'tunnel-autoreboot.timer')
        dropin_dir = Path('/etc/systemd/system') / (unit + '.d')
        dropin_file = dropin_dir / 'override.conf'
        if value is None:
            if dropin_file.exists() and not dropin_file.is_symlink():
                dropin_file.unlink()
            self.runner(['systemctl', 'disable', '--now', unit])
            self.runner(['systemctl', 'daemon-reload'])
            return {'autoreboot': None, 'unit': unit}
        dropin_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        content = '[Timer]\nOnCalendar=*-*-* {0}:00\nPersistent=true\n'.format(value)
        atomic_write(dropin_file, content)
        self.runner(['systemctl', 'daemon-reload'])
        self.runner(['systemctl', 'enable', '--now', unit])
        return {'autoreboot': value, 'unit': unit}

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
