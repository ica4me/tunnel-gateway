"""Shared terminal helpers for the interactive menu (display only, stdlib only)."""
import contextlib
import datetime
import io
import json
import os
import re
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from .cli import run

WIDTH = 78
USERNAME_RE = re.compile(r'^[a-z0-9_]{3,32}$')
IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
PROTOCOLS = ('ssh', 'vmess', 'vless', 'trojan', 'ss')
PROTO_NAME = {'ssh': 'SSH WebSocket', 'vmess': 'VMess', 'vless': 'VLESS', 'trojan': 'Trojan', 'ss': 'Shadowsocks'}
STATUS_LABEL = {'active': 'aktif', 'locked': 'terkunci', 'expired': 'expired',
                'quota_exceeded': 'kuota habis', 'limit_locked': 'kunci limit'}
STATUS_COLOR = {'active': '32', 'locked': '31', 'expired': '31',
                'quota_exceeded': '33', 'limit_locked': '33'}
GREEN, RED, YELLOW, CYAN = '32', '31', '33', '1;36'


def _utf8():
    return (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') == 'utf8'


UNLIMITED = '\u221e' if _utf8() else 'unlim'
MARK_OK = '\u2714' if _utf8() else '+'
MARK_BAD = '\u2718' if _utf8() else 'x'


# ---------------------------------------------------------------- output

def is_ip(value):
    """True while no domain is configured (gateway runs on its IP, self-signed)."""
    return bool(IP_RE.match(str(value or '')))


def paint(text, code):
    if code and sys.stdout.isatty() and not os.environ.get('NO_COLOR'):
        return '\033[{0}m{1}\033[0m'.format(code, text)
    return text


def write(line=''):
    sys.stdout.write(line + '\n')


def write_lines(lines):
    for line in lines:
        write(line)


def clear():
    if sys.stdout.isatty() and os.environ.get('TERM'):
        sys.stdout.write('\033[2J\033[H')


def pause():
    ask('\nTekan Enter untuk kembali...')


def title(text):
    write(paint('=== {0} ==='.format(text), CYAN))


def ok(text):
    write(paint('Berhasil: ' + text, GREEN))


def fail(text):
    write(paint('Gagal: ' + text, RED))


def note(text):
    for line in textwrap.wrap(text, WIDTH - 2):
        write(' ' + line)


def fit(text, width):
    text = str(text)
    return text if len(text) <= width else text[:width - 1] + '~'


# ---------------------------------------------------------------- formatting

def size(num):
    num = float(num or 0)
    for unit, factor in (('T', 1024 ** 4), ('G', 1024 ** 3), ('M', 1024 ** 2), ('K', 1024)):
        if num >= factor:
            pattern = '{0:.1f}{1}' if unit in ('T', 'G') else '{0:.0f}{1}'
            return pattern.format(num / factor, unit)
    return '{0:.0f}B'.format(num)


def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None


def local_time(value, fmt='%Y-%m-%d %H:%M'):
    ts = parse_ts(value)
    return ts.astimezone().strftime(fmt) if ts else '-'


def duration(seconds):
    seconds = int(max(0, seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return '{0} hari {1} jam'.format(days, hours)
    if hours:
        return '{0} jam {1} mnt'.format(hours, minutes)
    return '{0} mnt'.format(max(1, minutes))


def remaining(value):
    ts = parse_ts(value)
    if ts is None:
        return '-'
    seconds = (ts - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    if seconds <= 0:
        return 'habis'
    if seconds < 3600:
        return '{0} mnt'.format(max(1, int(seconds // 60)))
    if seconds < 86400:
        return '{0} jam'.format(int(seconds // 3600))
    return '{0} hari'.format(int(seconds // 86400))


def ago(epoch):
    return duration(time.time() - epoch) + ' lalu'


def short_ts(value):
    # 'Sun 2026-11-01 11:38:17 WIB' -> '2026-11-01 11:38'
    parts = str(value or '').split()
    if len(parts) >= 3 and re.match(r'^\d{4}-\d{2}-\d{2}$', parts[1]):
        return parts[1] + ' ' + parts[2][:5]
    return '-'


# ---------------------------------------------------------------- tables

def table(headers, rows, widths, right=()):
    """Column table; a cell may be text or (text, color)."""
    def cell(value, index):
        text, color = value if isinstance(value, tuple) else (value, None)
        text = fit('' if text is None else text, widths[index])
        text = text.rjust(widths[index]) if index in right else text.ljust(widths[index])
        return paint(text, color)
    head = ' ' + ' '.join(h.rjust(w) if i in right else h.ljust(w)
                          for i, (h, w) in enumerate(zip(headers, widths)))
    lines = [head.rstrip(), '-' * len(head)]
    for row in rows:
        lines.append((' ' + ' '.join(cell(v, i) for i, v in enumerate(row))).rstrip())
    return lines


def box(rows, label_width=18, width=WIDTH, color=True):
    """Two-column bordered table. Rows: ('#', SECTION) or (label, value[, color])."""
    value_width = width - label_width - 7
    border = '+' + '-' * (label_width + 2) + '+' + '-' * (value_width + 2) + '+'
    full = '+' + '-' * (label_width + value_width + 5) + '+'
    lines = []
    for row in rows:
        if row[0] == '#':
            lines.append(full)
            text = str(row[1]).ljust(label_width + value_width + 3)
            lines.append('| ' + (paint(text, CYAN) if color else text) + ' |')
            lines.append(border)
            continue
        label, value = row[0], row[1]
        shade = row[2] if len(row) > 2 else None
        chunks = textwrap.wrap(str(value if value not in (None, '') else '-'), value_width,
                               break_long_words=True, break_on_hyphens=False) or ['-']
        for index, chunk in enumerate(chunks):
            cell = chunk.ljust(value_width)
            if shade and color:
                cell = paint(cell, shade)
            lines.append('| {0} | {1} |'.format((label if index == 0 else '').ljust(label_width)[:label_width], cell))
    if not lines or lines[-1] != border:
        lines.append(border)
    return lines


# ---------------------------------------------------------------- input

def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        return ''


def ask_yes(prompt, default=False):
    answer = ask(prompt).lower()
    if not answer:
        return default
    return answer in ('y', 'ya', 'yes')


def ask_int(prompt, minimum=1, default=None):
    while True:
        text = ask(prompt)
        if text in ('', 'q', 'Q'):
            return default
        if text.isdigit() and int(text) >= minimum:
            return int(text)
        write('Masukkan angka >= {0} (kosong = {1}).'.format(minimum, 'batal' if default is None else default))


def ask_quota(prompt):
    while True:
        text = ask(prompt).upper()
        if not text:
            return None
        if re.match(r'^[0-9]+[KMGT]?$', text):
            return text
        write('Format tidak valid. Contoh: 30G, 500M, 0.')


def ask_username(prompt='Username (huruf kecil/angka/_ 3-32; kosong = batal): '):
    while True:
        text = ask(prompt)
        if not text:
            return None
        if USERNAME_RE.match(text):
            return text
        write('Username tidak valid. Contoh: budi_01')


# ---------------------------------------------------------------- data

def sh(args, timeout=15):
    """Run a read-only system command; never raises."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.SubprocessError):
        return 127, '', ''


def run_json(args, settings_override=None, backend=None, json_flag=True):
    """Run a tunnelctl command and parse its JSON output; errors still reach stderr."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = run(list(args) + (['--json'] if json_flag else []), settings_override=settings_override, backend=backend)
    text = buffer.getvalue().strip()
    try:
        data = json.loads(text) if json_flag and text else None
    except ValueError:
        data = None
    return code, data


def run_plain(args, settings_override=None, backend=None):
    return run(list(args), settings_override=settings_override, backend=backend)


def settings(settings_override=None):
    from .config import DEFAULT_SETTINGS, load_settings
    override = dict(settings_override or {})
    try:
        return load_settings(path=override.get('settings_path'), overrides=override)
    except Exception:
        return dict(DEFAULT_SETTINGS)


def accounts(settings_override=None, backend=None, protocol=None, **filters):
    from .manager import Manager
    manager = Manager(settings=settings_override, backend=backend)
    try:
        return manager.list(protocol=protocol, **filters)
    finally:
        manager.db.close()


def unit_states(units):
    """Return {unit: {ActiveState, SubState, ...}} with one systemctl call."""
    names = [u if '.' in u else u + '.service' for u in units]
    props = 'Id,LoadState,ActiveState,SubState,ActiveEnterTimestamp,MemoryCurrent,NextElapseUSecRealtime,LastTriggerUSec'
    code, out, _ = sh(['systemctl', 'show', '--no-pager', '-p', props] + names)
    states = {}
    for block in out.strip().split('\n\n'):
        values = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        if values.get('Id'):
            states[values['Id']] = values
    result = {}
    for unit, name in zip(units, names):
        result[unit] = states.get(name, {'LoadState': 'unknown', 'ActiveState': 'unknown'})
    return result


def state_label(values):
    load = values.get('LoadState')
    active = values.get('ActiveState')
    if load == 'not-found':
        return ('tidak ada', YELLOW)
    if active == 'active':
        return ('aktif', GREEN)
    if active == 'failed':
        return ('gagal', RED)
    if active in ('activating', 'reloading'):
        return ('memulai', YELLOW)
    if active == 'inactive':
        return ('mati', RED)
    return (active or '?', YELLOW)


def memory(values):
    raw = values.get('MemoryCurrent', '')
    return size(int(raw)) if raw.isdigit() else '-'


# ---------------------------------------------------------------- network

IPINFO_CACHE = Path('/run/tunnel/ipinfo.json')


def ipinfo(refresh=False, allow_network=True):
    """Public IP/ISP from https://ipinfo.io, cached 1 hour (failures cached 10 minutes)."""
    cached = {}
    try:
        cached = json.loads(IPINFO_CACHE.read_text())
    except (OSError, ValueError):
        cached = {}
    age = time.time() - float(cached.get('fetched', 0) or 0)
    fresh = age < (600 if cached.get('failed') else 3600)
    if (fresh and not refresh) or not allow_network:
        return cached.get('data') or {}
    data = {}
    try:
        import urllib.request
        request = urllib.request.Request('https://ipinfo.io/json',
                                         headers={'Accept': 'application/json', 'User-Agent': 'tunnelctl-menu'})
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
        if not isinstance(data, dict) or not data.get('ip'):
            data = {}
    except Exception:
        data = {}
    record = {'fetched': time.time(), 'data': data or cached.get('data') or {}, 'failed': not data}
    try:
        IPINFO_CACHE.parent.mkdir(parents=True, exist_ok=True)
        IPINFO_CACHE.write_text(json.dumps(record))
        os.chmod(str(IPINFO_CACHE), 0o600)
    except OSError:
        pass
    return record['data']


def local_ip():
    code, out, _ = sh(['ip', '-4', 'route', 'get', '1.1.1.1'], timeout=3)
    match = re.search(r'\bsrc\s+(\S+)', out)
    return match.group(1) if match else ''


def server_ip(allow_network=False):
    return ipinfo(allow_network=allow_network).get('ip') or local_ip() or '-'
