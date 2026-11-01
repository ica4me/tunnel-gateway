import datetime as _dt
import ipaddress
import json
import re
import uuid

from .errors import InputError

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")


def utcnow():
    return _dt.datetime.now(_dt.timezone.utc)


def iso_utc(dt_value):
    if dt_value.tzinfo is None:
        dt_value = dt_value.replace(tzinfo=_dt.timezone.utc)
    return dt_value.astimezone(_dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def parse_utc(value):
    if value.endswith('Z'):
        value = value[:-1] + '+00:00'
    return _dt.datetime.fromisoformat(value).astimezone(_dt.timezone.utc)


def parse_size(value):
    if value is None:
        return None
    if isinstance(value, int):
        if value < 0:
            raise InputError('Ukuran tidak boleh negatif')
        return value
    text = str(value).strip().upper()
    if text.isdigit():
        return int(text)
    units = {'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3, 'T': 1024 ** 4}
    suffix = text[-1:]
    if suffix not in units:
        raise InputError('Format kuota tidak valid')
    number = text[:-1]
    if not number.isdigit():
        raise InputError('Format kuota tidak valid')
    return int(number) * units[suffix]


def validate_username(username):
    if not USERNAME_RE.match(username):
        raise InputError('Username harus 3-32 karakter huruf kecil/angka/underscore')
    return username


def validate_protocol(protocol):
    allowed = {'ssh', 'vmess', 'vless', 'trojan', 'ss'}
    if protocol not in allowed:
        raise InputError('Protokol tidak valid')
    return protocol


def normalize_ips(values):
    seen = []
    for raw in values:
        text = str(raw).strip()
        if not text:
            continue
        if text.startswith('[') and text.endswith(']'):
            text = text[1:-1]
        try:
            parsed = ipaddress.ip_address(text)
        except ValueError:
            continue
        packed = parsed.compressed
        if packed not in seen:
            seen.append(packed)
    return seen


def validate_secret(protocol, secret, regen=False):
    if regen:
        if protocol in ('vmess', 'vless'):
            return str(uuid.uuid4())
        raise InputError('--regen hanya untuk VMess/VLESS')
    if secret is None:
        if protocol in ('vmess', 'vless'):
            return str(uuid.uuid4())
        raise InputError('Password wajib diisi untuk protokol ini')
    text = str(secret).strip()
    if protocol in ('vmess', 'vless'):
        try:
            return str(uuid.UUID(text))
        except Exception as exc:
            raise InputError('UUID tidak valid') from exc
    if len(text) < 1:
        raise InputError('Password kosong tidak diizinkan')
    if '\n' in text or '\r' in text:
        raise InputError('Password tidak boleh mengandung newline')
    return text


def json_dumps(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True)
