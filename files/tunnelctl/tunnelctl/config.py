import json
import os
from pathlib import Path

from .errors import InputError

DEFAULT_SETTINGS = {
    'domain': 'localhost',
    'cert_mode': 'selfsigned',
    'timezone': 'UTC',
    'xray_base_path': '/etc/tunnel/xray/base.json',
    'xray_config_path': '/etc/tunnel/xray/config.json',
    'xray_validate_cmd': ['xray', 'run', '-test', '-config'],
    'db_path': '/var/lib/tunnel/tunnel.db',
    'lock_path': '/run/tunnel/tunnel.lock',
    'settings_path': '/etc/tunnel/settings.json',
    'backup_dir': '/var/backups/tunnel',
    'exports_dir': '/var/lib/tunnel/exports',
    'ws_paths': {'vmess': '/vmess', 'vless': '/vless', 'trojan': '/trojan', 'ss': '/ss'},
    'grpc_names': {'vmess': 'vmess-grpc', 'vless': 'vless-grpc', 'trojan': 'trojan-grpc'},
    'ports': {'http': 80, 'https': 443, 'udpgw': [7300]},
    'defaults': {'days': 30, 'trial_hours': 1, 'quota_bytes': 0, 'ip_limit': 0, 'lock_minutes': 15},
    'expired_grace_days': 3,
    'ip_window_seconds': 90,
    'allow_non_root_test_backend': False,
}


def _deep_merge(base, patch):
    out = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_settings(path=None, overrides=None):
    config = dict(DEFAULT_SETTINGS)
    source = path or DEFAULT_SETTINGS['settings_path']
    if source and os.path.exists(source):
        raw = json.loads(Path(source).read_text())
        if not isinstance(raw, dict):
            raise InputError('settings.json harus object')
        config = _deep_merge(config, raw)
    if overrides:
        config = _deep_merge(config, overrides)
    if not isinstance(config.get('domain'), str) or not config['domain']:
        raise InputError('domain wajib diisi')
    return config
