#!/usr/bin/env python3
"""Build an audited source-only ZIP from explicit deployment paths."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile

ROLES = ('common', 'firewall', 'certs', 'openssh_admin', 'dropbear', 'badvpn',
         'wsepro', 'xray', 'nginx', 'haproxy', 'fail2ban', 'backup', 'tunnelctl', 'preflight')
#PLAYBOOKS = ('prepare-server.yml', 'commit-server.yml', 'site.yml', 'verify.yml', 'backup.yml', 'restore.yml', 'update.yml', 'uninstall.yml')
PLAYBOOKS = (
    'prepare-packages.yml',
    'prepare-speedtest.yml',
    'prepare-server.yml',
    'commit-server.yml',
    'site.yml',
    'verify.yml',
    'backup.yml',
    'restore.yml',
    'update.yml',
    'uninstall.yml',
)
TOP_FILES = ('README.md', 'requirements.yml', 'docs/LICENSING.md', 'docs/RELEASE.md',
             'release/build-release.py', 'release/bootstrap.sh', 'release/requirements.txt',
             'release/ansible.cfg')
OVERRIDES = {'bootstrap.sh': 'release/bootstrap.sh', 'requirements.txt': 'release/requirements.txt',
             'ansible.cfg': 'release/ansible.cfg'}
MAX_FILE_BYTES = 2 * 1024 * 1024
SECRET_PATTERNS = (
    rb'172\.16\.1\.(?:104|105)\b',
    rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    rb'AGE-SECRET-KEY-[A-Z0-9]+',
    rb'(?im)^\s*(?:ansible_password|ansible_ssh_pass|vault_[a-z_]+|cloudflare_api_token|backup_passphrase)\s*:\s*["\']?(?!\{\{|["\']?\s*$)[A-Za-z0-9+/]{12,}',
    rb'(?im)^\s*[a-z0-9_]*(?:token|password|secret|passphrase)\s*:\s*["\']?(?!\{\{|["\']?\s*$)[A-Za-z0-9._/+:-]{12,}',
)
def collect(root):
    """Only named deployment trees and text extensions are eligible."""
    root = Path(root)
    paths: set[str] = set(TOP_FILES)
    paths.update('playbooks/' + name for name in PLAYBOOKS)
    paths.update(OVERRIDES.values())
    for role in ROLES:
        for path in (root / 'roles' / role).rglob('*'):
            rel = path.relative_to(root)
            if '__pycache__' not in rel.parts and path.suffix in ('.yml', '.j2', '.patch'):
                paths.add(rel.as_posix())
    # Include package lists and all supported OS manifests.
    for path in (root / 'playbooks' / 'vars').rglob('*.yml'):
        paths.add(path.relative_to(root).as_posix())
    for tree, suffixes in [('files/tunnelctl/tunnelctl', ('.py', '.sql')),
                           ('inventories/new-server', ('.yml',))]:
        for path in (root / tree).rglob('*'):
            if '__pycache__' not in path.parts and path.suffix in suffixes:
                paths.add(path.relative_to(root).as_posix())
    # site/verify load these by relative path even with a custom inventory.
    paths.update(('inventories/example/group_vars/all/main.yml',
                  'inventories/example/group_vars/all/versions.yml'))
    entries = {}
    for relative in sorted(paths):
        path = root / relative
        if any((root / Path(*Path(relative).parts[:i])).is_symlink()
               for i in range(1, len(Path(relative).parts) + 1)):
            raise ValueError('Symlink source rejected: ' + relative)
        if not path.is_file():
            raise ValueError('Required source missing: ' + relative)
        payload = path.read_bytes()
        if len(payload) > MAX_FILE_BYTES or b'\x00' in payload:
            raise ValueError('Binary/oversized source rejected: ' + relative)
        payload.decode('utf-8')
        for pattern in SECRET_PATTERNS:
            if re.search(pattern, payload):
                raise ValueError('Sensitive content rejected: ' + relative)
        entries[relative] = payload
    for destination, source in OVERRIDES.items():
        entries[destination] = entries[source]
    return entries


def build(root, output):
    """Audit before writing; never overwrite an existing artifact."""
    root = Path(root)
    entries = collect(root)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = {name: {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
                for name, data in sorted(entries.items())}
    entries['RELEASE-MANIFEST.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    try:
        with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(entries.items()):
                info = zipfile.ZipInfo('tunnel-gateway/' + name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                mode = 0o755 if name.endswith(('.sh', 'build-release.py')) else 0o644
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
        with zipfile.ZipFile(output) as archive:
            if archive.testzip() is not None:
                raise ValueError('Archive CRC verification failed')
    except FileExistsError:
        raise
    except Exception:
        if output.exists():
            output.unlink()
        raise
    return {'path': str(output.resolve()), 'files': len(entries),
            'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, default=Path('/root/tunnel-gateway-release.zip'))
    parser.add_argument('--audit-only', action='store_true', help='Validate sources; write no ZIP')
    args = parser.parse_args()
    root = Path(args.root)
    if args.audit_only:
        print(json.dumps({'audited_files': len(collect(root)), 'archive_written': False}))
    else:
        print(json.dumps(build(root, args.output)))


if __name__ == '__main__':
    main()
