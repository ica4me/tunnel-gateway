"""Consistent SQLite snapshots; bounded, authenticated archive restores."""
import contextlib
import datetime
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath

from .errors import InputError, TunnelCtlError
from .system import atomic_write


def _sha256(path):
    digest = hashlib.sha256()
    with open(str(path), 'rb') as handle:
        for chunk in iter(lambda: handle.read(1048576), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_member(name):
    return bool(name) and not name.startswith('/') and '..' not in PurePosixPath(name).parts and '\\' not in name


def _run_cmd(run_cmd, args):
    if run_cmd:
        return run_cmd(args)
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=180).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise TunnelCtlError('Perintah backup gagal: ' + Path(args[0]).name) from exc


def _manifest_from_files(root, files, schema_version='1', settings=None):
    settings = settings or {}
    return {'project_version': '1.0.0', 'schema_version': int(schema_version),
            'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'hostname': socket.gethostname(), 'domain': settings.get('domain'), 'os': os.uname().sysname,
            'files': [{'path': str(rel), 'size': (root / rel).stat().st_size,
                       'sha256': _sha256(root / rel)} for rel in sorted(files)]}


def create_backup(settings, source_root='/', run_cmd=None, output=None):
    directory = Path(settings['backup_dir'])
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink(): raise InputError('Direktori backup symlink ditolak')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    hostname = re.sub('[^a-zA-Z0-9_-]', '_', socket.gethostname())
    name = 'tunnel-backup-{}-{}-{}'.format(hostname, stamp, uuid.uuid4().hex[:8])
    recipient = settings.get('backup_age_recipient') or settings.get('backup_age_recipient_value')
    recipients_file = settings.get('backup_age_recipients_file') or settings.get('backup_age_key_file')
    if settings.get('backup_passphrase') and not recipient and not recipients_file:
        raise InputError('Backup otomatis memakai kunci age; passphrase interaktif tidak didukung')
    encrypted = bool(recipient or recipients_file)
    suffix = '.tar.zst.age' if encrypted else '.tar.zst'
    target = Path(output) if output else directory / (name + suffix)
    if target.exists() or target.is_symlink(): raise InputError('Output backup sudah ada')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    source = Path(source_root)
    files = []
    for path in source.rglob('*'):
        if path.is_symlink(): raise InputError('Symlink sumber backup ditolak')
        if path.is_file(): files.append(path.relative_to(source).as_posix())
    if not files: raise InputError('Tidak ada data backup')
    with tempfile.TemporaryDirectory(dir=str(directory)) as temporary:
        root = Path(temporary)
        archive = root / 'snapshot.tar'
        manifest = _manifest_from_files(source, files, settings.get('schema_version', 1), settings)
        manifest_path = root / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest, sort_keys=True))
        os.chmod(str(manifest_path), 0o600)
        with tarfile.open(str(archive), 'w') as tf:
            tf.add(str(manifest_path), arcname='manifest.json', recursive=False)
            for rel in files:
                tf.add(str(source / rel), arcname=rel, recursive=False)
        compressed = root / 'snapshot.tar.zst'
        _run_cmd(run_cmd, ['zstd', '-q', '-f', str(archive), '-o', str(compressed)])
        payload = compressed
        if encrypted:
            payload = root / 'snapshot.tar.zst.age'
            args = ['age', '-r', str(recipient)] if recipient else ['age', '-R', str(recipients_file)]
            _run_cmd(run_cmd, args + ['-o', str(payload), str(compressed)])
        atomic_write(target, payload.read_bytes())
    return target


def _materialize_archive(path, workdir, run_cmd=None, age_identity=None):
    source = Path(path)
    if not source.is_file() or source.is_symlink(): raise InputError('File backup tidak ditemukan/aman')
    payload = source
    if source.name.endswith('.age'):
        if not age_identity: raise InputError('Identitas age diperlukan')
        payload = Path(workdir) / 'snapshot.tar.zst'
        _run_cmd(run_cmd, ['age', '-d', '-i', str(age_identity), '-o', str(payload), str(source)])
    if payload.name.endswith('.zst'):
        archive = Path(workdir) / 'snapshot.tar'
        _run_cmd(run_cmd, ['zstd', '-q', '-d', '-f', str(payload), '-o', str(archive)])
        return archive
    return payload


def extract_verified(path, destination, run_cmd=None, age_identity=None):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.is_symlink(): raise ValueError('Symlink tujuan ditolak')
    with tempfile.TemporaryDirectory() as temporary:
        archive = _materialize_archive(path, temporary, run_cmd, age_identity)
        with tarfile.open(str(archive), 'r:') as tf:
            members = tf.getmembers()
            seen = set()
            total = 0
            for member in members:
                name = member.name
                if not _safe_member(name) or name in seen or not member.isfile():
                    raise ValueError('Path/tipe arsip tidak aman')
                seen.add(name)
                total += member.size
                if total > 1073741824 or len(seen) > 10000: raise ValueError('Arsip terlalu besar')
            if 'manifest.json' not in seen: raise ValueError('Manifest hilang')
            manifest_member = tf.getmember('manifest.json')
            if manifest_member.size > 1048576: raise ValueError('Manifest terlalu besar')
            with contextlib.closing(tf.extractfile(manifest_member)) as handle:
                manifest = json.load(handle)
            version = int(manifest['schema_version'])
            if version > 1 or version < 1: raise ValueError('Versi schema tidak didukung')
            listed = [item['path'] for item in manifest['files']]
            if len(listed) != len(set(listed)) or set(listed) != seen - {'manifest.json'}:
                raise ValueError('Daftar file manifest tidak cocok')
            for item in manifest['files']:
                rel = item['path']
                if not _safe_member(rel): raise ValueError('Path manifest tidak aman')
                member = tf.getmember(rel)
                if member.size != item['size']: raise ValueError('Ukuran file tidak cocok')
                full = destination / rel
                full.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with contextlib.closing(tf.extractfile(member)) as source:
                    atomic_write(full, source.read())
                if _sha256(full) != item['sha256']: raise ValueError('Checksum tidak cocok')
            atomic_write(destination / 'manifest.json', json.dumps(manifest))
    return manifest


def verify_backup(path, run_cmd=None, age_identity=None):
    with tempfile.TemporaryDirectory() as temporary:
        manifest = extract_verified(path, Path(temporary) / 'extract', run_cmd, age_identity)
    return {'ok': True, 'files': ['manifest.json'] + [item['path'] for item in manifest['files']], 'schema_version': str(manifest['schema_version']), 'encrypted': str(path).endswith('.age')}


def restore_backup(path, destination, run_cmd=None, age_identity=None):
    # Low-level explicit sandbox extraction only. Runtime restores use Backup.restore mappings.
    with tempfile.TemporaryDirectory() as temporary:
        manifest = extract_verified(path, temporary, run_cmd, age_identity)
        for item in manifest['files']:
            rel = item['path']
            atomic_write(Path(destination) / rel, (Path(temporary) / rel).read_bytes())
    return {'ok': True}


class Backup:
    def __init__(self, manager, run_cmd=None):
        self.manager = manager
        self.run_cmd = run_cmd

    def _mappings(self):
        settings = self.manager.settings
        mappings = {'db/tunnel.db': settings['db_path'], 'etc/tunnel/settings.json': settings['settings_path']}
        for name, key in [('banner.txt', 'banner_path'), ('ws-epro.conf', 'wsepro_config_path'), ('xray/base.json', 'xray_base_path')]:
            if key in settings and Path(settings[key]).exists(): mappings['etc/tunnel/' + name] = settings[key]
        return mappings

    def create(self, output=None):
        manager = self.manager
        with manager.db.lock(), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'db').mkdir(mode=0o700)
            destination = sqlite3.connect(str(root / 'db/tunnel.db'))
            try: manager.db.connection.backup(destination)
            finally: destination.close()
            os.chmod(str(root / 'db/tunnel.db'), 0o600)
            for rel, source in self._mappings().items():
                if rel == 'db/tunnel.db': continue
                if Path(source).exists():
                    if Path(source).is_symlink(): raise InputError('Symlink sumber ditolak')
                    atomic_write(root / rel, Path(source).read_bytes())
            settings = dict(manager.settings, schema_version=manager.db.version())
            result = create_backup(settings, root, self.run_cmd, output)
            keep = int(settings.get('backup_keep', 7))
            if keep < 1: raise InputError('Retensi backup minimal 1')
            for path in self.list()[keep:]:
                if str(path) != str(result): path.unlink()
            return result

    def list(self):
        root = Path(self.manager.settings['backup_dir'])
        return sorted([p for p in root.glob('tunnel-backup-*') if p.is_file() and not p.is_symlink()], key=lambda p: p.stat().st_mtime, reverse=True)

    def verify(self, path):
        return verify_backup(path, self.run_cmd, self.manager.settings.get('backup_age_identity'))

    def restore(self, path, new_domain=None):
        manager = self.manager
        doctor = getattr(manager.backend, 'doctor', None)
        if not callable(doctor):
            raise InputError('Restore memerlukan doctor backend nyata')
        migrate = getattr(manager.backend, 'migrate_domain', None)
        migrate_fn = migrate if callable(migrate) else None
        if new_domain and migrate_fn is None:
            raise InputError('Hook migrasi domain belum dikonfigurasi')
        if new_domain:
            report = migrate_fn(manager.settings.get('domain'), new_domain, manager.settings, apply=False)
            if not isinstance(report, dict) or report.get('ok') is not True:
                raise InputError('Hook migrasi domain belum siap')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = extract_verified(path, root, self.run_cmd, manager.settings.get('backup_age_identity'))
            db_file = root / 'db/tunnel.db'
            if not db_file.exists(): raise InputError('Snapshot DB hilang')
            candidate = sqlite3.connect(str(db_file))
            try:
                if candidate.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise InputError('DB rusak')
                if candidate.execute('PRAGMA foreign_key_check').fetchall(): raise InputError('Referensi DB rusak')
                if int(candidate.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]) != int(manifest['schema_version']): raise InputError('Schema manifest/DB berbeda')
                accounts = [dict(zip([col[0] for col in cursor.description], row)) for cursor in [candidate.execute('SELECT * FROM accounts')] for row in cursor]
            finally: candidate.close()
            mappings = self._mappings()
            listed = set(item['path'] for item in manifest['files'])
            if listed - set(mappings): raise InputError('File snapshot tidak didukung oleh konfigurasi server')
            prior_backup = self.create()
            old_accounts = manager.rows()
            old_settings = dict(manager.settings)
            old_files = {rel: Path(target).read_bytes() if Path(target).exists() else None for rel, target in mappings.items() if rel != 'db/tunnel.db'}
            prior_db = Path(temporary) / 'prior.db'
            snapshot_connection = sqlite3.connect(str(prior_db))
            try: manager.db.connection.backup(snapshot_connection)
            finally: snapshot_connection.close()
            stopped = False
            applied_runtime = False
            applied_domain = False
            domain_before_apply = None
            try:
                manager.backend.timers('stop')
                stopped = True
                with manager.db.lock():
                    source = sqlite3.connect(str(db_file))
                    try: source.backup(manager.db.connection)
                    finally: source.close()
                    for rel, target in mappings.items():
                        if rel not in ('db/tunnel.db', 'etc/tunnel/settings.json') and (root / rel).exists(): atomic_write(target, (root / rel).read_bytes())
                    restored = root / 'etc/tunnel/settings.json'
                    if restored.exists():
                        restored_settings = json.loads(restored.read_text())
                        # Restore logical settings, never source server's destination paths/key identity.
                        for key in ('domain', 'ports', 'ws_paths', 'grpc_names', 'cert_mode', 'defaults', 'ss_method'):
                            if key in restored_settings: manager.settings[key] = restored_settings[key]
                    atomic_write(manager.settings['settings_path'], json.dumps(manager.settings, sort_keys=True, indent=2) + '\n')
                    if new_domain:
                        if migrate_fn is None:
                            raise InputError('Hook migrasi domain belum dikonfigurasi')
                        domain_before_apply = manager.settings.get('domain')
                        apply_report = migrate_fn(domain_before_apply, new_domain, manager.settings, apply=True)
                        if not isinstance(apply_report, dict) or apply_report.get('ok') is not True:
                            raise TunnelCtlError('Migrasi domain gagal diterapkan')
                        applied_domain = True
                        manager.settings['domain'] = new_domain
                        _settings = json.loads(Path(manager.settings['settings_path']).read_text()) if Path(manager.settings['settings_path']).exists() else {}
                        _settings['domain'] = new_domain
                        atomic_write(manager.settings['settings_path'], json.dumps(_settings, sort_keys=True, indent=2) + '\n')
                    manager.backend.reconcile(old_accounts, manager.rows(), manager.settings)
                    applied_runtime = True
                    report = doctor(manager.settings)
                    if not report.get('ok'): raise TunnelCtlError('Doctor gagal setelah restore')
                    manager.event(manager.db.connection, 'restore', actor='restore', detail={'pre_restore_backup': str(prior_backup)})
                return {'ok': True, 'pre_restore_backup': str(prior_backup)}
            except BaseException:
                with manager.db.lock():
                    source = sqlite3.connect(str(prior_db))
                    try: source.backup(manager.db.connection)
                    finally: source.close()
                    manager.settings = old_settings
                    for rel, contents in old_files.items():
                        if contents is not None: atomic_write(mappings[rel], contents)
                        elif Path(mappings[rel]).exists(): Path(mappings[rel]).unlink()
                    if applied_domain:
                        if migrate_fn is None:
                            raise TunnelCtlError('Hook migrasi domain belum dikonfigurasi')
                        rollback_report = migrate_fn(new_domain, old_settings.get('domain'), manager.settings, apply=True, rollback=True)
                        if not isinstance(rollback_report, dict) or rollback_report.get('ok') is not True:
                            raise TunnelCtlError('Rollback migrasi domain gagal')
                    if applied_runtime:
                        manager.backend.reconcile(accounts, old_accounts, manager.settings)
                raise
            finally:
                if stopped: manager.backend.timers('start')
