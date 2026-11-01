"""SQLite migration and locking boundary."""
import contextlib
import fcntl
import os
import sqlite3
from pathlib import Path


class Database:
    def __init__(self, path, lock_path=None):
        self._lock_depth = 0
        self.path = str(path)
        self.lock_path = lock_path or self.path + '.lock'
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if Path(self.path).is_symlink():
            raise ValueError('Database symlink tidak diizinkan')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        os.close(fd)
        self.connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('PRAGMA foreign_keys=ON')
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.execute('PRAGMA busy_timeout=30000')
        with self.lock():
            found = self.connection.execute("SELECT name FROM sqlite_master WHERE name='schema_meta'").fetchone()
            current = self.version() if found else 0
            migrations = sorted((Path(__file__).parent / 'migrations').glob('*.sql'))
            if current > len(migrations):
                raise ValueError('Schema lebih baru tidak didukung')
            for migration in migrations:
                version = int(migration.name.split('_')[0])
                if version > current:
                    self.connection.executescript('BEGIN IMMEDIATE;\n' + migration.read_text() + '\nCOMMIT;')
                    self.connection.execute("UPDATE schema_meta SET value=? WHERE key='schema_version'", (str(version),))
        for suffix in ('-wal', '-shm'):
            if os.path.exists(self.path + suffix):
                os.chmod(self.path + suffix, 0o600)

    def version(self):
        return int(self.connection.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0])

    @contextlib.contextmanager
    def lock(self):
        if self._lock_depth > 0:
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
            return
        Path(self.lock_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._lock_depth = 1
            try:
                yield
            finally:
                self._lock_depth = 0
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def transaction(self):
        with self.lock():
            self.connection.execute('BEGIN IMMEDIATE')
            try:
                yield self.connection
                self.connection.commit()
            except BaseException:
                self.connection.rollback()
                raise

    def close(self):
        self.connection.close()
