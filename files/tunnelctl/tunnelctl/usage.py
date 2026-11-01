"""Durable reset deltas with transactional receipts (not atomic with Xray)."""
import json
import sqlite3
import uuid
from pathlib import Path

from .errors import TunnelCtlError
from .system import atomic_write


def pending_dir(manager):
    return Path(manager.settings.get('usage_pending_dir', manager.settings['db_path'] + '.pending-usage'))


def collect(manager, account, now):
    directory = pending_dir(manager)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink():
        raise TunnelCtlError('Direktori jurnal kuota symlink ditolak')
    # Xray reset and fsync cannot form one transaction. A crash between these
    # operations can lose this sample. Never claim exactly-once across that gap.
    stats = manager.backend.xray_stats(account)
    up, down = int(stats.get('up', 0)), int(stats.get('down', 0))
    if up < 0 or down < 0:
        raise TunnelCtlError('Counter kuota negatif')
    token = uuid.uuid4().hex
    atomic_write(directory / (token + '.json'), json.dumps({
        'token': token, 'account_id': account['id'], 'username': account['username'],
        'protocol': account['protocol'], 'created_at': account['created_at'],
        'day': now.date().isoformat(), 'up': up, 'down': down,
    }, sort_keys=True))


def drain(manager):
    """Apply every durable delta before any runtime reconcile; retry DB failures."""
    directory = pending_dir(manager)
    if directory.is_symlink():
        raise TunnelCtlError('Direktori jurnal kuota symlink ditolak')
    for path in sorted(directory.glob('*.json')):
        if path.is_symlink():
            raise TunnelCtlError('Jurnal kuota symlink ditolak')
        record = json.loads(path.read_text())
        receipt = 'usage-receipt:' + record['token']
        for attempt in range(3):
            try:
                with manager.db.transaction() as connection:
                    found = connection.execute('SELECT value FROM settings WHERE key=?', (receipt,)).fetchone()
                    if not found:
                        account = connection.execute('SELECT * FROM accounts WHERE id=?', (record['account_id'],)).fetchone()
                        if account is None or any(account[key] != record[key] for key in ('username', 'protocol', 'created_at')):
                            raise TunnelCtlError('Akun jurnal kuota tidak cocok; jangan restart sebelum pemulihan')
                        connection.execute('UPDATE accounts SET used_up=used_up+?, used_down=used_down+? WHERE id=?',
                                           (record['up'], record['down'], record['account_id']))
                        connection.execute('INSERT INTO usage_daily(account_id,day,up,down) VALUES(?,?,?,?) '
                                           'ON CONFLICT(account_id,day) DO UPDATE SET up=up+excluded.up,down=down+excluded.down',
                                           (record['account_id'], record['day'], record['up'], record['down']))
                        connection.execute('INSERT INTO settings(key,value) VALUES(?,?)', (receipt, 'applied'))
                break
            except (sqlite3.Error, OSError):
                if attempt == 2:
                    raise
        path.unlink()
        # Receipts intentionally survive deletion: interrupted unlink/replay must
        # never double-count. They travel in the DB snapshot for recovery.
