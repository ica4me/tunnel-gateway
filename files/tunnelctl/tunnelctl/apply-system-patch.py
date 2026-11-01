#!/usr/bin/env python3
"""Patch system.py: 'Bersihkan log' truncates Xray logs in place (Xray keeps its file handle)."""
from pathlib import Path

path = Path('files/tunnelctl/tunnelctl/system.py')
text = path.read_text()
old = """            if log.exists() and not log.is_symlink():
                atomic_write(log, b'')
"""
new = """            if log.exists() and not log.is_symlink():
                # Truncate in place: Xray keeps its file descriptor, so replacing the file would hide new logs.
                with open(str(log), 'r+b') as handle:
                    handle.truncate(0)
"""
if new in text:
    print('system.py: patch sudah pernah diterapkan')
elif text.count(old) == 1:
    path.write_text(text.replace(old, new))
    print('system.py: OK')
else:
    raise SystemExit('system.py: pola lama tidak ditemukan, tidak diubah')
