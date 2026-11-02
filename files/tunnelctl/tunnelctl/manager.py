"""Transactional account source of truth; operating system is injected."""
import datetime
import json
import os
import secrets
import sqlite3

from .config import load_settings
from .db import Database
from .errors import Conflict, InputError, NotFound, TunnelCtlError
from . import util as util_module
from .usage import drain as drain_usage_deltas


class Manager:
    def __init__(self, settings=None, backend=None, clock=None):
        overrides = dict(settings or {})
        self.settings = load_settings(path=overrides.get('settings_path'), overrides=overrides)
        if backend is None:
            from .system import SystemBackend
            backend = SystemBackend()
        self.backend = backend
        self.clock = clock or util_module.utcnow
        self.util = util_module
        if backend.require_root and os.geteuid() != 0:
            raise TunnelCtlError('Hanya root yang boleh menjalankan tunnelctl')
        self.db = Database(self.settings['db_path'], self.settings['lock_path'])

    def rows(self):
        return [dict(row) for row in self.db.connection.execute('SELECT * FROM accounts ORDER BY id')]

    def get(self, protocol, username):
        util_module.validate_protocol(protocol)
        util_module.validate_username(username)
        row = self.db.connection.execute('SELECT * FROM accounts WHERE protocol=? AND username=?', (protocol,username)).fetchone()
        if row is None:
            raise NotFound('Akun tidak ditemukan')
        return dict(row)

    def event(self, connection, action, account_id=None, actor='cli', detail=None):
        connection.execute('INSERT INTO events(ts,account_id,actor,action,detail) VALUES(?,?,?,?,?)',
                           (util_module.iso_utc(self.clock()), account_id, actor, action, json.dumps(detail or {}, sort_keys=True)))

    def mutate(self, action, operation, actor='cli'):
        with self.db.lock():
            drain_usage_deltas(self)
            return self._mutate(action, operation, actor)

    def _mutate(self, action, operation, actor='cli'):
        old = None
        applied = False
        try:
            with self.db.transaction() as connection:
                old = self.rows()
                result = operation(connection)
                self.event(connection, action, result.get('id') if isinstance(result,dict) else None, actor)
                self.backend.reconcile(old, self.rows(), self.settings)
                applied = True
            return result
        except BaseException:
            # Backend must compensate partial apply failures itself. Compensate commit failures here.
            if applied and old is not None:
                self.backend.reconcile(self.rows(), old, self.settings)
            raise

    def _constraints(self, protocol, quota, limit):
        quota = util_module.parse_size(quota)
        if quota is not None and quota > 9223372036854775807:
            raise InputError('Kuota terlalu besar')
        if protocol == 'ssh' and quota:
            raise InputError('Kuota SSH tidak didukung: forwarding Dropbear berjalan dengan UID root')
        if limit is not None and (not isinstance(limit,int) or limit < 0):
            raise InputError('Limit harus bilangan bulat nonnegatif')
        return quota

    def create(self, protocol, username, secret=None, days=None, hours=None, trial=False, quota=None, limit=None, note=None):
        util_module.validate_protocol(protocol)
        util_module.validate_username(username)
        if hours is not None and (not trial or days is not None):
            raise InputError('--hours memerlukan --trial dan tidak boleh bersama --days')
        duration = hours if hours is not None else (self.settings['defaults']['trial_hours'] if trial else (days if days is not None else self.settings['defaults']['days']))
        if not isinstance(duration,int) or duration <= 0:
            raise InputError('Masa aktif harus bilangan bulat positif')
        default_quota = 0 if protocol == 'ssh' else self.settings['defaults']['quota_bytes']
        quota = self._constraints(protocol, quota if quota is not None else default_quota, limit)
        secret = util_module.validate_secret(protocol, secret if secret is not None or protocol in ('vmess','vless') else secrets.token_urlsafe(24))
        now = self.clock()
        expiry = now + (datetime.timedelta(hours=duration) if trial or hours is not None else datetime.timedelta(days=duration))
        def operation(c):
            try:
                c.execute('INSERT INTO accounts(username,protocol,secret,is_trial,created_at,expires_at,quota_bytes,ip_limit,note,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
                          (username,protocol,secret,int(trial),util_module.iso_utc(now),util_module.iso_utc(expiry),quota,limit if limit is not None else self.settings['defaults']['ip_limit'],note,util_module.iso_utc(now)))
            except sqlite3.IntegrityError as exc:
                raise Conflict('Akun sudah ada') from exc
            return self.get(protocol,username)
        return self.mutate('create',operation)

    def _update_fields(self,c,account,fields):
        fields['updated_at'] = util_module.iso_utc(self.clock())
        c.execute('UPDATE accounts SET '+','.join(key+'=?' for key in fields)+' WHERE id=?',tuple(fields.values())+(account['id'],))
        return self.get(account['protocol'],account['username'])

    def delete(self,protocol,username):
        def operation(c):
            account = self.get(protocol,username)
            c.execute('DELETE FROM accounts WHERE id=?',(account['id'],))
            return {'id':account['id'],'deleted':True}
        return self.mutate('delete',operation)

    def update(self,protocol,username,secret=None,regen=False,quota=None,limit=None,note=None):
        parsed = self._constraints(protocol,quota,limit)
        fields = {}
        if secret is not None or regen:
            fields['secret'] = util_module.validate_secret(protocol,secret,regen)
        if quota is not None: fields['quota_bytes'] = parsed
        if limit is not None: fields['ip_limit'] = limit
        if note is not None: fields['note'] = note
        if not fields: raise InputError('Tidak ada perubahan')
        def operation(c):
            account = self.get(protocol,username)
            if account['status']=='quota_exceeded' and parsed is not None and (parsed == 0 or parsed > account['used_up']+account['used_down']):
                fields.update(status='active',lock_reason=None,lock_until=None)
                if util_module.parse_utc(account['expires_at'])<=self.clock(): fields['status']='expired'
            return self._update_fields(c,account,fields)
        return self.mutate('update',operation)

    def renew(self,protocol,username,days,reset_quota=False,quota=None):
        if not isinstance(days,int) or days<=0: raise InputError('Hari harus positif')
        parsed = self._constraints(protocol,quota,None)
        def operation(c):
            a=self.get(protocol,username)
            fields={'expires_at':util_module.iso_utc(max(util_module.parse_utc(a['expires_at']),self.clock())+datetime.timedelta(days=days))}
            if parsed is not None: fields['quota_bytes']=parsed
            if reset_quota:
                fields.update(used_up=0,used_down=0)
                c.execute('DELETE FROM usage_daily WHERE account_id=?',(a['id'],))
            if a['status']=='expired' or (a['status']=='quota_exceeded' and reset_quota): fields.update(status='active',lock_until=None,lock_reason=None)
            return self._update_fields(c,a,fields)
        return self.mutate('renew',operation)

    def lock(self,protocol,username,minutes=None,reason=None):
        if minutes is not None and minutes<=0: raise InputError('Menit harus positif')
        until=util_module.iso_utc(self.clock()+datetime.timedelta(minutes=minutes)) if minutes is not None else None
        return self.mutate('lock',lambda c:self._update_fields(c,self.get(protocol,username),{'status':'locked','lock_until':until,'lock_reason':reason or 'manual'}))

    def unlock(self,protocol,username):
        def operation(c):
            a=self.get(protocol,username)
            status='active'
            if util_module.parse_utc(a['expires_at'])<=self.clock(): status='expired'
            elif a['quota_bytes'] and a['used_up']+a['used_down']>=a['quota_bytes']: status='quota_exceeded'
            return self._update_fields(c,a,{'status':status,'lock_reason':None,'lock_until':None})
        return self.mutate('unlock',operation)

    def reset_usage(self,protocol,username):
        def operation(c):
            a=self.get(protocol,username)
            c.execute('DELETE FROM usage_daily WHERE account_id=?',(a['id'],))
            fields={'used_up':0,'used_down':0}
            if a['status']=='quota_exceeded': fields.update(status='active' if util_module.parse_utc(a['expires_at'])>self.clock() else 'expired',lock_reason=None)
            return self._update_fields(c,a,fields)
        return self.mutate('reset_usage',operation)

    def list(self,protocol=None,status=None,expiring_days=None):
        result=[]
        if protocol: util_module.validate_protocol(protocol)
        for a in self.rows():
            if protocol and a['protocol']!=protocol: continue
            if status and a['status']!=status: continue
            if expiring_days is not None and util_module.parse_utc(a['expires_at'])>self.clock()+datetime.timedelta(days=expiring_days): continue
            a.pop('secret',None)
            result.append(a)
        return result

    def show(self,protocol,username):
        from .links import account_detail
        return account_detail(self.get(protocol,username),self.settings)

    def online(self,protocol=None):
        accounts=self.rows()
        if protocol: accounts=[a for a in accounts if a['protocol']==protocol]
        return self.backend.online(accounts,self.settings)

    def online_activity(self, protocol=None, interval=None):
        """Terhubung vs aktif trafik, khusus tampilan menu (bukan untuk enforcement)."""
        fn = getattr(self.backend, 'online_activity', None)
        if not callable(fn):
            raise InputError('Backend tidak mendukung pengamatan aktivitas')
        if protocol:
            util_module.validate_protocol(protocol)
        accounts = [a for a in self.rows() if not protocol or a['protocol'] == protocol]
        if interval is None:
            interval = self.settings.get('online_sample_seconds', 3)
        return fn(accounts, self.settings, interval=interval)

    # ------------------------------------------------------------ laporan (read-only)

    def usage_top(self, day=None, limit=20, protocol=None):
        """Ranking pemakaian trafik satu hari dari usage_daily (diisi collector tunnel-usage).

        Read-only: tidak memanggil collector, reset, atau enforcement. Hari = tanggal UTC, sama dengan
        tanggal yang dipakai collector saat mencatat."""
        if day is None:
            day = self.clock().date().isoformat()
        try:
            datetime.date.fromisoformat(str(day))
        except ValueError as exc:
            raise InputError('Format tanggal harus YYYY-MM-DD') from exc
        if not isinstance(limit, int) or limit < 1 or limit > 1000:
            raise InputError('Limit harus 1-1000')
        if protocol:
            util_module.validate_protocol(protocol)
        where = 'd.day = ? AND d.up + d.down > 0'
        params = [str(day)]
        if protocol:
            where += ' AND a.protocol = ?'
            params.append(protocol)
        connection = self.db.connection
        rows = connection.execute(
            'SELECT a.id, a.username, a.protocol, a.status, a.is_trial, d.up, d.down, d.up + d.down AS total '
            'FROM usage_daily AS d JOIN accounts AS a ON a.id = d.account_id '
            'WHERE ' + where + ' ORDER BY total DESC, a.id LIMIT ?', params + [limit]).fetchall()
        summary = connection.execute(
            'SELECT COUNT(*), COALESCE(SUM(d.up), 0), COALESCE(SUM(d.down), 0) '
            'FROM usage_daily AS d JOIN accounts AS a ON a.id = d.account_id WHERE ' + where, params).fetchone()
        return {'day': str(day), 'timezone': 'UTC', 'limit': limit, 'protocol': protocol,
                'accounts': int(summary[0]), 'total_up': int(summary[1]), 'total_down': int(summary[2]),
                'rows': [{'username': r['username'], 'protocol': r['protocol'], 'status': r['status'],
                          'is_trial': bool(r['is_trial']), 'up': int(r['up']), 'down': int(r['down']),
                          'total': int(r['total'])} for r in rows]}
