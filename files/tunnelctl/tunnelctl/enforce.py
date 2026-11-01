"""Penegakan expiry/quota/limit berbasis DB + backend sistem."""
import datetime

from .usage import collect as collect_usage_delta
from .usage import drain as drain_usage_deltas


def _safe_error(exc):
    # Hindari membocorkan detail sensitif boundary/runtime
    return exc.__class__.__name__


def enforce(manager, mode, actor='timer'):
    with manager.db.lock():
        drain_usage_deltas(manager)
        if mode in ('quota', 'all'):
            errors = []
            for account in manager.rows():
                if account['protocol'] == 'ssh' or account['status'] in ('expired', 'locked'):
                    continue
                try:
                    collect_usage_delta(manager, account, manager.clock())
                except Exception as exc:
                    errors.append({'scope': 'quota', 'account': account['username'], 'error': _safe_error(exc)})
            try:
                drain_usage_deltas(manager)
            except Exception as exc:
                errors.append({'scope': 'quota', 'error': _safe_error(exc)})
            if errors:
                return {'expired': 0, 'quota_locked': 0, 'limit_locked': 0, 'unlocked': 0, 'deleted': 0, 'errors': errors}
        return _enforce(manager, mode, actor)


def _enforce(manager, mode, actor='timer'):
    if mode not in ('expiry', 'quota', 'limit', 'all'):
        raise ValueError('mode tidak valid')
    now = manager.clock()
    result = {
        'expired': 0,
        'quota_locked': 0,
        'limit_locked': 0,
        'unlocked': 0,
        'deleted': 0,
        'errors': [],
    }

    if mode in ('expiry', 'all'):
        grace = datetime.timedelta(days=manager.settings['expired_grace_days'])
        for account in manager.rows():
            expires = manager.util.parse_utc(account['expires_at'])
            if expires > now:
                continue
            if account['status'] != 'expired':
                manager.mutate(
                    'expiry_lock',
                    lambda c, a=account: manager._update_fields(c, a, {'status': 'expired', 'lock_reason': 'expired'}),
                    actor=actor,
                )
                result['expired'] += 1
            if account['is_trial'] or (now - expires) > grace:
                manager.delete(account['protocol'], account['username'])
                result['deleted'] += 1

    if mode in ('quota', 'all'):
        for account in manager.rows():
            if account['protocol'] == 'ssh':
                continue
            if account['status'] in ('expired', 'locked'):
                continue
            try:
                fresh = manager.get(account['protocol'], account['username'])
                if fresh['quota_bytes'] > 0 and (fresh['used_up'] + fresh['used_down']) >= fresh['quota_bytes']:
                    if fresh['status'] != 'quota_exceeded':
                        manager.mutate(
                            'quota_exceeded',
                            lambda c, a=fresh: manager._update_fields(c, a, {'status': 'quota_exceeded', 'lock_reason': 'quota'}),
                            actor=actor,
                        )
                        result['quota_locked'] += 1
            except Exception as exc:
                result['errors'].append({'scope': 'quota', 'account': account['username'], 'error': _safe_error(exc)})

    if mode in ('limit', 'all'):
        lock_minutes = int(manager.settings['defaults']['lock_minutes'])
        for account in manager.rows():
            if int(account['ip_limit']) <= 0:
                continue

            # Auto-unlock jika lock sementara lewat waktu
            if account.get('status') == 'limit_locked' and account.get('lock_until'):
                until = manager.util.parse_utc(account['lock_until'])
                if until <= now:
                    manager.unlock(account['protocol'], account['username'])
                    result['unlocked'] += 1
                continue

            if account['status'] in ('expired', 'quota_exceeded', 'locked', 'limit_locked'):
                continue

            try:
                if account['protocol'] == 'ssh':
                    count = int(manager.backend.ssh_sessions().get(account['username'], 0))
                else:
                    count = len(manager.backend.xray_online_ips(account))
                if count > int(account['ip_limit']):
                    lock_until = manager.util.iso_utc(now + datetime.timedelta(minutes=lock_minutes))
                    manager.mutate(
                        'limit_lock',
                        lambda c, a=account, until=lock_until: manager._update_fields(
                            c,
                            a,
                            {
                                'status': 'limit_locked',
                                'lock_reason': 'limit_exceeded',
                                'lock_until': until,
                                'violation_count': int(a['violation_count']) + 1,
                            },
                        ),
                        actor=actor,
                    )
                    result['limit_locked'] += 1
            except Exception as exc:
                result['errors'].append({'scope': 'limit', 'account': account['username'], 'error': _safe_error(exc)})

    return result
