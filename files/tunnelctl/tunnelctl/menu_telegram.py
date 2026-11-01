"""Telegram gateway (menu 11): send account info to a Telegram chat. Stdlib only.

The bot token and chat ID live in their own root-only file (default /etc/tunnel/telegram.json),
not in settings.json, because Ansible rewrites settings.json on every site.yml run.
A failed send never blocks or undoes any account operation.
"""
import datetime
import getpass
import html
import json
import re
import socket
import urllib.error
import urllib.request
from pathlib import Path

from . import menu_ui as ui

API_URL = 'https://api.telegram.org/bot{0}/{1}'
TOKEN_RE = re.compile(r'^\d{5,}:[A-Za-z0-9_-]{30,}$')
CHAT_RE = re.compile(r'^(-?\d{3,20}|@[A-Za-z0-9_]{5,32})$')
DETAIL_MODES = ('ask', 'on', 'off')
DETAIL_LABEL = {'ask': 'TANYA', 'on': 'ON (otomatis)', 'off': 'OFF'}
MAX_MESSAGE = 3900
_urlopen = urllib.request.urlopen  # replaced in tests


# ---------------------------------------------------------------- config

def config_path(settings_override=None):
    return Path(ui.settings(settings_override).get('telegram_config_path', '/etc/tunnel/telegram.json'))


def load(settings_override=None):
    path = config_path(settings_override)
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data.setdefault('notify_create', True)
    if data.get('notify_detail') not in DETAIL_MODES:
        data['notify_detail'] = 'ask'
    return data


def save(data, settings_override=None):
    from .system import atomic_write
    atomic_write(config_path(settings_override), json.dumps(data, indent=2, sort_keys=True) + '\n')


def enabled(data):
    return bool(data.get('token') and data.get('chat_id'))


def mask_token(token):
    if not token:
        return '-'
    head, _, tail = token.partition(':')
    return '{0}:{1}...{2}'.format(head, tail[:3], tail[-3:]) if tail else '***'


def mask_chat(chat_id):
    text = str(chat_id or '')
    if not text:
        return '-'
    if text.startswith('@') or len(text) <= 5:
        return text
    return text[:3] + '*' * (len(text) - 6) + text[-3:]


# ---------------------------------------------------------------- Telegram API

def api(token, method, params=None, timeout=10):
    """Return (ok, result_or_reason). Never raises and never echoes the token."""
    request = urllib.request.Request(API_URL.format(token, method), data=json.dumps(params or {}).encode('utf-8'),
                                     headers={'Content-Type': 'application/json'})
    try:
        with _urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode('utf-8'))
        except Exception:
            return False, 'HTTP {0}'.format(exc.code)
    except urllib.error.URLError as exc:
        return False, 'tidak bisa menghubungi api.telegram.org ({0})'.format(getattr(exc, 'reason', 'jaringan'))
    except Exception as exc:
        return False, 'kesalahan jaringan ({0})'.format(type(exc).__name__)
    if isinstance(body, dict) and body.get('ok'):
        return True, body.get('result')
    return False, (body or {}).get('description', 'ditolak Telegram') if isinstance(body, dict) else 'respons tidak valid'


def _chunks(text):
    parts, current = [], ''
    for line in text.split('\n'):
        if current and len(current) + len(line) + 1 > MAX_MESSAGE:
            parts.append(current)
            current = ''
        current = current + '\n' + line if current else line
    if current:
        parts.append(current)
    return parts


def send(data, text):
    if not enabled(data):
        return False, 'Telegram belum diatur (menu 11)'
    for part in _chunks(text):
        ok, result = api(data['token'], 'sendMessage', {'chat_id': data['chat_id'], 'text': part,
                                                        'parse_mode': 'HTML', 'disable_web_page_preview': True})
        if not ok:
            return False, result
    return True, None


# ---------------------------------------------------------------- message formatting

def _e(value):
    return html.escape(str(value if value not in (None, '') else '-'))


def _footer():
    now = datetime.datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %Z')
    return '\n\U0001F5A5 {0} \u2022 {1}'.format(_e(socket.gethostname()), _e(now))


def account_message(detail, server_ip, event):
    protocol = detail['protocol']
    ssh = protocol == 'ssh'
    trial = bool(detail.get('is_trial'))
    head = '\u2705 <b>AKUN BARU' if event == 'create' else '\u2139\ufe0f <b>DETAIL AKUN'
    lines = ['{0} - {1}</b> ({2})'.format(head, _e(ui.PROTO_NAME[protocol].upper()), 'trial' if trial else 'reguler'), '']
    left = ui.remaining(detail.get('expires_at'))
    expiry = '{0} ({1})'.format(ui.local_time(detail.get('expires_at'), '%Y-%m-%d %H:%M %Z'),
                                'sudah habis' if left == 'habis' else left + ' lagi')
    status = ui.STATUS_LABEL.get(detail.get('status'), detail.get('status'))
    limit = int(detail.get('ip_limit') or 0)
    lines.append('<b>Username</b> : <code>{0}</code>'.format(_e(detail['username'])))
    lines.append('<b>{0}</b> : <code>{1}</code>'.format('UUID' if protocol in ('vmess', 'vless') else 'Password',
                                                       _e(detail.get('secret'))))
    if protocol == 'ss':
        lines.append('<b>Metode</b> : <code>{0}</code>'.format(_e(detail.get('ss_method'))))
    lines.append('<b>Expired</b> : {0}'.format(_e(expiry)))
    if ssh:
        lines.append('<b>Limit login</b> : {0}'.format('{0} sesi'.format(limit) if limit else 'tanpa batas'))
    else:
        quota = int(detail.get('quota_bytes') or 0)
        used = int(detail.get('used_up') or 0) + int(detail.get('used_down') or 0)
        lines.append('<b>Kuota</b> : {0}'.format(_e('{0} / {1}'.format(ui.size(used), ui.size(quota)) if quota
                                                      else '{0} / tanpa batas'.format(ui.size(used)))))
        lines.append('<b>Limit IP</b> : {0}'.format('{0} IP'.format(limit) if limit else 'tanpa batas'))
    lines.append('<b>Status</b> : {0}'.format(_e(status)))
    if detail.get('note'):
        lines.append('<b>Catatan</b> : {0}'.format(_e(detail['note'])))

    ports = detail.get('ports') or {}
    udpgw = ', '.join('127.0.0.1:{0}'.format(p) for p in (detail.get('udpgw') or ports.get('udpgw') or []))
    lines += ['', '<b>Domain</b> : <code>{0}</code>'.format(_e(detail.get('domain'))),
              '<b>IP server</b> : <code>{0}</code>'.format(_e(server_ip))]
    if ssh:
        lines.append('<b>Port</b> : SSH WS {0} | SSH WS TLS {1} | SSH-SSL {1}'.format(
            _e(ports.get('http', 80)), _e(ports.get('https', 443))))
        lines.append('<b>UDPGW</b> : <code>{0}</code>'.format(_e(udpgw or '-')))
        lines += ['', '<b>Contoh payload</b> ([host] = domain/IP):']
        for index, payload in enumerate(detail.get('payloads') or [], 1):
            lines.append('{0}. <code>{1}</code>'.format(index, _e(payload)))
    else:
        lines.append('<b>Port</b> : TLS {0} | non-TLS {1}'.format(_e(ports.get('https', 443)), _e(ports.get('http', 80))))
        lines.append('<b>Path WS</b> : <code>{0}</code>'.format(_e(detail.get('ws_path'))))
        if detail.get('grpc_name'):
            lines.append('<b>gRPC</b> : <code>{0}</code>'.format(_e(detail.get('grpc_name'))))
        lines.append('<b>UDPGW</b> : <code>{0}</code>'.format(_e(udpgw or '-')))
        labels = ('WS TLS 443', 'WS non-TLS 80', 'gRPC TLS 443')
        for index, link in enumerate(detail.get('links') or []):
            lines += ['', '<b>{0}</b>'.format(labels[index] if index < len(labels) else 'Link'),
                      '<code>{0}</code>'.format(_e(link))]
    warnings = detail.get('warnings') or []
    if warnings:
        lines.append('')
        lines += ['\u26a0\ufe0f {0}'.format(_e(item)) for item in warnings]
    lines.append(_footer())
    return '\n'.join(lines)


# ---------------------------------------------------------------- hook used by menu_account

def notify_account(detail, server_ip, event, settings_override=None):
    """Called after an account is created (event='create') or its detail is shown (event='detail')."""
    data = load(settings_override)
    if not enabled(data):
        return
    if event == 'create' and not data.get('notify_create', True):
        return
    if event == 'detail':
        mode = data.get('notify_detail', 'ask')
        if mode == 'off':
            return
        if mode == 'ask' and not ui.ask_yes('Kirim detail ini ke Telegram? [y/N]: '):
            return
    ok, reason = send(data, account_message(detail, server_ip, event))
    if ok:
        ui.write(ui.paint('Telegram: terkirim ke chat {0}.'.format(mask_chat(data['chat_id'])), ui.GREEN))
    else:
        ui.write(ui.paint('Telegram: gagal kirim ({0}). Akun tetap tersimpan normal.'.format(reason), ui.YELLOW))


# ---------------------------------------------------------------- menu 11

def _status_box(data, settings_override=None):
    if enabled(data):
        state = ('aktif', ui.GREEN)
    elif data.get('token') or data.get('chat_id'):
        state = ('belum lengkap', ui.YELLOW)
    else:
        state = ('belum diatur', ui.YELLOW)
    rows = [('#', 'TELEGRAM GATEWAY'),
            ('Status', state[0], state[1]),
            ('Bot', '@' + data['bot_username'] if data.get('bot_username') else '-'),
            ('Token', mask_token(data.get('token'))),
            ('Chat ID', mask_chat(data.get('chat_id'))),
            ('Kirim saat buat', 'ON' if data.get('notify_create', True) else 'OFF'),
            ('Kirim saat detail', DETAIL_LABEL[data.get('notify_detail', 'ask')]),
            ('File config', '{0} (mode 0600)'.format(config_path(settings_override)))]
    ui.write_lines(ui.box(rows))


def set_token(settings_override=None):
    data = load(settings_override)
    ui.title('ATUR TOKEN BOT')
    ui.write('Token saat ini : {0}{1}'.format(mask_token(data.get('token')),
                                              ' (@{0})'.format(data['bot_username']) if data.get('bot_username') else ''))
    ui.note('Buat bot lewat @BotFather di Telegram (/newbot), lalu salin token yang diberikan. '
            'Token tidak ditampilkan saat diketik/ditempel.')
    try:
        token = getpass.getpass('Token baru (kosong = batal): ').strip()
    except (EOFError, KeyboardInterrupt):
        token = ''
    if not token:
        ui.write('Dibatalkan.')
        return
    if not TOKEN_RE.match(token):
        ui.fail('format token tidak valid (contoh bentuk: 123456789:AAH...).')
        return
    ui.write('Memeriksa token ke Telegram...')
    ok, result = api(token, 'getMe')
    if not ok:
        ui.fail('token ditolak: {0}. Token lama tidak diubah.'.format(result))
        return
    changed_bot = data.get('token') and data.get('bot_username') != result.get('username')
    data.update(token=token, bot_username=result.get('username', ''))
    if changed_bot and data.get('chat_id'):
        ui.write(ui.paint('Bot berganti: kirim /start ke @{0} dari chat tujuan, lalu uji kirim (menu 3).'.format(
            data['bot_username']), ui.YELLOW))
    save(data, settings_override)
    ui.ok('token disimpan untuk bot @{0} ({1}).'.format(data['bot_username'], result.get('first_name', '')))


def _detect_chats(token):
    ok, result = api(token, 'getUpdates', {'timeout': 0, 'allowed_updates': ['message', 'my_chat_member', 'channel_post']})
    if not ok:
        return None, result
    chats = {}
    for update in result or []:
        for key in ('message', 'my_chat_member', 'channel_post', 'edited_message'):
            chat = (update.get(key) or {}).get('chat')
            if chat and chat.get('id') is not None:
                name = chat.get('title') or ' '.join(x for x in (chat.get('first_name'), chat.get('last_name')) if x)
                if chat.get('username'):
                    name = (name + ' ' if name else '') + '@' + chat['username']
                chats[str(chat['id'])] = (chat.get('type', '?'), name or '-')
    return chats, None


def set_chat(settings_override=None):
    data = load(settings_override)
    ui.title('ATUR CHAT ID')
    ui.write('Chat ID saat ini: {0}'.format(mask_chat(data.get('chat_id'))))
    if not data.get('token'):
        ui.fail('atur token bot dulu (menu 1).')
        return
    bot = '@' + data['bot_username'] if data.get('bot_username') else 'bot Anda'
    ui.write('')
    ui.write('Cara paling mudah:')
    ui.write('  1. Buka Telegram, cari {0}, tekan Start (atau kirim /start).'.format(bot))
    ui.write('  2. Untuk grup: tambahkan {0} ke grup, lalu kirim satu pesan di grup.'.format(bot))
    ui.write('  3. Kembali ke sini dan tekan Enter untuk mendeteksi chat.')
    ui.ask('\nTekan Enter jika sudah... ')
    chats, error = _detect_chats(data['token'])
    if chats is None:
        ui.write(ui.paint('Deteksi otomatis gagal: {0}'.format(error), ui.YELLOW))
        chats = {}
    rows = [[str(i), cid, kind, name] for i, (cid, (kind, name)) in enumerate(sorted(chats.items()), 1)]
    if rows:
        ui.write_lines(ui.table(['No', 'Chat ID', 'Jenis', 'Nama'], rows, [2, 16, 10, 40], right=(0,)))
        prompt = '\nPilih NOMOR, atau ketik chat ID manual (kosong = batal): '
    else:
        ui.write('Belum ada chat terdeteksi. Pastikan sudah menekan Start di bot, atau ketik chat ID manual.')
        prompt = '\nChat ID manual (angka, grup diawali -100; kosong = batal): '
    choice = ui.ask(prompt)
    if not choice:
        ui.write('Dibatalkan.')
        return
    if choice.isdigit() and 1 <= int(choice) <= len(rows) and len(choice) <= 3:
        chat_id = rows[int(choice) - 1][1]
    elif CHAT_RE.match(choice):
        chat_id = choice
    else:
        ui.fail('chat ID tidak valid.')
        return
    trial = dict(data, chat_id=chat_id)
    ui.write('Mengirim pesan konfirmasi ke chat tersebut...')
    ok, reason = send(trial, '\U0001F517 <b>Tunnel Gateway terhubung</b>\nChat ini akan menerima info akun dari server '
                             '<code>{0}</code>.{1}'.format(_e(socket.gethostname()), _footer()))
    if not ok:
        ui.fail('pesan konfirmasi gagal: {0}'.format(reason))
        if not ui.ask_yes('Tetap simpan chat ID ini? [y/N]: '):
            ui.write('Chat ID tidak diubah.')
            return
    save(trial, settings_override)
    ui.ok('chat ID {0} disimpan.'.format(mask_chat(chat_id)))


def test_send(settings_override=None):
    data = load(settings_override)
    ui.title('KIRIM PESAN UJI')
    if not enabled(data):
        ui.fail('atur token (menu 1) dan chat ID (menu 2) dulu.')
        return
    conf = ui.settings(settings_override)
    text = ('\U0001F9EA <b>Pesan uji Tunnel Gateway</b>\n'
            '<b>Domain</b> : <code>{0}</code>\n<b>IP</b> : <code>{1}</code>{2}').format(
        _e(conf.get('domain')), _e(ui.server_ip(allow_network=True)), _footer())
    ok, reason = send(data, text)
    (ui.ok if ok else ui.fail)('pesan uji terkirim.' if ok else 'pesan uji gagal: {0}'.format(reason))


def toggle_create(settings_override=None):
    data = load(settings_override)
    data['notify_create'] = not data.get('notify_create', True)
    save(data, settings_override)
    ui.ok('kirim saat buat akun sekarang {0}.'.format('ON' if data['notify_create'] else 'OFF'))


def choose_detail_mode(settings_override=None):
    data = load(settings_override)
    ui.title('KIRIM SAAT LIHAT DETAIL')
    ui.write('Saat ini: {0}'.format(DETAIL_LABEL[data['notify_detail']]))
    ui.write('  1. TANYA - setiap membuka detail akun, menu bertanya dulu (disarankan)')
    ui.write('  2. ON    - selalu kirim otomatis')
    ui.write('  3. OFF   - tidak pernah kirim')
    choice = ui.ask('Pilih (kosong = batal): ')
    mode = {'1': 'ask', '2': 'on', '3': 'off'}.get(choice)
    if not mode:
        ui.write('Dibatalkan.')
        return
    data['notify_detail'] = mode
    save(data, settings_override)
    ui.ok('kirim saat lihat detail sekarang {0}.'.format(DETAIL_LABEL[mode]))


def remove(settings_override=None):
    path = config_path(settings_override)
    ui.title('HAPUS PENGATURAN TELEGRAM')
    if not path.exists():
        ui.write('Belum ada pengaturan Telegram.')
        return
    if not ui.ask_yes('Hapus token dan chat ID (pengiriman berhenti)? [y/N]: '):
        ui.write('Dibatalkan.')
        return
    path.unlink()
    ui.ok('pengaturan Telegram dihapus.')


def telegram_menu(settings_override=None, backend=None):
    while True:
        ui.clear()
        data = load(settings_override)
        ui.title('TELEGRAM GATEWAY (BOT)')
        _status_box(data, settings_override)
        ui.write(' 1. Atur token bot')
        ui.write(' 2. Atur chat ID (deteksi otomatis)')
        ui.write(' 3. Kirim pesan uji')
        ui.write(' 4. Kirim saat buat akun   : {0}  (pilih untuk ubah)'.format('ON' if data.get('notify_create', True) else 'OFF'))
        ui.write(' 5. Kirim saat lihat detail: {0}'.format(DETAIL_LABEL[data['notify_detail']]))
        ui.write(' 6. Hapus token & chat ID')
        ui.write(' 0. Kembali')
        choice = ui.ask('Pilih: ')
        if choice in ('0', 'q', 'Q'):
            return
        ui.clear()
        actions = {'1': set_token, '2': set_chat, '3': test_send, '4': toggle_create,
                   '5': choose_detail_mode, '6': remove}
        if choice in actions:
            actions[choice](settings_override)
        else:
            ui.write('Pilihan tidak valid.')
        ui.pause()
