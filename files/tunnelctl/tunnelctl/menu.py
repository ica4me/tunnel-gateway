"""Main interactive menu (Indonesian, no curses). Sub-menus live in menu_*.py."""
import datetime

from . import menu_account
from . import menu_backup
from . import menu_info
from . import menu_system
from . import menu_telegram
from . import menu_ui as ui

HEADER_SERVICES = [('haproxy', 'HAProxy'), ('xray', 'Xray'), ('ws-epro', 'Ws-Epro'),
                   ('dropbear-tunnel', 'Dropbear'), ('nginx', 'Nginx')]
SHORT_NAME = {'ssh': 'SSH', 'vmess': 'VMess', 'vless': 'VLESS', 'trojan': 'Trojan', 'ss': 'SS'}


def _header(settings_override=None, backend=None):
    conf = ui.settings(settings_override)
    line = '=' * 64
    ui.write(ui.paint(line, ui.CYAN))
    ui.write(ui.paint('TUNNEL GATEWAY'.center(64), ui.CYAN))
    ui.write(ui.paint(line, ui.CYAN))
    now = datetime.datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %Z')
    ui.write(' Domain : {0}'.format(conf.get('domain', '-')))
    ui.write(' IP     : {0:<22} Waktu : {1}'.format(ui.server_ip(), now))
    try:
        rows = ui.accounts(settings_override, backend)
        counts = dict((proto, sum(1 for r in rows if r['protocol'] == proto)) for proto in ui.PROTOCOLS)
        ui.write(' Akun   : ' + ' | '.join('{0} {1}'.format(SHORT_NAME[p], counts[p]) for p in ui.PROTOCOLS))
    except Exception:
        ui.write(' Akun   : ' + ui.paint('gagal membaca database', ui.RED))
    units = HEADER_SERVICES + [('badvpn-udpgw@{0}'.format(p), 'UDPGW') for p in conf.get('ports', {}).get('udpgw', [7300])]
    code, out, _ = ui.sh(['systemctl', 'is-active'] + [u for u, _ in units], timeout=5)
    states = out.split()
    marks = []
    for index, (_, label) in enumerate(units):
        active = index < len(states) and states[index] == 'active'
        marks.append(label + ' ' + ui.paint(ui.MARK_OK if active else ui.MARK_BAD, ui.GREEN if active else ui.RED))
    ui.write(' Service: ' + ' '.join(marks))
    ui.write(ui.paint(line, ui.CYAN))


MAIN_ITEMS = [('1', 'Menu SSH WebSocket'), ('2', 'Menu VMess'), ('3', 'Menu VLESS'), ('4', 'Menu Trojan'),
              ('5', 'Menu Shadowsocks'), ('6', 'Cek user online (semua)'), ('7', 'Menu Sistem'),
              ('8', 'Backup & Restore'), ('9', 'Info port & path'), ('10', 'Ringkasan server'),
              ('11', 'Telegram Gateway (bot)')]
PROTOCOL_KEYS = {'1': 'ssh', '2': 'vmess', '3': 'vless', '4': 'trojan', '5': 'ss'}


def _loop(settings_override=None, backend=None):
    while True:
        ui.clear()
        _header(settings_override, backend)
        for key, label in MAIN_ITEMS:
            ui.write('{0:>2}. {1}'.format(key, label))
        ui.write(' 0. Keluar')
        choice = ui.ask('Pilih menu: ')
        if choice in ('0', 'q', 'Q'):
            return 0
        if choice in PROTOCOL_KEYS:
            menu_account.account_menu(PROTOCOL_KEYS[choice], settings_override, backend)
            continue
        if choice == '7':
            menu_system.system_menu(settings_override, backend)
            continue
        if choice == '8':
            menu_backup.backup_menu(settings_override, backend)
            continue
        if choice == '11':
            menu_telegram.telegram_menu(settings_override, backend)
            continue
        ui.clear()
        if choice == '6':
            menu_account.online_all(settings_override, backend)
            ui.pause()
        elif choice == '9':
            menu_info.ports_info(settings_override, backend)
            ui.pause()
        elif choice == '10':
            menu_info.dashboard(settings_override, backend)
        else:
            ui.write('Menu tidak valid.')
            ui.pause()


def run_menu(settings_override=None, backend=None):
    try:
        return _loop(settings_override, backend)
    except KeyboardInterrupt:
        ui.write('\nKeluar dari menu.')
        return 0
