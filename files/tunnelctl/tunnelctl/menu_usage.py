import datetime

from . import menu_ui as ui

DEFAULT_LIMIT = 20


def _utc_day_window(day):
    """Rentang tanggal UTC dalam jam lokal server, mis. '07:00 - 06:59 (besok) WIB'."""
    try:
        start = datetime.datetime.fromisoformat(day).replace(tzinfo=datetime.timezone.utc).astimezone()
    except ValueError:
        return '-'
    end = start + datetime.timedelta(days=1) - datetime.timedelta(minutes=1)
    if start.utcoffset() == datetime.timedelta(0):
        return '00:00 - 23:59 {0}'.format(start.strftime('%Z'))
    return '{0} {1} - {2} {3} {4}'.format(start.strftime('%Y-%m-%d'), start.strftime('%H:%M'),
                                         end.strftime('%Y-%m-%d'), end.strftime('%H:%M'), start.strftime('%Z'))


def _last_collect():
    state = ui.unit_states(['tunnel-usage.timer'])['tunnel-usage.timer']
    label, color = ui.state_label(state)
    return ui.short_ts(state.get('LastTriggerUSec')), label, color


def render(data):
    day = data.get('day', '-')
    last, timer_label, timer_color = _last_collect()
    rows = [('#', 'PEMAKAIAN TRAFIK AKUN HARI INI'),
            ('Hari (UTC)', day),
            ('Waktu server', _utc_day_window(day)),
            ('Dicatat terakhir', '{0} (timer tunnel-usage {1})'.format(last, timer_label),
             None if timer_label == 'aktif' else timer_color),
            ('Akun dengan trafik', data.get('accounts', 0)),
            ('Total hari ini', '{0} (upload {1} / download {2})'.format(
                ui.size(int(data.get('total_up', 0)) + int(data.get('total_down', 0))),
                ui.size(data.get('total_up', 0)), ui.size(data.get('total_down', 0))))]
    ui.write_lines(ui.box(rows))
    ui.write('')
    items = data.get('rows') or []
    if not items:
        ui.write('Belum ada pemakaian trafik tercatat untuk hari ini.')
    else:
        table = []
        for index, row in enumerate(items, 1):
            status = row.get('status', '')
            table.append([str(index), row['username'] + ('*' if row.get('is_trial') else ''),
                          ui.PROTO_NAME.get(row['protocol'], row['protocol']),
                          ui.size(row['up']), ui.size(row['down']), (ui.size(row['total']), ui.CYAN),
                          (ui.STATUS_LABEL.get(status, status), ui.STATUS_COLOR.get(status))])
        ui.write_lines(ui.table(['No', 'Username', 'Protokol', 'Upload', 'Download', 'Total', 'Status'],
                                table, [3, 16, 11, 8, 8, 8, 11], right=(0, 3, 4, 5)))
        if any(row.get('is_trial') for row in items):
            ui.write(' * = akun trial')
        if data.get('accounts', 0) > len(items):
            ui.write(' Menampilkan {0} teratas dari {1} akun.'.format(len(items), data['accounts']))
    ui.write('')
    ui.note('SSH trafik per-user tidak tersedia. Reset pemakaian atau hapus akun akan menghapus data hariannya.')


def usage_menu(settings_override=None, backend=None, limit=DEFAULT_LIMIT):
    while True:
        ui.clear()
        ui.title('PEMAKAIAN TRAFIK AKUN HARI INI')
        code, data = ui.run_json(['account', 'usage-top', '--limit', str(limit)], settings_override, backend)
        if code != 0 or not isinstance(data, dict):
            ui.fail('data pemakaian tidak bisa dibaca (lihat pesan di atas).')
        else:
            render(data)
        ui.write('')
        ui.write(' 1. Reload')
        ui.write(' 0. Kembali')
        while True:
            choice = ui.ask('Pilih: ')
            if choice == '1':
                break
            if choice in ('0', 'q', 'Q'):
                return
            ui.write('Pilih 1 atau 0.')
