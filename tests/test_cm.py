import base64
import copy
import datetime as dt
import hashlib
from http.server import HTTPServer
import json
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cm
import monitor


def proxy(name='socks-41101', ip='2001:4860:1234::1', port=41101):
    return dict(name=name, addr=f'[{ip}]:{port}', handler={'type': 'socks5', 'auth': {'username': 'test-user', 'password': 'dummy-only'}},
                listener={'type': 'tcp'}, metadata={'interface': ip}, resolver='ipv6')


def settings():
    return dict(services={'socks-41101': {'ip': '2001:4860:1234::1', 'port': 41101}},
                interval=60, listen='127.0.0.1', port=0, metrics_url='http://127.0.0.1:19090/metrics')


def sample(a=100, b=200, start=100, client='127.0.0.1'):
    return f'''process_start_time_seconds {start}
gost_service_transfer_input_bytes_total{{service="socks-41101",client="{client}"}} {a}
gost_service_transfer_output_bytes_total{{service="socks-41101",client="{client}"}} {b}
'''


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'data.sqlite'
        self.db = monitor.connect(self.path)
        self.s = settings()
        self.now = dt.datetime(2026, 10, 31, 23, 59, tzinfo=monitor.TZ)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def save(self, text, now=None):
        process, counters = monitor.parse_metrics(text)
        monitor.save(self.db, self.s, process, counters, now or self.now)

    def total(self, month='2026-10', ip=None):
        return monitor.report(self.db, self.s, month, ip)['total_bytes']

    def test_baseline_delta_and_duplicate(self):
        self.save(sample())
        self.assertEqual(self.total(), 0)
        self.save(sample(150, 280))
        self.save(sample(150, 280))
        self.assertEqual(self.total(), 130)

    def test_restart_detected_even_when_new_value_is_larger(self):
        self.save(sample())
        self.save(sample(1000, 2000, start=101))
        self.assertEqual(self.total(), 3000)

    def test_counter_reset_without_process_restart(self):
        self.save(sample())
        self.save(sample(1, 2))
        self.assertEqual(self.total(), 3)

    def test_month_boundary(self):
        self.save(sample())
        self.save(sample(110, 220), self.now + dt.timedelta(minutes=2))
        self.assertEqual(self.total(), 0)
        self.assertEqual(self.total('2026-11'), 30)

    def test_ip_change_does_not_rewrite_history(self):
        self.save(sample())
        self.save(sample(110, 220))
        self.s['services']['socks-41101']['ip'] = '2001:4860:1234::2'
        self.save(sample(10, 20, start=101))
        self.assertEqual(self.total(ip='2001:4860:1234::1'), 30)
        self.assertEqual(self.total(ip='2001:4860:1234::2'), 30)

    def test_reopen_db_preserves_baseline(self):
        self.save(sample())
        self.save(sample(110, 220))
        self.db.close()
        self.db = monitor.connect(self.path)
        self.save(sample(120, 240))
        self.assertEqual(self.total(), 60)

    def test_temporarily_missing_series_not_double_counted(self):
        self.save(sample())
        self.save('process_start_time_seconds 100\n')
        self.save(sample(110, 220))
        self.assertEqual(self.total(), 30)

    def test_empty_first_sample_new_client_and_unknown_service(self):
        self.save('process_start_time_seconds 100\n')
        self.save(sample())
        text = sample() + sample(10, 20, client='127.0.0.2')
        text += 'gost_service_transfer_input_bytes_total{service="other"} 9999\n'
        self.save(text)
        self.assertEqual(self.total(), 330)

    def test_failed_fetch_preserves_history_and_marks_error(self):
        self.save(sample())
        with patch('monitor.fetch', side_effect=TimeoutError('test timeout')):
            self.assertFalse(monitor.collect(self.db, self.s))
        self.assertIn('TimeoutError', monitor.report(self.db, self.s, '2026-10')['last_error'])
        self.save(sample(110, 220))
        self.assertEqual(self.total(), 30)

    def test_legacy_import_is_once_and_unknown_ip(self):
        path = Path(self.temp.name) / 'old.sqlite'
        old = sqlite3.connect(path)
        old.executescript("CREATE TABLE monthly(month,service,input,output); INSERT INTO monthly VALUES ('2026-10','socks-1',5,6); INSERT INTO monthly VALUES ('2026-10','socks-2',0,0);")
        old.close()
        monitor.import_legacy(self.db, path)
        monitor.import_legacy(self.db, path)
        self.assertEqual(self.total(ip='unknown-legacy'), 11)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM monthly').fetchone()[0], 2)

    def test_legacy_incompatible_fails_without_modifying_source(self):
        path = Path(self.temp.name) / 'bad.sqlite'
        old = sqlite3.connect(path)
        old.execute('CREATE TABLE monthly(other TEXT)')
        old.close()
        before = path.read_bytes()
        with self.assertRaises(ValueError):
            monitor.import_legacy(self.db, path)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM monthly').fetchone()[0], 0)

    def test_invalid_metrics_fail(self):
        for text in ('garbage', sample(a='NaN'), sample(a=-1), sample() + sample()):
            with self.subTest(text=text), self.assertRaises(ValueError):
                monitor.parse_metrics(text)

    def test_cycle_16_boundary_and_recalculation(self):
        self.s['cycle_day'] = 16
        self.save(sample(0, 0), dt.datetime(2026, 10, 15, 12, tzinfo=monitor.TZ))
        self.save(sample(10, 20), dt.datetime(2026, 10, 15, 23, 59, tzinfo=monitor.TZ))
        self.save(sample(30, 60), dt.datetime(2026, 10, 16, 0, 0, tzinfo=monitor.TZ))
        self.assertEqual(self.total('2026-09'), 30)
        self.assertEqual(self.total('2026-10'), 60)
        self.s['cycle_day'] = 1
        self.assertEqual(self.total('2026-10'), 90)

    def test_current_cycle_and_short_month_clamping(self):
        s = dict(cycle_day=16)
        self.assertEqual(monitor.current_month(s, dt.datetime(2026, 10, 7, tzinfo=monitor.TZ)), '2026-09')
        self.assertEqual(monitor.current_month(s, dt.datetime(2026, 10, 16, tzinfo=monitor.TZ)), '2026-10')
        self.assertEqual(monitor.cycle_bounds('2026-01', 31), (dt.date(2026,1,31), dt.date(2026,2,28)))
        self.assertEqual(monitor.cycle_bounds('2024-02', 31), (dt.date(2024,2,29), dt.date(2024,3,31)))
        self.assertEqual(monitor.cycle_bounds('2026-12', 16), (dt.date(2026,12,16), dt.date(2027,1,16)))

    def test_custom_cycle_excludes_unsplittable_legacy(self):
        with self.db:
            self.db.execute('INSERT INTO monthly VALUES (?,?,?,?,?)', ('2026-10','unknown-legacy','old',10,20))
        self.s['cycle_day'] = 16
        data = monitor.report(self.db, self.s, '2026-10')
        self.assertEqual(data['total_bytes'], 0)
        self.assertTrue(data['legacy_warning'])
        self.s['cycle_day'] = 1
        self.assertEqual(self.total(), 30)


class ConfigurationTests(unittest.TestCase):
    def test_apply_failure_restores_all_configs_and_running_services(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config_path, settings_path, unit = root/'config.json', root/'monitor.json', root/'gost.service'
            originals = {config_path: json.dumps({'services':[proxy()]}), settings_path: json.dumps(settings()), unit:'old unit\n'}
            for path, text in originals.items():
                path.write_text(text)
            def fake_run(args, check=True, data=None):
                return str(config_path) if args[:3] == ['systemctl','show','gost'] else ''
            with patch.multiple(cm, CONFIG=config_path, SETTINGS=settings_path, UNIT=unit), \
                 patch('cm.Path', side_effect=lambda p: root/'backups' if p == '/etc/cm/backups' else Path(p)), \
                 patch('cm.run', side_effect=fake_run) as run, patch('cm.active', return_value=True), \
                 patch('cm.monitor.connect') as connect, patch('cm.monitor.collect'), \
                 patch('cm.wait_metrics', side_effect=RuntimeError('injected startup failure')):
                with self.assertRaisesRegex(RuntimeError, 'injected'):
                    cm.apply_config({'services':[proxy(ip='2001:4860:1234::2')]}, binary='/usr/local/bin/gost')
            for path, text in originals.items():
                self.assertEqual(path.read_text(), text)
            self.assertIn(unittest.mock.call(['systemctl','restart','cm-monitor'], check=False), run.call_args_list)

    def test_proxy_selector_and_ambiguous_ip(self):
        p = proxy()
        c = {'services': [p]}
        self.assertIs(cm.pick(c, '41101'), p)
        c['services'].append(proxy('second', port=41102))
        with self.assertRaises(ValueError):
            cm.pick(c, '2001:4860:1234::1')

    def test_other_services_not_managed(self):
        p = proxy()
        p['handler']['type'] = 'http'
        self.assertIsNone(cm.service_info(p))

    def test_metrics_configuration_never_silently_overwritten(self):
        c = {'metrics': {'addr': ':9999'}}
        with self.assertRaises(ValueError):
            cm.ensure_metrics(c)
        self.assertEqual(c['metrics']['addr'], ':9999')

    def test_generate_preserves_existing_and_reserved_ports(self):
        original = proxy(ip='2001:4860:1234::1')
        c = {'services': [original]}
        ips = [dict(ip='2001:4860:1234::1', family=6), dict(ip='2001:4860:1234::2', family=6)]
        args = cm.parser().parse_args(['generate'])
        def read(path):
            return copy.deepcopy(c) if path == cm.CONFIG else dict(port=19091)
        with patch('cm.read_json', side_effect=read), patch('cm.scan', return_value=ips), patch('cm.source4', return_value=None), \
             patch('cm.occupied_ports', return_value={41121}), patch('cm.apply_config') as apply, patch('cm.show'):
            cm.generate(args)
        result = apply.call_args.args[0]
        self.assertEqual(result['services'][0], original)
        self.assertEqual(result['services'][1]['addr'], '[2001:4860:1234::2]:41122')

    def test_generate_ipv4_entry_and_unique_random_credentials(self):
        ips = [dict(ip='2001:4860:1234::1', family=6), dict(ip='2001:4860:1234::2', family=6)]
        args = cm.parser().parse_args(['generate', '--entry', 'ipv4', '--v6', 'random'])
        with patch('cm.read_json', side_effect=lambda p: {'services': []} if p == cm.CONFIG else {'port': 19091}), \
             patch('cm.scan', return_value=ips), patch('cm.source4', return_value=None), patch('cm.occupied_ports', return_value=set()), \
             patch('cm.apply_config') as apply, patch('cm.show'):
            cm.generate(args)
        proxies = apply.call_args.args[0]['services']
        self.assertTrue(all(p['addr'].startswith('0.0.0.0:') for p in proxies))
        self.assertNotEqual(proxies[0]['handler']['auth'], proxies[1]['handler']['auth'])

    def test_scan_filters_unusable_ipv6(self):
        entries = [dict(local='2001:4860::1', scope='global', flags=[]),
                   dict(local='2001:4860::2', scope='global', flags=['temporary']),
                   dict(local='2001:4860::3', scope='global', dadfailed=True),
                   dict(local='fe80::1', scope='link'), dict(local='fd00::1', scope='global')]
        with patch('cm.run', return_value=json.dumps([dict(ifname='eth0', addr_info=entries)])):
            self.assertEqual([r['ip'] for r in cm.scan()], ['2001:4860::1'])

    def test_edit_preserves_unrelated_config_and_service_identity(self):
        original = proxy()
        original['metadata']['custom'] = 'keep'
        args = cm.parser().parse_args(['edit', '41101', '--port', '42000'])
        with patch('cm.read_json', side_effect=lambda p: {'services': [copy.deepcopy(original)]} if p == cm.CONFIG else {'port':19091}), \
             patch('cm.scan', return_value=[dict(ip='2001:4860:1234::1')]), patch('cm.occupied_ports', return_value=set()), \
             patch('cm.apply_config') as apply:
            cm.edit(args)
        result = apply.call_args.args[0]['services'][0]
        self.assertEqual(result['name'], original['name'])
        self.assertEqual(result['metadata']['custom'], 'keep')
        self.assertTrue(result['addr'].endswith(':42000'))


class QueryTests(unittest.TestCase):
    def test_auth(self):
        digest = hashlib.sha256(b'dummy-token').hexdigest()
        basic = base64.b64encode(b'cm:dummy-token').decode()
        self.assertTrue(monitor.authorized('Basic ' + basic, digest))
        self.assertTrue(monitor.authorized('Bearer dummy-token', digest))
        for header in ('', 'Basic ?invalid', 'Bearer wrong'):
            self.assertFalse(monitor.authorized(header, digest))

    def test_http_readonly_and_no_credentials(self):
        db = sqlite3.connect(':memory:', check_same_thread=False)
        template = monitor.connect(Path(tempfile.gettempdir()) / ('cm-schema-' + str(time_ns()) + '.sqlite'))
        template.backup(db)
        path = template.execute('PRAGMA database_list').fetchone()[2]
        template.close()
        Path(path).unlink()
        s = settings()
        server = monitor.make_server(s, db)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            with opener.open(base + '/api/traffic') as r:
                data = json.load(r)
            self.assertTrue(data['stale'])
            self.assertNotIn('dummy-only', json.dumps(data))
            with opener.open(base + '/') as r:
                self.assertIn('GOST 周期流量', r.read().decode())
            for path, code in [('/api/traffic?month=bad', 400), ('/config', 404)]:
                with self.assertRaises(urllib.error.HTTPError) as error:
                    opener.open(base + path)
                self.assertEqual(error.exception.code, code)
            with self.assertRaises(urllib.error.HTTPError) as error:
                opener.open(urllib.request.Request(base + '/', data=b'{}'))
            self.assertEqual(error.exception.code, 501)
        finally:
            server.shutdown()
            server.server_close()
            db.close()


def time_ns():
    import time
    return time.time_ns()


if __name__ == '__main__':
    unittest.main()
