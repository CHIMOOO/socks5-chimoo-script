"""Real GOST test: local SOCKS5 TCP/UDP, metrics, restart, persisted monitor API.

Run on Linux: python3 tests/integration_gost.py /path/to/gost
Does not require root, public network traffic, or systemd.
"""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import monitor


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def read_exact(sock, size):
    result = b''
    while len(result) < size:
        block = sock.recv(size - len(result))
        if not block:
            raise RuntimeError('SOCKS connection closed')
        result += block
    return result


def socks(proxy_port, target, command=1, target_host='127.0.0.1'):
    s = socket.create_connection(('127.0.0.1', proxy_port), timeout=5)
    s.sendall(b'\x05\x01\x02')
    assert read_exact(s, 2) == b'\x05\x02'
    s.sendall(b'\x01\x04test\x05dummy')
    assert read_exact(s, 2) == b'\x01\x00'
    address = b'\x04' + socket.inet_pton(socket.AF_INET6, target_host) if ':' in target_host else b'\x01' + socket.inet_aton(target_host)
    s.sendall(b'\x05' + bytes([command]) + b'\x00' + address + struct.pack('!H', target))
    reply = read_exact(s, 4)
    assert reply[1] == 0, reply
    if reply[3] == 1:
        host = socket.inet_ntop(socket.AF_INET, read_exact(s, 4))
    elif reply[3] == 4:
        host = socket.inet_ntop(socket.AF_INET6, read_exact(s, 16))
    else:
        host = read_exact(s, read_exact(s, 1)[0]).decode()
    target_port = struct.unpack('!H', read_exact(s, 2))[0]
    return s, (host, target_port)


def main():
    binary = str(Path(sys.argv[1]).resolve())
    proxy_port, metric_port, query_port, v6proxy_port = port(), port(), port(), port()
    class Echo(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'x' * 16384)
        def log_message(self, *args):
            pass
    web = HTTPServer(('127.0.0.1', 0), Echo)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    class IPv6Web(HTTPServer):
        address_family = socket.AF_INET6
    web6 = IPv6Web(('::1', 0), Echo)
    threading.Thread(target=web6.serve_forever, daemon=True).start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 0))
    udp.settimeout(5)
    def echo_udp():
        payload, address = udp.recvfrom(65535)
        udp.sendto(payload, address)
    processes = []
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with tempfile.TemporaryDirectory(prefix='cm-integration-') as folder:
            root = Path(folder)
            config = dict(services=[dict(name='test-socks', addr=f'127.0.0.1:{proxy_port}',
                          handler=dict(type='socks5', auth=dict(username='test', password='dummy'), metadata={'udp': True}),
                          listener=dict(type='tcp'))], metrics=dict(addr=f'127.0.0.1:{metric_port}', path='/metrics'))
            config['services'].append(dict(name='test-socks6', addr=f'127.0.0.1:{v6proxy_port}',
                handler=dict(type='socks5', auth=dict(username='test', password='dummy')),
                listener=dict(type='tcp'), metadata={'interface':'::1'}))
            config_file = root / 'gost.json'
            config_file.write_text(json.dumps(config))
            settings = dict(metrics_url=f'http://127.0.0.1:{metric_port}/metrics', interval=1,
                            listen='127.0.0.1', port=query_port, services={'test-socks': {'ip':'127.0.0.1', 'port':proxy_port}})
            settings['services']['test-socks6'] = {'ip':'::1','port':v6proxy_port}
            settings_file = root / 'monitor.json'
            settings_file.write_text(json.dumps(settings))
            log = open(root / 'gost.log', 'w')
            def start_gost():
                process = subprocess.Popen([binary, '-C', str(config_file)], stdout=log, stderr=log)
                processes.append(process)
                for _ in range(100):
                    try:
                        monitor.fetch(settings)
                        return process
                    except Exception:
                        if process.poll() is not None:
                            raise RuntimeError('GOST exited: ' + (root / 'gost.log').read_text()[-2000:])
                        time.sleep(.1)
                raise RuntimeError('metrics not ready')
            gost = start_gost()
            code = ('import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import common;'
                    'common.SETTINGS=Path(sys.argv[2]);common.DATABASE=Path(sys.argv[3]);import monitor;monitor.main()')
            agent = subprocess.Popen([sys.executable, '-c', code, str(ROOT), str(settings_file), str(root / 'traffic.sqlite')], stdout=log, stderr=log)
            processes.append(agent)
            def query():
                with opener.open(f'http://127.0.0.1:{query_port}/api/traffic', timeout=2) as r:
                    return json.load(r)
            for _ in range(50):
                try:
                    if query()['last_success']:
                        break
                except OSError:
                    pass
                time.sleep(.1)
            else:
                raise RuntimeError('monitor not ready: ' + (root / 'gost.log').read_text()[-2000:])
            def tcp_transfer(ipv6=False):
                s, _ = socks(v6proxy_port if ipv6 else proxy_port, web6.server_port if ipv6 else web.server_port,
                             target_host='::1' if ipv6 else '127.0.0.1')
                with s:
                    s.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
                    result = b''
                    while block := s.recv(65536):
                        result += block
                assert b'x' * 16384 in result
            tcp_transfer()
            tcp_transfer(ipv6=True)
            time.sleep(1.4)
            before = query()['total_bytes']
            assert before >= 16384, query()
            assert next(r for r in query()['ips'] if r['ip']=='::1')['total_bytes'] >= 16384
            threading.Thread(target=echo_udp, daemon=True).start()
            control, relay = socks(proxy_port, 0, command=3)
            with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(5)
                packet = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', udp.getsockname()[1]) + b'u' * 1024
                client.sendto(packet, ('127.0.0.1', relay[1]))
                response, _ = client.recvfrom(65535)
                assert response.endswith(b'u' * 1024)
            time.sleep(1.4)
            after_udp = query()['total_bytes']
            assert after_udp >= before + 2048, (before, after_udp)
            gost.terminate()
            gost.wait(timeout=5)
            time.sleep(1.1)
            gost = start_gost()
            tcp_transfer()
            time.sleep(1.4)
            after_restart = query()['total_bytes']
            assert after_restart >= after_udp + 16384
            assert query()['last_error'] == ''
            rss = next((line.strip() for line in Path(f'/proc/{agent.pid}/status').read_text().splitlines() if line.startswith('VmRSS:')), 'unknown')
            print(f'PASS: real SOCKS5 IPv4/IPv6 TCP and UDP, GOST restart, persistent collector and JSON API. Monitor {rss}')
            agent.terminate()
            agent.wait(timeout=5)
            gost.terminate()
            gost.wait(timeout=5)
            log.close()
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                            '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            secure_settings = dict(settings, listen='0.0.0.0', port=0, cert=str(cert), key=str(key),
                                   token_hash=hashlib.sha256(b'dummy-query-token').hexdigest())
            db = monitor.connect(root / 'traffic.sqlite')
            secure_server = monitor.make_server(secure_settings, db)
            threading.Thread(target=secure_server.serve_forever, daemon=True).start()
            try:
                context = ssl.create_default_context(cafile=str(cert))
                secure_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
                url = f'https://127.0.0.1:{secure_server.server_port}/api/traffic'
                try:
                    secure_opener.open(url)
                    raise AssertionError('unauthenticated request accepted')
                except urllib.error.HTTPError as exc:
                    assert exc.code == 401
                request = urllib.request.Request(url, headers={'Authorization':'Bearer dummy-query-token'})
                with secure_opener.open(request) as response:
                    assert json.load(response)['total_bytes'] == after_restart
                print('PASS: HTTPS certificate verification, anonymous rejection, authenticated query')
            finally:
                secure_server.shutdown()
                secure_server.server_close()
                db.close()
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        web.shutdown()
        web.server_close()
        web6.shutdown()
        web6.server_close()
        udp.close()


if __name__ == '__main__':
    main()
