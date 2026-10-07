#!/usr/bin/env bash
set -euo pipefail
umask 077
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
cat > "$WORK/common.py" <<'CM_EMBED_COMMON_PY'
"""Shared paths and atomic file writes; no third-party packages."""
import json
import os
from pathlib import Path
import tempfile

CONFIG = Path('/etc/gost-auto/config.json')
SETTINGS = Path('/etc/cm/monitor.json')
TOKEN = Path('/etc/cm/query-token')
DATABASE = Path('/var/lib/cm/traffic.sqlite')
LEGACY_DATABASE = Path('/var/lib/gost-traffic/traffic.sqlite')
UNIT = Path('/etc/systemd/system/gost.service')


def read_json(path, default=None):
    if not path.exists() and default is not None:
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path, data):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + '\n')
CM_EMBED_COMMON_PY
cat > "$WORK/monitor.py" <<'CM_EMBED_MONITOR_PY'
"""GOST counters -> monthly SQLite totals -> read-only HTTP/HTTPS."""
import base64
import calendar
import datetime as dt
import hashlib
import hmac
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
import re
import sqlite3
import ssl
import threading
import time
from urllib.parse import parse_qs, urlsplit
import urllib.request

from common import DATABASE, SETTINGS, read_json

TZ = dt.timezone(dt.timedelta(hours=8))
METRIC = re.compile(r'^gost_service_transfer_(input|output)_bytes_total\{(.*)\}\s+(\S+)')
LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
MAX_RESPONSE = 8 * 1024 * 1024


def parse_metrics(text):
    process = None
    counters = {}
    for line in text.splitlines():
        if line.startswith('process_start_time_seconds '):
            process = line.split()[1]
        m = METRIC.match(line)
        if not m:
            continue
        labels = {k: json.loads('"' + v + '"') for k, v in LABEL.findall(m[2])}
        if 'service' not in labels:
            raise ValueError('流量指标缺少 service 标签')
        value = float(m[3])
        if not math.isfinite(value) or value < 0:
            raise ValueError('无效的流量计数')
        key = json.dumps([m[1], sorted(labels.items())], separators=(',', ':'))
        if key in counters:
            raise ValueError('重复的指标序列')
        counters[key] = (labels['service'], m[1], int(value))
    if process is None or not math.isfinite(float(process)):
        raise ValueError('缺少进程启动时间，无法可靠识别 GOST 重启')
    return process, counters


def fetch(settings):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(settings['metrics_url'], timeout=5) as r:
        data = r.read(MAX_RESPONSE + 1)
    if len(data) > MAX_RESPONSE:
        raise ValueError('指标响应过大')
    return parse_metrics(data.decode('utf-8'))


def connect(path=DATABASE):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10, check_same_thread=False)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS baseline(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS monthly(
            month TEXT NOT NULL, ip TEXT NOT NULL, service TEXT NOT NULL,
            input INTEGER NOT NULL DEFAULT 0, output INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(month, ip, service));
        CREATE TABLE IF NOT EXISTS daily(
            day TEXT NOT NULL, ip TEXT NOT NULL, service TEXT NOT NULL,
            input INTEGER NOT NULL DEFAULT 0, output INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(day, ip, service));
    ''')
    return db


def save(db, settings, process, counters, now=None):
    now = now or dt.datetime.now(TZ)
    stamp, day = now.isoformat(timespec='seconds'), now.strftime('%Y-%m-%d')
    # Serializes command-line snapshots with the daemon's regular collection.
    with db:
        db.execute('BEGIN IMMEDIATE')
        meta = dict(db.execute('SELECT key,value FROM meta'))
        old = dict(db.execute('SELECT key,value FROM baseline'))
        initial = 'started_at' not in meta
        reset = meta.get('process') != process
        for key, (service, direction, value) in counters.items():
            entry = settings['services'].get(service)
            if not entry:
                continue
            ip = entry['ip']
            delta = 0 if initial else (value if reset or key not in old or value < old[key] else value - old[key])
            db.execute('INSERT OR IGNORE INTO daily(day,ip,service) VALUES (?,?,?)', (day, ip, service))
            db.execute('UPDATE daily SET ' + direction + '=' + direction + '+? WHERE day=? AND ip=? AND service=?',
                       (delta, day, ip, service))
        if reset:
            db.execute('DELETE FROM baseline')
        db.executemany('INSERT OR REPLACE INTO baseline VALUES (?,?)', ((k, v[2]) for k, v in counters.items()))
        values = [('process', process), ('last_success', stamp), ('last_error', '')]
        if initial:
            values.append(('started_at', stamp))
        elif reset:
            values.append(('last_reset', stamp + ' GOST 已重启，旧进程未采集尾量可能丢失'))
        db.executemany('INSERT OR REPLACE INTO meta VALUES (?,?)', values)


def collect(db, settings):
    try:
        process, counters = fetch(settings)
        save(db, settings, process, counters)
        return True
    except Exception as exc:
        message = dt.datetime.now(TZ).isoformat(timespec='seconds') + ' ' + type(exc).__name__ + ': ' + str(exc)
        with db:
            db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('last_error', message))
        print(message, flush=True)
        return False


def import_legacy(db, path):
    """Old data has no IP identity: retain it explicitly as unknown, never guess."""
    if not path.exists() or db.execute("SELECT 1 FROM meta WHERE key='legacy_imported'").fetchone():
        return
    old = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
    try:
        columns = {r[1] for r in old.execute('PRAGMA table_info(monthly)')}
        if not {'month', 'service', 'input', 'output'} <= columns:
            raise ValueError('旧监控数据库格式不兼容，已保留原文件，停止自动导入')
        rows = old.execute('SELECT month,service,input,output FROM monthly').fetchall()
    finally:
        old.close()
    with db:
        for month, service, incoming, outgoing in rows:
            db.execute('INSERT INTO monthly VALUES (?,?,?,?,?) ON CONFLICT(month,ip,service) DO UPDATE SET input=input+excluded.input,output=output+excluded.output',
                       (month, 'unknown-legacy', service, incoming, outgoing))
        db.execute('INSERT INTO meta VALUES (?,?)', ('legacy_imported', str(path)))


def cycle_bounds(month, cycle_day):
    if not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])', month):
        raise ValueError('月份格式应为 YYYY-MM')
    if not 1 <= cycle_day <= 31:
        raise ValueError('周期起始日必须为 1..31')
    year, number = map(int, month.split('-'))
    start = dt.date(year, number, min(cycle_day, calendar.monthrange(year, number)[1]))
    year2, number2 = (year+1, 1) if number == 12 else (year, number+1)
    end = dt.date(year2, number2, min(cycle_day, calendar.monthrange(year2, number2)[1]))
    return start, end


def current_month(settings, now=None):
    today = (now or dt.datetime.now(TZ)).date()
    month = today.strftime('%Y-%m')
    start, _ = cycle_bounds(month, settings.get('cycle_day', 1))
    if today < start:
        month = (today.replace(day=1) - dt.timedelta(days=1)).strftime('%Y-%m')
    return month


def report(db, settings, month, ip=None):
    cycle_day = settings.get('cycle_day', 1)
    start, end = cycle_bounds(month, cycle_day)
    meta = dict(db.execute('SELECT key,value FROM meta'))
    combined = {}
    raw = db.execute('SELECT ip,service,SUM(input),SUM(output) FROM daily WHERE day>=? AND day<? GROUP BY ip,service',
                     (start.isoformat(), end.isoformat())).fetchall()
    legacy_warning = ''
    # Old monthly-only records cannot be split across arbitrary billing days.
    if cycle_day == 1:
        raw += db.execute('SELECT ip,service,input,output FROM monthly WHERE month=?', (month,)).fetchall()
    elif db.execute('SELECT 1 FROM monthly LIMIT 1').fetchone():
        legacy_warning = '旧整月记录无法拆分，未计入此周期；cm legacy 可单独查看。'
    for i, s, a, b in raw:
        values = combined.setdefault((i, s), [0, 0])
        values[0] += a
        values[1] += b
    rows = [dict(ip=i, service=s, input_bytes=a, output_bytes=b, total_bytes=a+b)
            for (i, s), (a, b) in sorted(combined.items())]
    seen = {(r['ip'], r['service']) for r in rows}
    if month == current_month(settings):
        for name, entry in settings['services'].items():
            if (entry['ip'], name) not in seen:
                rows.append(dict(ip=entry['ip'], service=name, input_bytes=0, output_bytes=0, total_bytes=0))
    if ip:
        rows = [r for r in rows if r['ip'] == ip]
    ips = {}
    for row in rows:
        total = ips.setdefault(row['ip'], dict(ip=row['ip'], input_bytes=0, output_bytes=0, total_bytes=0))
        for k in ('input_bytes', 'output_bytes', 'total_bytes'):
            total[k] += row[k]
    last = meta.get('last_success')
    stale = not last or (dt.datetime.now(TZ) - dt.datetime.fromisoformat(last)).total_seconds() > settings['interval'] * 2 + 10
    return dict(month=month, cycle_day=cycle_day, period_start=start.isoformat()+'T00:00:00+08:00',
                period_end=end.isoformat()+'T00:00:00+08:00', legacy_warning=legacy_warning,
                timezone='Asia/Shanghai', started_at=meta.get('started_at'), last_success=last,
                last_error=meta.get('last_error', ''), last_reset=meta.get('last_reset', ''), stale=stale,
                ips=list(ips.values()), services=rows, total_bytes=sum(r['total_bytes'] for r in rows))


def render(data):
    esc = html.escape
    rows = ''.join('<tr><td>' + esc(r['ip']) + '</td>' + ''.join('<td>%.4f</td>' % (r[k]/1024**3)
                   for k in ('input_bytes', 'output_bytes', 'total_bytes')) + '</tr>' for r in data['ips'])
    status = '采集延迟 / 已停止' if data['stale'] else '采集正常'
    return '''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CM · GOST 流量</title>
<style>body{font:16px system-ui,sans-serif;background:#f4f6f8;color:#152c3c;margin:0;padding:24px}
main{max-width:960px;margin:auto}table{border-collapse:collapse;width:100%;background:white}
td,th{text-align:left;padding:12px;border-bottom:1px solid #e0e6eb}td:first-child{overflow-wrap:anywhere}
.scroll{overflow:auto}input,button{font:inherit;padding:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere}
small{color:#526474}h1{font-size:26px}</style><main><h1>CM · GOST 周期流量</h1>
<p>每月 ''' + str(data['cycle_day']) + ' 日开始：' + esc(data['period_start'][:10]) + ' 00:00 至 ' + esc(data['period_end'][:10]) + ''' 00:00（不含结束时刻）</p>
<form><label>周期起始月份 <input type="month" name="month" value="''' + esc(data['month']) + '''"></label><button>查询</button></form>
<p>''' + status + ' · 总计 %.4f GiB</p>' % (data['total_bytes']/1024**3) + '''
<div class="scroll"><table><tr><th>配置的出口 IP</th><th>接收 GiB</th><th>发送 GiB</th><th>合计 GiB</th></tr>''' + rows + '''</table></div>
<p><small>北京时间周期；刷新页面查看。原始指标方向不一定等于客户端上传/下载。
unknown-legacy 是旧版按端口统计、无法追溯 IP 的历史。这里只统计 GOST，不代表商家计费流量。</small></p><pre>''' + esc(json.dumps(
        {k: data[k] for k in ('started_at', 'last_success', 'last_error', 'last_reset', 'legacy_warning')}, ensure_ascii=False, indent=2)) + '</pre></main></html>'


def authorized(header, token_hash):
    try:
        kind, value = header.split(' ', 1)
        if kind.lower() == 'basic':
            user, token = base64.b64decode(value, validate=True).decode().split(':', 1)
            if user != 'cm':
                return False
        elif kind.lower() == 'bearer':
            token = value
        else:
            return False
        return hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), token_hash)
    except (ValueError, UnicodeError):
        return False


def make_server(settings, db):
    db_lock = threading.RLock()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if settings['listen'] not in ('127.0.0.1', '::1') and not authorized(self.headers.get('Authorization', ''), settings['token_hash']):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="CM"')
                self.end_headers()
                return
            url = urlsplit(self.path)
            if url.path not in ('/', '/api/traffic'):
                self.send_error(404)
                return
            args = parse_qs(url.query)
            month = args.get('month', [current_month(settings)])[0]
            try:
                with db_lock:
                    data = report(db, settings, month, args.get('ip', [None])[0])
            except ValueError:
                self.send_error(400, 'Expected month in YYYY-MM format')
                return
            is_json = url.path == '/api/traffic'
            body = (json.dumps(data, ensure_ascii=False, indent=2) if is_json else render(data)).encode()
            self.send_response(200)
            self.send_header('Content-Type', ('application/json' if is_json else 'text/html') + '; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(body)

    context = None
    if settings['listen'] != '127.0.0.1':
        if not settings.get('token_hash'):
            raise ValueError('对外查询必须配置令牌')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(settings['cert'], settings['key'])

    class Server(HTTPServer):
        def get_request(self):
            conn, address = super().get_request()
            conn.settimeout(2)
            if context:
                try:
                    conn = context.wrap_socket(conn, server_side=True)
                except Exception:
                    conn.close()
                    raise
            return conn, address

        def handle_error(self, request, address):
            # Do not log clients' headers or request data.
            pass

    server = Server((settings['listen'], settings['port']), Handler)
    server.timeout = 1
    server.db_lock = db_lock
    return server


def main():
    settings = read_json(SETTINGS)
    db = connect()
    server = make_server(settings, db)
    # One bounded query thread: slow HTTP clients cannot delay collection.
    threading.Thread(target=server.serve_forever, daemon=True).start()
    while True:
        with server.db_lock:
            collect(db, settings)
        time.sleep(settings['interval'])


if __name__ == '__main__':
    main()
CM_EMBED_MONITOR_PY
cat > "$WORK/cm.py" <<'CM_EMBED_CM_PY'
#!/usr/bin/env python3
"""CM: small interactive manager for the user's single-process GOST setup."""
import argparse
import copy
import datetime as dt
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import quote
import urllib.request

from common import CONFIG, SETTINGS, TOKEN, UNIT, LEGACY_DATABASE, atomic_write, read_json, write_json
import monitor

VERSION = '0.1.0'
GOST_VERSION = '3.3.0'
DIGESTS = {
    'amd64': '676fb7f78d267b6ae73df719c0c7f2b565dde7147da935cfafbc1e1da558b6d5',
    'arm64': 'd03699e3f385d4ff5dad68046712adfcc7515325a064d2ab046e0bece30f8f8f',
}


def run(args, check=True, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=60)
    if check and result.returncode:
        # Configuration and curl errors can contain credentials. Never echo stderr.
        raise RuntimeError('命令失败：' + ' '.join(args[:2]) + '；请检查服务状态或网络')
    return result.stdout.strip()


def active(name):
    return run(['systemctl', 'is-active', name], check=False) == 'active'


def ensure_gost():
    binary = shutil.which('gost')
    if not binary:
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
        if arch is None:
            raise RuntimeError('自动安装只支持 amd64/arm64；请先手动安装 GOST 3')
        print('未找到 GOST，下载并校验 GOST ' + GOST_VERSION)
        url = f'https://github.com/go-gost/gost/releases/download/v{GOST_VERSION}/gost_{GOST_VERSION}_linux_{arch}.tar.gz'
        with tempfile.TemporaryDirectory(prefix='cm-gost-') as folder:
            archive = Path(folder, 'gost.tar.gz')
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(url, timeout=60) as response, archive.open('wb') as out:
                shutil.copyfileobj(response, out)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != DIGESTS[arch]:
                raise RuntimeError('GOST SHA256 校验失败，未安装')
            with tarfile.open(archive) as tar:
                member = tar.getmember('gost')
                if not member.isfile():
                    raise RuntimeError('发行包不是普通二进制文件')
                with tar.extractfile(member) as src, open('/usr/local/bin/gost.cm-new', 'wb') as out:
                    shutil.copyfileobj(src, out)
            os.chmod('/usr/local/bin/gost.cm-new', 0o755)
            os.replace('/usr/local/bin/gost.cm-new', '/usr/local/bin/gost')
        binary = '/usr/local/bin/gost'
    version = run([binary, '-V'])
    if not re.search(r'\bv?3\.', version):
        raise RuntimeError('已有 GOST 不是 3.x，保留原程序；请先处理版本兼容性')
    return binary, version


def service_info(service):
    try:
        if service['handler']['type'] != 'socks5' or service['listener']['type'] != 'tcp':
            return None
        ip = str(ipaddress.ip_address(service['metadata']['interface']))
        host, port = service['addr'].rsplit(':', 1)
        port = int(port)
        if not 1 <= port <= 65535:
            return None
        auth = service['handler']['auth']
        if not isinstance(auth['username'], str) or not isinstance(auth['password'], str):
            return None
        return dict(name=service['name'], ip=ip, host=host.strip('[]'), port=port, auth=auth)
    except (KeyError, TypeError, ValueError):
        return None


def mapping(config):
    found = {}
    names = set()
    for service in config.get('services', []):
        name = service['name']
        if name in names:
            raise ValueError('配置中服务名称重复：' + name)
        names.add(name)
        info = service_info(service)
        if info:
            found[name] = {'ip': info['ip'], 'port': info['port']}
    return found


def scan():
    devices = json.loads(run(['ip', '-j', 'addr', 'show']))
    addresses = []
    for device in devices:
        for entry in device.get('addr_info', []):
            ip = ipaddress.ip_address(entry['local'])
            flags = set(entry.get('flags', []))
            if any(entry.get(f) or f in flags for f in ('temporary', 'tentative', 'dadfailed', 'deprecated')):
                continue
            if entry.get('preferred_life_time') == 0 or entry.get('scope') != 'global':
                continue
            if ip.version == 6 and (not ip.is_global or ip not in ipaddress.ip_network('2000::/3')):
                continue
            addresses.append(dict(ip=str(ip), interface=device['ifname'], family=ip.version))
    return sorted(addresses, key=lambda x: (x['family'], int(ipaddress.ip_address(x['ip']))))


def source4(addresses):
    try:
        route = json.loads(run(['ip', '-j', '-4', 'route', 'get', '1.1.1.1']))[0]
        candidate = route.get('prefsrc') or route.get('src')
        if any(a['ip'] == candidate for a in addresses):
            return candidate
    except (RuntimeError, ValueError, IndexError):
        pass
    return next((a['ip'] for a in addresses if a['family'] == 4), None)


def public_ip():
    try:
        value = run(['curl', '--noproxy', '*', '-4', '-fsS', '--connect-timeout', '5', '--max-time', '10', 'https://api.ipify.org'])
        return str(ipaddress.IPv4Address(value))
    except (RuntimeError, ValueError):
        return ''


def occupied_ports():
    return {int(m[1]) for line in run(['ss', '-H', '-ltn']).splitlines()
            if len(line.split()) > 3 and (m := re.search(r':(\d+)$', line.split()[3]))}


def ensure_metrics(config):
    metrics = {'addr': '127.0.0.1:19090', 'path': '/metrics'}
    if 'metrics' in config and config['metrics'] != metrics:
        raise ValueError('已有不同的 metrics 配置，未覆盖；CM 需要 127.0.0.1:19090/metrics')
    config['metrics'] = metrics


def wait_metrics(settings):
    for _ in range(15):
        try:
            monitor.fetch(settings)
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError('GOST 指标接口未就绪，无法启用可靠采集')


def backup_file(path, folder):
    if path.exists():
        shutil.copy2(path, folder / path.name)


def restore(path, old):
    if old is None:
        path.unlink(missing_ok=True)
    else:
        atomic_write(path, old, 0o644 if path == UNIT else 0o600)


def apply_config(config, binary=None):
    binary = binary or ensure_gost()[0]
    ensure_metrics(config)
    new_mapping = mapping(config)
    settings = read_json(SETTINGS)
    old = {p: p.read_text() if p.exists() else None for p in (CONFIG, SETTINGS, UNIT)}
    gost_running, monitor_running = active('gost'), active('cm-monitor')
    existing_command = run(['systemctl', 'show', 'gost', '-p', 'ExecStart', '--value'], check=False)
    if existing_command and str(CONFIG) not in existing_command:
        raise RuntimeError('已有 gost.service 使用另一份配置。未接管，请先迁移到 /etc/gost-auto/config.json')
    folder = Path('/etc/cm/backups') / (dt.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3))
    folder.mkdir(parents=True, mode=0o700)
    for path in old:
        backup_file(path, folder)
    try:
        run(['systemctl', 'stop', 'cm-monitor'], check=False)
        if CONFIG.exists() and gost_running:
            db = monitor.connect()
            try:
                monitor.collect(db, settings)
            finally:
                db.close()
        settings['services'] = new_mapping
        write_json(CONFIG, config)
        write_json(SETTINGS, settings)
        # systemd quotes executable paths; no shell is used here.
        if any(c in binary for c in ('"', '\n', '\\', '%')):
            raise ValueError('GOST 路径包含不支持的字符')
        atomic_write(UNIT, f'''[Unit]
Description=CM GOST SOCKS5 proxies
After=network-online.target
Wants=network-online.target

[Service]
ExecStart="{binary}" -C {CONFIG}
Restart=always
RestartSec=5
LimitNOFILE=65535
UMask=0077

[Install]
WantedBy=multi-user.target
''', 0o644)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'restart', 'gost'])
        wait_metrics(settings)
        run(['systemctl', 'restart', 'cm-monitor'])
        time.sleep(1)
        if not active('cm-monitor'):
            raise RuntimeError('监控服务启动失败')
        run(['systemctl', 'enable', 'gost', 'cm-monitor'])
    except Exception:
        for path, content in old.items():
            restore(path, content)
        run(['systemctl', 'daemon-reload'], check=False)
        run(['systemctl', 'restart' if gost_running else 'stop', 'gost'], check=False)
        if monitor_running:
            run(['systemctl', 'restart', 'cm-monitor'], check=False)
        raise
    print('配置已应用；原文件备份：' + str(folder))


def bootstrap():
    binary, version = ensure_gost()
    print(version)
    if not SETTINGS.exists():
        settings = dict(metrics_url='http://127.0.0.1:19090/metrics', interval=60,
                        listen='127.0.0.1', port=19091, services={}, public_ip=public_ip(), cycle_day=1)
        write_json(SETTINGS, settings)
    legacy_enabled = run(['systemctl', 'is-enabled', 'gost-traffic'], check=False) == 'enabled'
    legacy_active = active('gost-traffic')
    if LEGACY_DATABASE.exists():
        run(['systemctl', 'stop', 'gost-traffic'], check=False)
        db = monitor.connect()
        try:
            monitor.import_legacy(db, LEGACY_DATABASE.resolve())
        except Exception:
            if legacy_active:
                run(['systemctl', 'start', 'gost-traffic'], check=False)
            raise
        finally:
            db.close()
    try:
        config = read_json(CONFIG, {'services': []})
        apply_config(config, binary)
    except Exception:
        if legacy_active:
            run(['systemctl', 'start', 'gost-traffic'], check=False)
        raise
    if legacy_enabled or legacy_active:
        run(['systemctl', 'disable', '--now', 'gost-traffic'], check=False)
    print('CM 已就绪。输入 cm 打开面板；首次使用选择“生成代理”。')


def pick(config, selector):
    matches = [s for s in config.get('services', []) if (i := service_info(s)) and
               selector in (i['name'], i['ip'], str(i['port']))]
    if len(matches) != 1:
        raise ValueError('请用唯一的服务名或端口选择；该条件匹配 %d 个服务' % len(matches))
    return matches[0]


def endpoint(info, settings):
    host = info['host']
    if host in ('0.0.0.0', '::', ''):
        host = settings.get('public_ip') or '<服务器公网IPv4>'
    if ':' in host:
        host = '[' + host + ']'
    return f'{host}:{info["port"]}'


def show(selector=None, reveal=False):
    config, settings = read_json(CONFIG), read_json(SETTINGS)
    services = [pick(config, selector)] if selector else config.get('services', [])
    for service in services:
        info = service_info(service)
        if not info:
            continue
        print(f'{info["name"]} | 入口 {endpoint(info, settings)} | 出口 {info["ip"]} | 用户 {info["auth"]["username"]}')
        if reveal:
            auth = info['auth']
            print('socks5://' + quote(auth['username'], safe='') + ':' + quote(auth['password'], safe='') + '@' + endpoint(info, settings))
        else:
            print('密码：******（cm show 选择器 --reveal 显示完整链接）')


def credentials(shared=False):
    if shared:
        user = input('用户名：').strip()
        password = getpass.getpass('密码（不回显）：')
        if not user or not password:
            raise ValueError('用户名和密码不能为空')
        return {'username': user, 'password': password}
    return {'username': 'u' + secrets.token_hex(4), 'password': secrets.token_urlsafe(18)}


def generate(args):
    config = read_json(CONFIG)
    addresses = scan()
    v4 = source4(addresses)
    targets = ([v4] if v4 else []) + [a['ip'] for a in addresses if a['family'] == 6]
    if not targets:
        raise ValueError('没有可用的本机地址')
    managed = [s for s in config.get('services', []) if service_info(s)]
    existing = {service_info(s)['ip']: s for s in managed}
    # Default adds missing IPv6 and preserves every existing proxy.
    keep = [s for s in config.get('services', []) if not service_info(s) or not args.reset]
    if args.reset and args.v4 == 'keep' and v4 in existing:
        keep.append(existing[v4])
    used = occupied_ports()
    if args.reset:
        used -= {service_info(s)['port'] for s in managed}
    used |= {service_info(s)['port'] for s in keep if service_info(s)}
    used |= {19090, read_json(SETTINGS)['port']}
    shared = credentials(True) if args.shared else None
    for ip in targets:
        if any(service_info(s) and service_info(s)['ip'] == ip for s in keep):
            continue
        is4 = ipaddress.ip_address(ip).version == 4
        random_port = args.v4 == 'random' if is4 else args.v6 == 'random'
        if random_port:
            candidates = [p for p in range(20000, 60001) if p not in used]
            if not candidates:
                raise ValueError('没有可用端口')
            port = secrets.choice(candidates)
        elif is4:
            port = 41101
            if port in used:
                raise ValueError('固定端口 41101 被占用，请选择随机端口或先修改配置')
        else:
            port = next((p for p in range(41121, 65536) if p not in used), None)
            if port is None:
                raise ValueError('没有可用端口')
        used.add(port)
        listen = '0.0.0.0' if is4 or args.entry == 'ipv4' else '[' + ip + ']'
        family = 'ipv4' if is4 else 'ipv6'
        # Stable identity survives port edits; regenerated proxies get a new ID.
        keep.append(dict(name='cm-' + secrets.token_hex(6), addr=f'{listen}:{port}',
                         handler={'type': 'socks5', 'auth': shared or credentials()}, listener={'type': 'tcp'},
                         metadata={'interface': ip}, resolver='cm-' + family))
    config['services'] = keep
    resolvers = config.setdefault('resolvers', [])
    for family in ('ipv4', 'ipv6'):
        if not any(r['name'] == 'cm-' + family for r in resolvers):
            resolvers.append(dict(name='cm-' + family, nameservers=[
                {'addr': '1.1.1.1:53', 'only': family}, {'addr': '8.8.8.8:53', 'only': family}]))
    apply_config(config)
    show(reveal=False)
    print('代理尚未验证外网连通性；执行 cm test。完整连接地址：cm links')


def edit(args):
    config = read_json(CONFIG)
    service = pick(config, args.selector)
    before = service_info(service)
    ip = str(ipaddress.ip_address(args.source)) if args.source else before['ip']
    if ip not in {a['ip'] for a in scan()}:
        raise ValueError('出口 IP 不在服务器现有可用地址中')
    if ipaddress.ip_address(ip).version != ipaddress.ip_address(before['ip']).version:
        raise ValueError('不能跨 IPv4/IPv6 修改，请重新生成相应代理')
    port = args.port or before['port']
    if not 1 <= port <= 65535:
        raise ValueError('端口必须为 1..65535')
    if port != before['port'] and (port in occupied_ports() or port in (19090, read_json(SETTINGS)['port'])):
        raise ValueError('端口已占用或为监控保留端口')
    host = before['host']
    if args.entry == 'ipv4':
        host = '0.0.0.0'
    elif args.entry == 'ipv6' or ':' in host:
        if ipaddress.ip_address(ip).version != 6:
            raise ValueError('IPv6 入口需要 IPv6 出口服务')
        host = ip
    service['addr'] = ('[' + host + ']' if ':' in host else host) + ':' + str(port)
    service['metadata']['interface'] = ip
    if args.username:
        service['handler']['auth']['username'] = args.username
    if args.password:
        password = getpass.getpass('新密码（不回显）：')
        if not password:
            raise ValueError('密码不能为空')
        service['handler']['auth']['password'] = password
    apply_config(config)


def test_proxies(selector=None):
    config = read_json(CONFIG)
    services = [pick(config, selector)] if selector else config.get('services', [])
    for service in services:
        i = service_info(service)
        if not i:
            continue
        host = '127.0.0.1' if i['host'] in ('0.0.0.0', '') else i['host']
        host = '[' + host + ']' if ':' in host else host
        # curl reads credentials from stdin, never process arguments.
        auth = i['auth']['username'] + ':' + i['auth']['password']
        if any(ch in auth for ch in ('\n', '\r', '\x00')):
            print(i['name'] + '：凭据含换行，跳过测试')
            continue
        escaped = auth.replace('\\', '\\\\').replace('"', '\\"')
        endpoint_url = 'https://api6.ipify.org' if ':' in i['ip'] else 'https://api.ipify.org'
        try:
            actual = run(['curl', '--config', '-', '--noproxy', '', '-fsS', '--connect-timeout', '5', '--max-time', '15',
                          '--proxy', f'socks5h://{host}:{i["port"]}', endpoint_url], data=f'proxy-user = "{escaped}"\n')
            actual = str(ipaddress.ip_address(actual))
            verdict = '出口匹配' if actual == i['ip'] else '连通，但公网出口与配置 IP 不同（可能经过 NAT）'
            print(f'{i["name"]} {i["ip"]} -> {actual}：{verdict}')
        except (RuntimeError, ValueError):
            print(i['name'] + '：验证失败，请检查地址、路由、防火墙和上游网络')


def traffic(month=None, ip=None):
    settings = read_json(SETTINGS)
    db = monitor.connect()
    try:
        data = monitor.report(db, settings, month or monitor.current_month(settings), ip)
    finally:
        db.close()
    print(f'每月 {data["cycle_day"]} 日开始（北京时间） | 合计 {data["total_bytes"]/1024**3:.4f} GiB')
    print(f'周期：{data["period_start"][:10]} 00:00 至 {data["period_end"][:10]} 00:00（不含结束时刻）')
    print('配置的出口 IP                          接收 GiB      发送 GiB      合计 GiB')
    for row in data['ips']:
        print(f'{row["ip"]:38} {row["input_bytes"]/1024**3:12.4f} {row["output_bytes"]/1024**3:12.4f} {row["total_bytes"]/1024**3:12.4f}')
    print('最后采集：', data['last_success'], '；状态：', '延迟/停止' if data['stale'] else '正常')
    if data['last_error']:
        print('采集错误：', data['last_error'])
    if data['last_reset']:
        print(data['last_reset'])
    if data['legacy_warning']:
        print(data['legacy_warning'])


def configure_cycle(day):
    settings = read_json(SETTINGS)
    if day is None:
        print('当前周期起始日：每月 %d 日' % settings.get('cycle_day', 1))
        return
    if not 1 <= day <= 31:
        raise ValueError('请输入 1..31；小月没有该日期时取当月最后一天')
    old = copy.deepcopy(settings)
    settings.update(cycle_day=day, cycle_configured=True)
    write_json(SETTINGS, settings)
    try:
        run(['systemctl', 'restart', 'cm-monitor'])
        time.sleep(1)
        if not active('cm-monitor'):
            raise RuntimeError('监控启动失败')
    except Exception:
        write_json(SETTINGS, old)
        run(['systemctl', 'restart', 'cm-monitor'], check=False)
        raise
    print('已设置每月 %d 日开始；已有每日数据按新周期重新汇总，不重启 GOST。' % day)


def legacy():
    db = monitor.connect()
    try:
        print('旧版整月记录（不能准确拆分到自定义周期）：')
        for month, ip, count in db.execute('SELECT month,ip,SUM(input+output) FROM monthly GROUP BY month,ip ORDER BY month,ip'):
            print(f'{month} {ip} {count/1024**3:.4f} GiB')
    finally:
        db.close()


def query_info(reveal=False):
    s = read_json(SETTINGS)
    if s['listen'] == '127.0.0.1':
        host = s.get('public_ip') or '服务器IP'
        print(f'在你电脑运行：ssh -N -L {s["port"]}:127.0.0.1:{s["port"]} root@{host}')
        print(f'网页：http://127.0.0.1:{s["port"]}/')
        print(f'JSON：http://127.0.0.1:{s["port"]}/api/traffic?month=2026-10&ip=出口IP')
    else:
        print(f'网页：https://{s["hostname"]}:{s["port"]}/')
        print(f'JSON：https://{s["hostname"]}:{s["port"]}/api/traffic?month=YYYY-MM&ip=出口IP')
        print('用户名：cm；密码：' + (TOKEN.read_text().strip() if reveal else '运行 cm query --reveal 查看'))
        print('API 支持 Authorization: Bearer <同一密码>；不会公开代理账号密码。')


def configure_web(args):
    old = read_json(SETTINGS)
    new = copy.deepcopy(old)
    if not 1024 <= args.port <= 65535 or args.port == 19090:
        raise ValueError('查询端口需为 1024..65535，且不能为 19090')
    if args.port != old['port'] and args.port in occupied_ports():
        raise ValueError('查询端口已被占用')
    new['port'] = args.port
    if args.public:
        if not args.cert or not args.key or not args.hostname:
            raise ValueError('对外查询需要 --hostname 域名 --cert 证书 --key 私钥')
        if not re.fullmatch(r'[A-Za-z0-9.-]+', args.hostname):
            raise ValueError('域名格式错误')
        cert, key = Path(args.cert).resolve(), Path(args.key).resolve()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        tls_dir = Path('/etc/cm/tls')
        tls_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Versioned files make settings rollback preserve the previous certificate.
        tag = secrets.token_hex(6)
        cert_out, key_out = tls_dir / (tag + '.crt'), tls_dir / (tag + '.key')
        atomic_write(cert_out, cert.read_text())
        atomic_write(key_out, key.read_text())
        token = TOKEN.read_text().strip() if TOKEN.exists() else secrets.token_urlsafe(24)
        atomic_write(TOKEN, token + '\n')
        new.update(listen='0.0.0.0', hostname=args.hostname, cert=str(cert_out), key=str(key_out),
                   token_hash=hashlib.sha256(token.encode()).hexdigest())
    else:
        new['listen'] = '127.0.0.1'
    write_json(SETTINGS, new)
    try:
        run(['systemctl', 'restart', 'cm-monitor'])
        time.sleep(1)
        if not active('cm-monitor'):
            raise RuntimeError('查询服务启动失败')
    except Exception:
        write_json(SETTINGS, old)
        run(['systemctl', 'restart', 'cm-monitor'], check=False)
        raise
    query_info(reveal=True)
    if args.public:
        print(f'请在云安全组/现有防火墙中放行 TCP {args.port}；脚本不自动修改防火墙。')


def status():
    print('CM ' + VERSION)
    print('GOST：' + run(['systemctl', 'is-active', 'gost'], check=False))
    print('监控：' + run(['systemctl', 'is-active', 'cm-monitor'], check=False))
    print(run(['systemctl', 'show', 'gost', 'cm-monitor', '-p', 'Id', '-p', 'MemoryCurrent', '-p', 'CPUUsageNSec'], check=False))


def parser():
    p = argparse.ArgumentParser(description='CM GOST 管理面板；不带参数打开交互菜单')
    subs = p.add_subparsers(dest='command')
    for name in ('init', 'status', 'scan', 'links', 'query', 'snapshot', 'legacy'):
        sub = subs.add_parser(name)
        if name == 'query':
            sub.add_argument('--reveal', action='store_true')
    sub = subs.add_parser('show')
    sub.add_argument('selector', nargs='?')
    sub.add_argument('--reveal', action='store_true')
    sub = subs.add_parser('generate')
    sub.add_argument('--v4', choices=['keep', 'fixed', 'random'], default='keep')
    sub.add_argument('--v6', choices=['sequential', 'random'], default='sequential')
    sub.add_argument('--entry', choices=['ipv4', 'ipv6'], default='ipv6')
    sub.add_argument('--shared', action='store_true', help='交互输入共用账号密码；默认每条随机')
    sub.add_argument('--reset', action='store_true', help='重新生成托管代理；默认只补充缺失 IP')
    sub = subs.add_parser('edit')
    sub.add_argument('selector')
    sub.add_argument('--port', type=int)
    sub.add_argument('--source')
    sub.add_argument('--entry', choices=['ipv4', 'ipv6'])
    sub.add_argument('--username')
    sub.add_argument('--password', action='store_true', help='交互输入，不通过命令参数传密码')
    sub = subs.add_parser('delete')
    sub.add_argument('selector')
    sub = subs.add_parser('test')
    sub.add_argument('selector', nargs='?')
    sub = subs.add_parser('traffic')
    sub.add_argument('month', nargs='?')
    sub.add_argument('--ip')
    sub = subs.add_parser('cycle')
    sub.add_argument('day', nargs='?', type=int, help='周期起始日 1..31；小月取月末')
    sub = subs.add_parser('web')
    sub.add_argument('--public', action='store_true')
    sub.add_argument('--port', type=int, default=19091)
    sub.add_argument('--hostname')
    sub.add_argument('--cert')
    sub.add_argument('--key')
    sub = subs.add_parser('public-ip')
    sub.add_argument('ip', nargs='?')
    sub = subs.add_parser('service')
    sub.add_argument('action', choices=['start', 'stop', 'restart'])
    return p


def dispatch(args):
    cmd = args.command
    if cmd == 'init':
        bootstrap()
    elif cmd == 'status':
        status()
    elif cmd == 'scan':
        for row in scan():
            print(row['interface'], row['ip'])
    elif cmd in ('show', 'links'):
        show(getattr(args, 'selector', None), cmd == 'links' or getattr(args, 'reveal', False))
    elif cmd == 'generate':
        generate(args)
    elif cmd == 'edit':
        edit(args)
    elif cmd == 'delete':
        config = read_json(CONFIG)
        config['services'].remove(pick(config, args.selector))
        apply_config(config)
    elif cmd == 'test':
        test_proxies(args.selector)
    elif cmd == 'traffic':
        traffic(args.month, args.ip)
    elif cmd == 'cycle':
        configure_cycle(args.day)
    elif cmd == 'legacy':
        legacy()
    elif cmd == 'query':
        query_info(args.reveal)
    elif cmd == 'web':
        configure_web(args)
    elif cmd == 'snapshot':
        db = monitor.connect()
        try:
            if not monitor.collect(db, read_json(SETTINGS)):
                raise RuntimeError('采集失败；历史数据保留')
        finally:
            db.close()
    elif cmd == 'public-ip':
        settings = read_json(SETTINGS)
        settings['public_ip'] = str(ipaddress.IPv4Address(args.ip or public_ip()))
        write_json(SETTINGS, settings)
        print('展示用公网 IPv4：' + settings['public_ip'])
    elif cmd == 'service':
        if args.action in ('stop', 'restart') and active('gost'):
            db = monitor.connect()
            try:
                monitor.collect(db, read_json(SETTINGS))
            finally:
                db.close()
        run(['systemctl', args.action, 'gost'])
    else:
        menu()


def menu():
    ensure_gost()
    if not SETTINGS.exists():
        bootstrap()
    if not read_json(SETTINGS).get('cycle_configured'):
        while True:
            try:
                configure_cycle(int(input('流量周期从每月几号开始？输入 1..31 [默认 1，例如 16]：').strip() or '1'))
                break
            except ValueError as exc:
                print(exc)
    while True:
        print('\n' + '=' * 58)
        print(' CM · GOST 管理面板  ' + VERSION)
        print(' GOST：%s   监控：%s' % (run(['systemctl', 'is-active', 'gost'], False), run(['systemctl', 'is-active', 'cm-monitor'], False)))
        print(' 流量周期起始日：每月 %d 日' % read_json(SETTINGS).get('cycle_day', 1))
        print(' 1. 查看代理配置     2. 显示完整代理地址\n 3. 扫描本机 IP      4. 生成 / 补充代理\n 5. 修改指定代理     6. 删除指定代理\n 7. 每 IP 周期流量   8. 查询页面 / API 地址\n 9. 配置查询端口    10. 测试代理出口\n11. 启停 GOST       12. 状态与资源占用\n13. 设置周期起始日  14. 旧版整月流量\n 0. 退出')
        try:
            choice = input('请选择：').strip()
            if choice == '0':
                return
            if choice == '1':
                show(input('端口/IP/服务名，留空查看全部：').strip() or None)
            elif choice == '2':
                show(reveal=True)
            elif choice == '3':
                dispatch(parser().parse_args(['scan']))
            elif choice == '4':
                print('只使用已有 IP。应用配置会短暂重启 GOST。')
                options = ['generate']
                if input('重新生成现有代理？输入 yes，否则仅补充缺失 IP：') == 'yes':
                    options += ['--reset']
                options += ['--v4', input('IPv4 keep/fixed/random [keep]：').strip() or 'keep']
                options += ['--v6', input('IPv6 sequential/random [sequential]：').strip() or 'sequential']
                options += ['--entry', input('IPv6 的入口 ipv6/ipv4 [ipv6]：').strip() or 'ipv6']
                if input('共用账号密码？yes；默认每条随机：') == 'yes':
                    options += ['--shared']
                dispatch(parser().parse_args(options))
            elif choice == '5':
                options = ['edit', input('服务名/端口/IP：').strip()]
                for flag, prompt in [('--port', '新端口'), ('--source', '本机出口 IP'), ('--entry', '入口 ipv4/ipv6'), ('--username', '用户名')]:
                    value = input(prompt + '（留空保留）：').strip()
                    if value:
                        options += [flag, value]
                if input('修改密码？yes：') == 'yes':
                    options += ['--password']
                dispatch(parser().parse_args(options))
            elif choice == '6':
                selector = input('服务名/端口/IP：').strip()
                if input('删除代理并保留历史流量？输入 yes：') == 'yes':
                    dispatch(parser().parse_args(['delete', selector]))
            elif choice == '7':
                traffic(input('周期起始月份 YYYY-MM（默认当前周期）：').strip() or None, input('出口 IP（默认全部）：').strip() or None)
            elif choice == '8':
                query_info(reveal=True)
            elif choice == '9':
                options = ['web', '--port', input('查询端口 [19091]：').strip() or '19091']
                if input('对外开放 HTTPS？yes；默认仅本机 + SSH 隧道：') == 'yes':
                    options += ['--public', '--hostname', input('证书对应域名：').strip(), '--cert', input('证书 PEM 路径：').strip(), '--key', input('私钥 PEM 路径：').strip()]
                dispatch(parser().parse_args(options))
            elif choice == '10':
                test_proxies(input('服务名/端口/IP（默认全部）：').strip() or None)
            elif choice == '11':
                dispatch(parser().parse_args(['service', input('start / stop / restart：').strip()]))
            elif choice == '12':
                status()
            elif choice == '13':
                configure_cycle(int(input('每月几号开始？1..31：').strip()))
            elif choice == '14':
                legacy()
        except (ValueError, RuntimeError, OSError) as exc:
            print('操作失败：' + str(exc))
        except SystemExit:
            print('参数错误，返回菜单')


def main():
    args = parser().parse_args()
    if os.geteuid() != 0:
        raise SystemExit('请使用 sudo cm 或 root 运行')
    # A lock serializes configuration changes from different SSH sessions.
    import fcntl
    lock = open('/run/cm.lock', 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('另一个 cm 面板/命令正在运行，请先退出它')
    try:
        dispatch(args)
    except (ValueError, RuntimeError, OSError) as exc:
        raise SystemExit('失败：' + str(exc))
    except (KeyboardInterrupt, EOFError):
        print('\n已退出')


if __name__ == '__main__':
    main()
CM_EMBED_CM_PY
cat > "$WORK/install.sh" <<'CM_EMBED_INSTALL_SH'
#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ ${EUID} -eq 0 ]] || { echo '请使用 sudo bash install.sh'; exit 1; }
command -v systemctl >/dev/null || { echo '需要使用 systemd 的 Debian/Ubuntu 服务器'; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'systemd 未运行，不能安装服务'; exit 1; }
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for f in cm.py common.py monitor.py; do
    [[ -f "$SOURCE/$f" ]] || { echo "缺少 $f，请上传整个目录或使用 dist/cm-install.sh"; exit 1; }
done

if ! command -v python3 >/dev/null || ! command -v curl >/dev/null || ! command -v ip >/dev/null || ! command -v ss >/dev/null; then
    command -v apt-get >/dev/null || { echo '请先安装 python3、curl、ca-certificates、iproute2'; exit 1; }
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 curl ca-certificates iproute2
fi
python3 -c 'import sys; assert sys.version_info >= (3,9), "需要 Python 3.9+"'
python3 -m py_compile "$SOURCE/cm.py" "$SOURCE/common.py" "$SOURCE/monitor.py"
if [[ -e /usr/local/bin/cm ]] && ! grep -q '/opt/cm/cm.py' /usr/local/bin/cm; then
    echo '/usr/local/bin/cm 已属于其他程序，未覆盖'
    exit 1
fi

# Keep the previous application files if an in-place installation fails.
WORK=$(mktemp -d)
PREVIOUS=0
MONITOR_WAS_ACTIVE=0
if [[ -d /opt/cm ]]; then
    cp -a /opt/cm "$WORK/cm"
    PREVIOUS=1
fi
if systemctl is-active --quiet cm-monitor; then MONITOR_WAS_ACTIVE=1; fi
if [[ -f /etc/systemd/system/cm-monitor.service ]]; then
    cp -p /etc/systemd/system/cm-monitor.service "$WORK/cm-monitor.service"
fi
cleanup() { rm -rf -- "$WORK"; }
rollback() {
    systemctl stop cm-monitor >/dev/null 2>&1 || true
    if [[ $PREVIOUS == 1 ]]; then
        cp -a "$WORK/cm/." /opt/cm/
    fi
    if [[ -f "$WORK/cm-monitor.service" ]]; then
        cp -p "$WORK/cm-monitor.service" /etc/systemd/system/cm-monitor.service
    fi
    systemctl daemon-reload || true
    if [[ $MONITOR_WAS_ACTIVE == 1 ]]; then systemctl start cm-monitor || true; fi
    echo '安装失败。GOST 配置修改阶段会自动恢复；请保留上方错误信息。' >&2
}
trap cleanup EXIT
trap rollback ERR
systemctl stop cm-monitor >/dev/null 2>&1 || true
install -d -m 755 /opt/cm
install -d -m 700 /etc/cm /var/lib/cm
install -m 644 "$SOURCE/cm.py" "$SOURCE/common.py" "$SOURCE/monitor.py" /opt/cm/
cat > /etc/systemd/system/cm-monitor.service <<'UNIT'
[Unit]
Description=CM GOST monthly traffic and read-only query
After=network.target gost.service

[Service]
ExecStart=/usr/bin/python3 /opt/cm/monitor.py
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/cm
CapabilityBoundingSet=
MemoryAccounting=yes
CPUAccounting=yes

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 /etc/systemd/system/cm-monitor.service
systemctl daemon-reload
python3 /opt/cm/cm.py init
cat > /usr/local/bin/cm <<'CLI'
#!/bin/sh
exec /usr/bin/python3 /opt/cm/cm.py "$@"
CLI
chmod 755 /usr/local/bin/cm
trap - ERR
echo '安装完成：cm 打开面板，cm --help 查看命令。'
if [[ ${1:-} != --no-menu ]] && [[ -r /dev/tty ]]; then
    /usr/local/bin/cm < /dev/tty
fi
CM_EMBED_INSTALL_SH
bash "$WORK/install.sh" "$@"
