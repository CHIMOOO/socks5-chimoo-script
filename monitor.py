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
