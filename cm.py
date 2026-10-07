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
