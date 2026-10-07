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
