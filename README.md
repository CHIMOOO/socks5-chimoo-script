# CM · GOST 轻量管理面板

在服务器输入 **`cm`**，通过中文菜单管理 GOST SOCKS5 代理和每个出口 IP 的周期流量。

- 已有 GOST 3 就沿用；未安装时下载官方 **v3.3.0**，验证固定 SHA256 后安装。
- 兼容原脚本的 `/etc/gost-auto/config.json` 和 `gost.service`，保留已有账号、端口和出口配置。
- **只使用服务器已有、可用的 IPv4 / IPv6**。不生成 IPv6 网卡地址，不假定服务器拥有整段 IPv6。
- 默认补充缺少 IP 的代理；可选择重新生成、固定/随机端口、独立随机凭据或交互输入共用凭据。
- IPv6 代理可以使用各自 IPv6 作为入口，也可以统一使用服务器 IPv4 作为入口。
- 查看和修改指定代理，测试实际出口，查看代理链接。
- 单个 Python 监控进程，每 60 秒采集 GOST 指标，SQLite 按北京时间保存每日累计，按自定义月周期查询。
- 终端按 IP 查询；浏览器页面与只读 JSON API；默认本机访问，可配置独立端口的 HTTPS 查询。

## 安装

支持 Debian / Ubuntu、systemd、Python 3.9+，自动安装 GOST 支持 amd64 / arm64。不使用 Docker、pip、Prometheus 或 Grafana。

### 单文件安装（推荐）

在服务器终端一条命令下载并安装：

```bash
curl -fsSLo cm-install.sh https://raw.githubusercontent.com/CHIMOOO/socks5-chimoo-script/main/dist/cm-install.sh && sudo bash cm-install.sh
```

也可以手动上传：

将项目的 **`dist/cm-install.sh`** 上传至服务器 `/root/`，执行：

```bash
sudo bash /root/cm-install.sh
```

安装完成自动进入面板。以后只需：

```bash
cm
```

如果希望直接粘贴执行，可打开 `dist/cm-install.sh`，把全部内容包在以下块中粘贴到 root 终端（标记必须各自独占一行）：

```bash
bash <<'CM_SETUP'
# 在这里粘贴 dist/cm-install.sh 的完整内容
CM_SETUP
```

源码仓库：<https://github.com/CHIMOOO/socks5-chimoo-script>。

### 从项目目录安装

上传整个目录，在服务器项目目录运行：

```bash
sudo bash install.sh
```

无人值守安装，只初始化服务、不进入菜单：

```bash
sudo bash install.sh --no-menu
```

安装缺少的系统工具可能执行 `apt-get`。首次安装、再次安装及配置变更会重启 GOST，现有连接短暂中断。普通打开菜单和查询不会重启。

如果原 `gost.service` 使用别的配置路径，CM 会拒绝覆盖。先自行迁移到 `/etc/gost-auto/config.json`，不要并行启动两套占用相同端口的 GOST。

## 首次使用

1. 输入 `cm`，首次会询问**流量周期从每月几号开始**，例如输入 `16`；选择 **3** 检查扫描到的 IP。
2. 选择 **4** 生成代理。默认保留已有代理，只补充新 IP。
3. 默认 IPv4 新代理端口 41101，IPv6 从 41121 顺序分配，自动跳过已占用端口。也可选择随机端口。
4. 默认每条新代理使用独立随机账号密码；如需要统一账号密码，选择共用并交互输入。
5. 选择 **10** 测试出口。生成配置不等于公网可达，仍须具备相应 IPv6 路由并开放代理端口。
6. 选择 **2** 显示完整 SOCKS5 链接。普通查看隐藏密码。

不会添加 IPv6 地址、修改系统路由、修改防火墙或关闭 Docker。IPv4 入站、IPv6 出站需要目标具有 AAAA 记录；仅支持 IPv4 的目标不保证可通过 IPv6 出口访问。

新建代理沿用原脚本的 TCP 配置，不自动开启 SOCKS5 UDP 转发；已有代理的额外 handler 设置保持原样。监控也能采集已启用 UDP 的服务指标。

## 菜单

```text
 CM · GOST 管理面板
 1. 查看代理配置     2. 显示完整代理地址
 3. 扫描本机 IP      4. 生成 / 补充代理
 5. 修改指定代理     6. 删除指定代理
 7. 每 IP 周期流量   8. 查询页面 / API 地址
 9. 配置查询端口    10. 测试代理出口
11. 启停 GOST       12. 状态与资源占用
13. 设置周期起始日  14. 旧版整月流量
 0. 退出
```

## 直接使用命令

下面的 IP、端口是示例，请替换为实际配置。选择器支持 **服务名、端口或出口 IP**；匹配多个代理时，请改用唯一服务名。

```bash
cm --help
cm status
cm scan
cm show
cm show 41101
cm show 41101 --reveal
cm links

# 补充尚未配置的 IPv6，IPv6 地址直接入站
cm generate

# 补充缺失 IP，IPv4 入站、各自 IPv6 出站，IPv6 随机端口
cm generate --entry ipv4 --v6 random

# 重新生成已有托管代理；IPv4 保留，其余代理重置
cm generate --reset --v4 keep --v6 random --entry ipv4

# 全部重置为随机端口；默认凭据也会重新随机生成
cm generate --reset --v4 random --v6 random

# 使用交互输入的共用账号密码
cm generate --shared

cm edit 41101 --port 42001
cm edit 42001 --username myuser --password
cm edit 41121 --entry ipv4
cm edit 41121 --source 2001:db8::123
cm delete 42001
cm test
cm test 41121

cm service stop
cm service start
cm service restart
```

`--source` 只接受扫描到的现有同族 IP。`--password` 通过终端隐藏输入，不接受明文密码参数。测试代理时，凭据通过 curl 标准输入传递，不放进命令参数。完整代理链接仅在显式请求时显示，不输出到日志。

`--v4 fixed` 为新 IPv4 代理分配 41101；`--v4 keep` 在有旧配置时保留，没有时使用 41101。**没有 `--reset` 时，任何已有代理都不重置**，即使传了随机端口选项。顺序端口/固定端口不意味着固定默认密码。

如果公网 IP 检测失败或服务器经过 NAT，可设置用于展示链接的公网 IPv4：

```bash
cm public-ip 203.0.113.10
cm public-ip                 # 自动重新探测
```

此操作仅影响展示地址，不修改绑定或路由。

## 流量采集与查询

安装后 **`cm-monitor.service` 开机自动运行，每 60 秒采集**。无需手动触发。

```bash
cm cycle 16                        # 每月 16 日为周期起点
cm cycle                           # 查看当前设置
cm traffic                         # 当前周期每个出口 IP 的流量
cm traffic 2026-10                  # 从 2026-10-16 到 2026-11-16 的周期
cm traffic 2026-10 --ip 2001:db8::1 # 指定周期和 IP
cm snapshot                        # 立即采集一次，不重启 GOST
cm status                          # 服务状态、内存字节数和累计 CPU 时间
```

`cm` 菜单持有配置锁，同一时间只开一个面板/命令；另一个 SSH 窗口执行命令前先退出当前面板。后台监控和网页查询不受这个锁影响。

### 自定义周期日期

菜单 **13** 输入 `16`，或执行 `cm cycle 16`，表示 **每月 16 日 00:00 至下月 16 日 00:00（不含结束时刻）**，按北京时间计算。比如 10 月 7 日查询“当前周期”，会显示 9 月 16 日至 10 月 16 日。

支持 1～31。设置为 31 时，没有 31 日的月份取最后一天，例如 1 月 31 日至 2 月 28 日、2 月 28 日至 3 月 31 日。默认 1 为自然月。

`month=2026-10` 和 `cm traffic 2026-10` 表示**周期起始月份**。网页及 JSON 返回 `cycle_day`、`period_start`、`period_end`，避免把自定义周期误认为自然月。

改变日期不清空数据，也不重启 GOST；已经采集的**每日累计**按新日期重新汇总。无人值守安装默认 1，首次打开面板再询问日期。旧版只有整月数据不能重算，见下面迁移说明。

### 统计口径与边界

- 指标来自 GOST 的 `gost_service_transfer_input_bytes_total` / `output_bytes_total`，不抓包、不解析访问日志。
- 按**服务配置的出口 IP**汇总，同 IP 多个代理会合并。它不是网卡某地址的所有流量，也不证明每次连接实际使用该出口；使用 `cm test` 单独验证连通性。
- 页面显示 GOST 原始“接收/发送”计数。TCP 与 SOCKS5 UDP 指标的方向口径可能不同，不能直接当成一致的客户端上传/下载。协议握手等也可能计入。
- 统计从启用后开始，初次采样建立基线，无法恢复此前未记录的流量。
- SQLite 同一事务写入计数基线和每日累计；重启采集程序不重复计数。识别 GOST 进程重启及计数下降。
- GOST 突然退出或两次采样之间多次重启时，未采集流量可能丢失。正常通过 CM 修改/停用时先尽力采样，仍不能承诺精确计费。
- 采样差值记入采集时的北京时间日期。跨午夜/周期边界的一次采样可能归到下一天（正常约 60 秒）；长期停止采集后恢复也按恢复采样日期归入，不伪造中间各天的数据。
- 改 IP 前采样旧配置，再重启并切换映射；旧 IP 的历史不会改归新 IP。改端口保持服务身份，流量连续。
- **修改配置请通过 CM。**直接编辑 JSON 不会同步监控映射；这种情况下先恢复一致配置或重新运行安装器，不能依靠猜测关联历史。
- 代理被删除后历史保留。接口会标明采集错误和延迟；空数据不代表统计前没有使用流量。

### 从之前的轻量脚本迁移

安装器检测到 `/var/lib/gost-traffic/traffic.sqlite` 时，会停止原 `gost-traffic` 采集，导入其 `monthly(month,service,input,output)` 数据，成功后禁用旧服务。原数据库不删除。

旧数据只有服务/端口，没有可验证的历史 IP，因此导入为 **`unknown-legacy`**；可查询但不擅自归到当前 IP。导入只执行一次，零流量行也保留。格式不兼容时停止安装，不删除原数据。

周期起始日为 1 时，旧整月数据可按自然月合并展示；其他起始日无法准确拆分，**不计入自定义周期总量**，页面会提示。通过 `cm legacy` 或菜单 **14** 随时单独查询旧整月记录。

## 查询网页与只读 API

### 默认：本机端口 + SSH 隧道

```bash
cm query
```

按输出提示，在自己的电脑执行（替换服务器地址）：

```bash
ssh -N -L 19091:127.0.0.1:19091 root@服务器IP
```

保持 SSH 连接，浏览器打开 `http://127.0.0.1:19091/`。默认无需开放公网查询端口，也无需额外部署 Nginx。

服务器本机查询 JSON：

```bash
curl --noproxy '*' 'http://127.0.0.1:19091/api/traffic'
curl --noproxy '*' 'http://127.0.0.1:19091/api/traffic?month=2026-10&ip=2001:db8::1'
```

### 对外开放独立 HTTPS 查询端口

准备一个指向服务器的域名，以及对应的 PEM 证书链和私钥。菜单 **9** 或命令：

```bash
cm web --public --port 19443 --hostname traffic.example.com \
  --cert /path/to/fullchain.pem --key /path/to/privkey.pem
```

在云安全组和现有防火墙中自行放行 TCP 19443。查看地址和独立查询密码：

```bash
cm query --reveal
```

浏览器访问 `https://traffic.example.com:19443/`，用户名 **`cm`**，密码使用上面显示的查询密码。API 也支持 HTTP Basic 或 `Authorization: Bearer <查询密码>`。查询密码不放在 URL 中。

接口只提供流量数据，没有修改代理、读取代理凭据或执行命令的接口。公网模式强制 TLS 和独立认证；本机模式可由服务器本地用户访问。HTTPS 证书会复制到 `/etc/cm/tls/`，续签后需要再次执行相同 `cm web` 命令载入新证书。

关闭公网查询，恢复本机模式：

```bash
cm web --port 19091
```

## 文件、备份与服务

| 路径/服务 | 用途 |
|---|---|
| `/usr/local/bin/cm` | 面板入口 |
| `/opt/cm/` | Python 源码 |
| `/etc/gost-auto/config.json` | GOST 配置，权限 600 |
| `/etc/cm/monitor.json` | 指标地址、IP 映射、查询设置 |
| `/etc/cm/query-token` | 对外查询密码，权限 600 |
| `/etc/cm/tls/` | 查询服务证书副本 |
| `/etc/cm/backups/` | 应用配置前的配置/服务备份 |
| `/var/lib/cm/traffic.sqlite` | 持久化每日累计、旧整月记录及采样基线 |
| `gost.service` | 单进程、多代理 GOST |
| `cm-monitor.service` | 一个 Python 进程：采集 + 只读查询 |

监控使用一个有界查询线程，慢查询连接不会阻塞采集；没有为每个 IP 启动一个进程。监控进程受 systemd 文件系统写保护约束，仅 `/var/lib/cm` 可写。额外内存与指标数量有关，请用 `cm status` 实测，不承诺固定占用。

配置应用失败会恢复上一份 GOST 配置、监控设置和 GOST unit，并尽力恢复运行状态。备份只覆盖配置文件，不包含每次完整流量数据库副本。手动备份 SQLite 建议使用 Python `sqlite3.Connection.backup`，或先停止监控后复制数据库。

```bash
systemctl status gost cm-monitor --no-pager
journalctl -u cm-monitor -n 30 --no-pager
```

GOST 运行日志可能含业务访问细节，分享前自行检查。CM 不自动输出这些日志。

只停止监控，不影响代理：

```bash
systemctl disable --now cm-monitor
```

恢复：

```bash
systemctl enable --now cm-monitor
```

## 开发与验证

只依赖 Python 标准库。修改源码后重新生成单文件安装器：

```bash
python3 -m unittest discover -s tests -v
python3 build.py
bash -n install.sh
bash -n dist/cm-install.sh
```

集成测试使用显式指定的真实 GOST 二进制和 `openssl`，需要本机 IPv6 回环可用；只启动临时本机服务，不修改 systemd 或服务器配置：

```bash
python3 tests/integration_gost.py /path/to/gost
```

项目不包含真实代理密码；测试使用虚拟凭据。正式机的 systemd 安装、IPv6 公网路由和证书部署需要在目标服务器验证。

当前已验证：25 项自动测试；真实 GOST 3.3.0 的 IPv4/IPv6 TCP、SOCKS5 UDP、重启累计和 HTTPS 查询鉴权；1280px/375px 浏览器布局及周期切换。WSL Linux 小流量测试中监控进程 RSS 约 26 MiB，仅作参考，不含 GOST 本身，也不代表长期大流量或大量客户端的占用。
