# ddosguard

基于 NetFlow 的 DDoS 攻击检测与交换机联动处置。

接收路由/交换机发送的 **NetFlow v5 / v9 / IPFIX** 流数据，按 **目标 IP + 端口** 聚合最近
N 秒（默认 5 秒）的连接数（flow 数）/ 包数 / 字节数；当目标 IP 命中配置的「交换机 + 目标网段」
且指标超过阈值时，通过 **SSH** 在对应交换机上执行命令模板（自动填入 `{ip}` / `{port}`），
用于下发 ACL 丢弃/限速攻击流量。带冷却时间，避免同一攻击目标重复下发命令。

## 架构

```
路由器/交换机 ──NetFlow(v5/v9/IPFIX)──> ddosguard
                                          │
              UDP 接收 → 解析 → 目标网段过滤 → 滑动窗口聚合(目标IP+端口)
                                          │
                                    每 1s 检测阈值
                                          │  命中
                                          ▼
                         SSH 到「交换机」执行命令模板 {ip} {port}
```

| 模块 | 说明 |
|------|------|
| `internal/netflow` | v5/v9/IPFIX 解析（模板缓存、选项模板跳过、IPFIX 变长字段） |
| `internal/detect` | 按秒分桶的滑动窗口聚合、阈值判定、冷却抑制、异步处置 |
| `internal/switchctl` | SSH 交互式 shell 执行命令模板（密码/私钥认证、PTY、超时） |
| `internal/config` | YAML 配置加载与校验（网段解析、阈值覆盖） |
| `cmd/ddosguard` | 入口：UDP 接收、工作池、检测循环、metrics/health |

## 部署模式

**推荐：旁路消费（与 netstream-collector 联动）**

```
路由器 ──NetFlow──> netstream-collector ──> Elasticsearch
                         │ forward_to: "127.0.0.1:2056"（原始报文转发）
                         ▼
                   ddosguard（listen: 127.0.0.1:2056）
                         │
                         └──SSH──> 交换机（ACL 封堵）
```

- netstream-collector 增加 `forward_to` 配置后，把收到的原始 NetFlow 报文额外转发一份
- ddosguard 只监听 `127.0.0.1`，不暴露网络面；采集与防护进程隔离（故障域、权限、升级独立）
- 若 ddosguard 直接接交换机流量，将 `collector.listen` 改为 `0.0.0.0:2055` 即可

## 配置

```yaml
http:
  listen: ":8080"          # metrics/health 监听（空=不启用）

collector:
  listen: "0.0.0.0:2055"   # NetFlow 监听
  buffer_size: 65535
  workers: 4

detection:
  window: "5s"             # 聚合窗口（最近 5 秒）
  check_interval: "1s"     # 检测周期
  cooldown: "300s"         # 同一 交换机+IP+端口 命中后的抑制时间
  min_flows: 1000          # 窗口内连接数（flow 数）阈值
  min_bytes: 20971520      # 窗口内流量（字节）阈值，20MB/5s ≈ 32Mbps
  min_packets: 0           # 窗口内包数阈值（0=不启用）
  # 三个条件为且关系：同时达到才触发

switches:
  - name: "sw-core-1"          # 交换机名（日志/规则标识）
    host: "10.0.0.1"           # 交换机管理 IP
    port: 22
    username: "netops"
    password: "change-me"
    # private_key: "/etc/ddosguard/id_rsa"   # 私钥认证（优先于密码）
    timeout: "15s"
    targets:                   # 受保护的目标 IP 段（CIDR 或单个 IP）
      - "203.0.113.0/24"
      - "198.51.100.10"
    min_flows: 500             # 可选：覆盖全局阈值
    # min_bytes: 10485760
    rule_id_start: 800         # ACL rule 起始编号（默认 800，批次内连续分配）
    ssh_enabled: true          # 是否执行 SSH（false=仅检测记录，不登录交换机）
    login_commands: []         # 登录后先执行的命令（如 enable）
    commands:                  # 命令模板，支持 {ip} / {port} / {proto} / {rule_id}
      - "sys"
      - "acl name DDOS advance"
      - "rule {rule_id} deny {proto} destination-port eq {port} destination {ip} 0.0.0.0"
      - "commit"
      - "quit"
      - "quit"
      - "display acl name DDOS | include {rule_id}"
      - "quit"
```

要点：

- **阈值语义（且关系）**：`min_flows`（连接数）/ `min_bytes`（流量）/ `min_packets`（包数）
  三个条件需**同时满足**才触发；0 表示不启用该条件（只对 >0 的条件做 AND 判断）。
  所有阈值为 `window`（默认 5s）窗口内的累计值。
- **多交换机 + 多网段**：`switches` 可配置多个，每个交换机关联自己的目标网段与阈值；
  目标 IP 命中哪个交换机的网段，就在哪台交换机上下发命令。
- **rule 编号（每批从 800 开始）**：每次检测批次内的多条规则**无条件从
  `rule_id_start`（默认 800）开始连续编号**（800、801、802...），一次批次可同时
  下发多条 rule；**下一批次重新从 800 开始**，覆盖上一次下发的规则。
- **批次去重（不重复 SSH）**：记录上一批已下发的目标（IP+端口）；新批次目标若
  **全部属于**上一批（子集或相同）则**跳过 SSH**；出现新目标时执行整批
  （从 800 开始覆盖）。批次判断与执行全程串行，避免执行期间重复触发。
- **per-交换机 SSH 开关**：`ssh_enabled: false` 时该交换机只做检测与日志记录
  （日志中包含将渲染下发的完整命令，便于演练/审批），不登录交换机；默认 `true`。
- **去重**：同一「交换机 + 目标 IP + 端口」在 `dedup_ttl`（默认 24h）内不会重复下发，
  避免持续攻击反复刷 SSH 命令；`cooldown`（默认 300s）为最小重发间隔，两者取较大值。
- **命令模板**：逐行下发（交互式 shell，兼容 `sys`/`system-view` 等模式切换）；
  `{ip}` 替换为命中的目标 IP，`{port}` 为端口，`{proto}` 为窗口内主导协议
  （tcp/udp/icmp...，如模板中写死协议则忽略），`{rule_id}` 为固定 rule 编号。
  请按实际设备型号调整命令。

## 运行

```bash
make build            # 产物 build/ddosguard
./build/ddosguard -config config.yaml
# metrics/health 端口在配置中设置：http.listen（默认 ":8080"，空=不启用）
# 也可用参数临时覆盖：-http :9090

curl http://127.0.0.1:8080/metrics
# ddosguard_packets_received / records_parsed / records_matched / hits_total / parse_errors
```

## 测试

```bash
make test
```

覆盖：

- `netflow`：v5 解析（含 ICMP 端口处理）、v9 模板/数据/模板持久化、IPFIX 变长字段；
- `detect`：滑动窗口累计与滚出、阈值判定、冷却抑制、网段过滤、**UDP→解析→检测→处置** 集成链路；
- `switchctl`：命令模板渲染、**真实 SSH 协议**（内置 mock SSH 服务器）执行与命令核对。

## 端到端验证（本机模拟）

```bash
# 1) 起 mock 交换机（记录收到的命令）
go run testdata/mockssh/main.go -addr 127.0.0.1:2222

# 2) 起 ddosguard（用示例配置，监听 127.0.0.1:12055 便于本机测试）
./build/ddosguard -config build/e2e.yaml

# 3) 发送 10 条 dst=203.0.113.9:443 的 v5 流
python3 - <<'EOF'
import socket, struct, time
pkt = struct.pack('!HHIIIIBBH', 5, 10, 70000, int(time.time()), 0, 1, 0, 0, 0)
for _ in range(10):
    pkt += struct.pack('!4s4s4sHHIIIIHHBBBBHHBBH',
        socket.inet_aton('192.0.2.50'), socket.inet_aton('203.0.113.9'), socket.inet_aton('0.0.0.0'),
        1, 2, 10, 1500, 1000, 60000, 40000, 443, 0, 0x10, 6, 0, 0, 0, 24, 24, 0)
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(pkt, ('127.0.0.1', 12055))
EOF
```

预期：ddosguard 输出 `ddos attack detected`，mockssh 收到
`rule 800 deny tcp destination-port eq 443 destination 203.0.113.9 0.0.0.0`；
同一批次内多个目标命中时编号连续分配（800、801...）；下一次批次的编号
重新从 800 开始（覆盖上一次下发的规则）。

## 注意事项

- 检测基于流记录（flow），**连接数 = 窗口内 flow 条数**；若设备开启采样，实际连接数会被
  低估（采样率越高越明显），可通过调低 `min_flows` 或结合 `min_bytes` 使用。
- 交换机 SSH 账号建议使用仅具备下发 ACL 权限的专用账号；私钥认证优先于密码。
- 下发命令前建议在测试环境验证模板（不同厂商/型号的命令差异较大）。
- 如需持久化封堵记录或与工单系统联动，可在 `switchctl.Executor.Run` 后扩展。
