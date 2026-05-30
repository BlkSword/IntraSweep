# IntraSweep - 内网渗透辅助工具

IntraSweep 是一个基于 Rust 开发的高性能内网渗透辅助工具，提供网络扫描、信息收集、密码爆破、漏洞检测、AD 域枚举、提权检测和内网穿透功能。

## 特性

- **高性能扫描** - 异步 I/O + 多级并发架构，支持 TCP Connect/SYN/UDP 扫描、ARP/ICMP 主机发现
- **交互式向导** - 7 大功能均支持交互式配置向导，无需记忆复杂参数
- **漏洞扫描** - 内置 31 条 PoC 规则，支持外部 YAML/JSON 声明式 PoC 和 Python/PowerShell 脚本 PoC，多步骤变量提取
- **Web 指纹识别** - 内置 33 条指纹规则，覆盖中间件/OA/DevOps/基础设施
- **AD 域枚举** - LDAP 查询用户/组/计算机，Kerberoasting、AS-REP Roasting、BloodHound 数据导出
- **提权检测** - Windows 6 类 / Linux 8 类自动化提权向量检查
- **密码爆破** - 8 种服务（SSH/RDP/Redis/PostgreSQL/MySQL/MSSQL/MongoDB/WinRM），Semaphore 并发控制 + 命中即停
- **内网穿透** - 正向/反向隧道、SOCKS5 代理、多级链式跳板，支持 XChaCha20-Poly1305 加密和连接多路复用，Ctrl+C 优雅关闭
- **格式化输出** - JSON/CSV 双格式导出
- **OPSEC 优化** - LTO + strip + codegen-units=1 最小体积、敏感字符串 XOR 编译期混淆
- **模块化架构** - CLI 层与业务逻辑分离，各功能模块独立自治

## 安装

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 克隆并构建
git clone https://github.com/BlkSword/IntraSweep.git
cd IntraSweep
cargo build --release
```

可执行文件位于 `target/release/intrasweep.exe`

## 项目结构

```
src/
├── main.rs           入口（命令路由）
├── cli/              CLI 层（命令处理、交互式向导、结果展示）
│   ├── mod.rs        Cli/Commands 定义、InteractiveMenu、共享工具
│   ├── scan.rs       扫描命令
│   ├── crack.rs      爆破命令
│   ├── tunnel.rs     隧道命令
│   ├── vuln.rs       漏洞扫描命令
│   ├── ad.rs         AD 枚举命令
│   ├── privesc.rs    提权检测命令
│   └── system.rs     信息收集命令
├── scanner/          扫描引擎（主机发现、端口扫描、服务探测、Web 指纹）
├── cracker/          密码爆破（8 种服务、并发引擎、字典管理）
├── tunnel/           网络穿透（正向/反向/SOCKS5/链式、加密、多路复用、双向中继、优雅关闭）
├── vuln/             漏洞扫描（PoC 引擎、内置规则、外部加载、脚本执行）
├── ad/               AD 域枚举（LDAP 查询、Kerberoasting、BloodHound 导出）
├── privesc/          提权检测（Windows/Linux 平台检查）
├── collector/        信息收集（系统、网络、进程、凭据、文件）
├── core/             核心库（错误处理、日志、字符串混淆）
└── output/           输出层（JSON/CSV 导出、彩色终端、进度条）
```

## 快速开始

### 全局选项

```bash
intrasweep -v <command> ...          # 详细输出 (DEBUG 级别日志)
intrasweep -q <command> ...          # 安静模式 (仅错误)
intrasweep --log-file log.txt <command> ...  # 日志写入文件
```

### 网络扫描

```bash
# 交互式向导（推荐）
intrasweep scan

# 直接扫描
intrasweep scan 192.168.1.0/24 port          # 端口扫描
intrasweep scan 192.168.1.0/24 host           # 主机发现
intrasweep scan 192.168.1.0/24 comprehensive  # 综合扫描（主机+端口+服务）

# 快速模式
intrasweep scan 192.168.1.0/24 port --fast

# Web 指纹识别
intrasweep scan 192.168.1.0/24 port --webfinger
intrasweep scan 192.168.1.0/24 comprehensive --webfinger -o result.json

# 输出格式
intrasweep scan 192.168.1.0/24 port --format csv -o result.csv
```

**扫描类型：**

| 类型 | 说明 |
|------|------|
| `port` | 端口扫描（默认 TCP Connect） |
| `host` | 主机发现（TCP SYN/ICMP/ARP） |
| `comprehensive` | 综合扫描（主机发现 + 端口扫描 + 服务探测） |

**主机发现方法：**

| 方法 | 说明 |
|------|------|
| TCP SYN | 默认，兼容性好 |
| ICMP | 需要 ICMP 权限 |
| ARP | 仅本地网段，速度快（Windows） |
| Hybrid | TCP SYN + ICMP 组合 |

**扫描预设：**

| 预设 | 说明 |
|------|------|
| Fast | 高并发、短超时 |
| Standard | 平衡速度与准确性 |
| Deep | 全端口扫描 |
| Stealth | 低并发、有延迟 |

### 系统信息收集

```bash
intrasweep system all        # 全量收集
intrasweep system system     # 系统信息（OS、主机名、架构、CPU、内存）
intrasweep system network    # 网络信息（接口、路由、ARP、连接）
intrasweep system process    # 进程信息（列表、可疑进程、资源占用）
intrasweep system credential # 凭据信息（密码哈希、令牌、SSH 密钥、API Key）
intrasweep system file       # 文件信息（敏感文件、配置文件、最近文件）
intrasweep system domain     # 域环境（域加入状态、域控、域用户、SPN）
intrasweep system all -o report.json   # 收集并保存
intrasweep system all -q               # 静默模式（不显示进度条）
```

| 命令 | 缩写 | 功能 |
|------|------|------|
| `all` | `a` | 全量收集 |
| `system` | `sy` | 系统信息 |
| `network` | `n` | 网络信息 |
| `process` | `p` | 进程信息 |
| `credential` | `c` | 凭据信息 |
| `file` | `f` | 文件信息 |
| `domain` | `d` | 域环境信息 |

### 密码爆破

```bash
# 交互式向导
intrasweep crack

# 直接爆破
intrasweep crack 192.168.1.1 -s ssh -u root -P passwords.txt
intrasweep crack 192.168.1.1 -s rdp -u administrator -P passwords.txt
intrasweep crack 192.168.1.1 -s redis -P passwords.txt
intrasweep crack 192.168.1.1 -s mysql -u root -P passwords.txt -c 20 -t 10

# 指定端口
intrasweep crack 192.168.1.1 -s ssh -p 2222 -u root -P passwords.txt

# 用户名字典
intrasweep crack 192.168.1.1 -s ssh -U users.txt -P passwords.txt

# 逗号分隔用户名
intrasweep crack 192.168.1.1 -s ssh -u "root,admin,test" -P passwords.txt

# 延迟（避免触发防护）
intrasweep crack 192.168.1.1 -s ssh -u root -P passwords.txt --delay 500
```

**支持服务：**

| 服务 | 默认端口 | 说明 |
|------|---------|------|
| `ssh` | 22 | SSH |
| `rdp` | 3389 | 远程桌面（支持 CredSSP/NLA） |
| `redis` | 6379 | Redis |
| `postgres` | 5432 | PostgreSQL |
| `mysql` | 3306 | MySQL |
| `mssql` | 1433 | Microsoft SQL Server |
| `mongodb` | 27017 | MongoDB |
| `winrm` | 5985 | WinRM（支持 NTLM 认证） |

### 漏洞扫描

```bash
# 交互式向导
intrasweep vuln

# 对目标运行内置 PoC
intrasweep vuln 192.168.1.0/24
intrasweep vuln 192.168.1.0/24 --severity critical   # 仅检测严重漏洞
intrasweep vuln 192.168.1.0/24 --category 未授权     # 按类别过滤

# 加载外部 PoC 文件/目录
intrasweep vuln 192.168.1.0/24 --poc-file ./pocs/

# 输出格式
intrasweep vuln 192.168.1.0/24 --format csv -o results.csv
```

### AD 域深度枚举

```bash
# 完整枚举（用户、组、计算机、Kerberoast/AS-REP 目标、信任关系、GPO）
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password

# 仅 Kerberoasting（提取 SPN 账户）
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password -m kerberoast

# 仅 AS-REP Roasting（预认证禁用用户）
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password -m asrep-roast

# 导出 BloodHound 数据
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password -m bloodhound --bloodhound-dir ./bh_data

# 使用 LDAPS
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password --ssl

# 导出结果
intrasweep ad --dc 10.0.0.1 -d corp.local -u admin -p password -o ad_result.json
```

### 提权检测

```bash
# 运行所有检查（自动识别 Windows/Linux）
intrasweep privesc

# 指定检查类别
intrasweep privesc --check service       # Windows: 服务相关
intrasweep privesc --check credentials   # Windows: 凭据相关
intrasweep privesc --check tokens        # Windows: 令牌特权
intrasweep privesc --check suid          # Linux: SUID 二进制
intrasweep privesc --check sudo          # Linux: Sudo 规则
intrasweep privesc --check docker        # Linux: Docker 组

# 导出结果
intrasweep privesc -o privesc_result.json
intrasweep privesc --format csv -o privesc_result.csv
```

### 内网穿透

```bash
# 交互式向导（推荐，包含加密配置）
intrasweep tunnel

# 正向隧道 — 本地端口转发到远程目标
intrasweep tunnel forward -t 192.168.1.100:3389 -L 8080

# 反向隧道 — 从内网建立连接回外网
intrasweep tunnel reverse -t 10.0.0.1:8888 -L 8080

# SOCKS5 代理 — 动态端口转发
intrasweep tunnel socks5 -L 1080
intrasweep tunnel socks5 -L 1080 --socks5-username user --socks5-password pass

# 链式隧道 — 多级跳板连接
intrasweep tunnel chain -H 10.0.0.1:2222 -H 10.0.0.2:3333 -t 192.168.2.100:80

# 加密隧道 — XChaCha20-Poly1305 AEAD 加密传输
intrasweep tunnel forward -t 192.168.1.100:3389 -L 8080 --encryption-key "my-secret"
intrasweep tunnel reverse -t 10.0.0.1:8888 -L 8080 --encryption-key "my-secret"
```

所有隧道类型支持 Ctrl+C 优雅关闭，收到信号后自动断开连接并清理资源。

## 命令参考

### Scan

| 参数 | 说明 |
|------|------|
| `<targets>` | 扫描目标（IP/CIDR/范围），可选，不填进入交互式 |
| `<scan_type>` | `port` / `host` / `comprehensive`，可选 |
| `--fast` | 快速扫描预设 |
| `--webfinger` | 启用 Web 指纹识别 |
| `--format` | 输出格式 `json` / `csv`（默认 `json`） |
| `-o` | 输出文件路径 |

### System

| 参数 | 说明 |
|------|------|
| `<item>` | 收集项目：`all(a)` `system(sy)` `network(n)` `process(p)` `credential(c)` `file(f)` `domain(d)` |
| `-o` | 输出文件路径 |
| `-q` | 静默模式（不显示进度条） |

### Crack

| 参数 | 说明 |
|------|------|
| `<target>` | 目标主机，可选，不填进入交互式 |
| `-s, --service` | 服务类型：`ssh` `rdp` `redis` `postgres` `mysql` `mssql` `mongodb` `winrm` |
| `-p, --port` | 端口（默认使用服务默认端口） |
| `-u, --usernames` | 用户名（逗号分隔） |
| `-U, --username-file` | 用户名字典文件 |
| `-P, --password-file` | 密码字典文件 |
| `-c, --concurrency` | 并发数（默认 10） |
| `-t, --timeout` | 超时秒数（默认 5） |
| `--delay` | 延迟毫秒数（可选，用于避免触发防护） |

### Vuln

| 参数 | 说明 |
|------|------|
| `<targets>` | 扫描目标（IP/CIDR/host:port），可选，不填进入交互式 |
| `--poc-file` | 外部 PoC 文件或目录（YAML/JSON/脚本） |
| `--severity` | 按严重性过滤：`critical` `high` `medium` `low` `info` |
| `--category` | 按类别过滤 |
| `--format` | 输出格式 `json` / `csv`（默认 `json`） |
| `-o` | 输出文件路径 |
| `-c, --concurrency` | 并发数（默认 20） |
| `-t, --timeout` | 超时秒数（默认 10） |

### Ad

| 参数 | 说明 |
|------|------|
| `--dc` | 域控 IP 地址（必填） |
| `-d, --domain` | 域名（必填，例 `corp.local`） |
| `-u, --username` | 认证用户名 |
| `-p, --password` | 认证密码 |
| `--ssl` | 使用 LDAPS（端口 636） |
| `-m, --mode` | 模式：`all`（默认） `kerberoast` `asrep-roast` `bloodhound` |
| `--bloodhound-dir` | BloodHound 输出目录（`--mode bloodhound` 时使用） |
| `--format` | 输出格式（默认 `json`） |
| `-o` | 输出文件路径 |

### Privesc

| 参数 | 说明 |
|------|------|
| `-c, --check` | 检查类别，不填则运行全部 |
| `--format` | 输出格式（默认 `json`） |
| `-o` | 输出文件路径 |

**Windows 类别：** `service` `credentials` `registry` `tokens` `files` `patches`

**Linux 类别：** `suid` `capabilities` `cron` `writable` `docker` `sudo` `ssh` `kernel`

### Tunnel

| 参数 | 说明 |
|------|------|
| `<type>` | 隧道类型：`forward` / `reverse` / `socks5` / `chain`，可选，不填进入交互式 |
| `-t, --target` | 目标地址 `host:port` |
| `-L, --local-port` | 本地监听端口 |
| `-R, --remote-port` | 远程监听端口 |
| `-H, --hop` | 跳板主机（可多次指定） |
| `--socks5-username` | SOCKS5 认证用户名 |
| `--socks5-password` | SOCKS5 认证密码 |
| `--encryption-key` | 加密密钥（设置后启用 XChaCha20-Poly1305 AEAD 加密） |
| `--mux` | 启用连接多路复用 |
| `-c, --max-connections` | 最大并发连接（默认 100） |
| `-t, --timeout` | 超时秒数（默认 30） |

## 漏洞扫描

### 内置 PoC 规则（31 条）

| 类别 | 数量 | 规则 |
|------|------|------|
| 反序列化 | 3 | Shiro-550, Fastjson, Log4Shell (CVE-2021-44228) |
| 未授权访问 | 15 | Nacos, Jenkins, Elasticsearch, Harbor, Redis, MongoDB, FTP 匿名, SMB 空会话, LDAP 空绑定, MSSQL SA 空密码, Memcached, ZooKeeper, Docker API, MySQL Root 空密码, phpMyAdmin |
| OA 系统 | 4 | 泛微OA, 致远OA, 通达OA, 蓝凌OA |
| RCE | 2 | WebLogic CVE-2020-14882, ThinkPHP 5.x RCE |
| 信息泄露 | 4 | .git 目录, .env 文件, Druid 监控, Spring Boot Actuator |
| 配置/检测 | 3 | SMB 签名未启用, RDP 开放, WinRM 开放 |

### 外部 PoC 格式

**HTTP 声明式 PoC：**

```yaml
id: example-poc
info:
  name: 示例漏洞检测
  severity: high
  category: 未授权
  description: 检测示例服务未授权访问
  remediation: 启用认证
transport: http
rules:
  - method: GET
    path: "/api/users"
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["username", "password"]
```

**TCP 协议 PoC：**

```yaml
id: service-check
info:
  name: 服务检测
  severity: medium
transport: tcp
default-port: 6379
rules:
  - data: "INFO\r\n"
    read-size: 4096
    matchers:
      - type: word
        words: ["version"]
```

**多步骤 PoC**（变量提取 + 步骤间传递）：

```yaml
id: multi-step-example
info:
  name: 多步骤检测示例
  severity: critical
transport: http
rules:
  - method: POST
    path: "/login"
    body: "user=admin&pass=admin"
    extractors:
      - name: token
        type: regex
        part: body
        regex: '"token":"([a-f0-9]+)"'
    matchers:
      - type: status
        status: [200]
  - method: GET
    path: "/api/admin?token={{token}}"
    matchers:
      - type: word
        words: ["admin_panel"]
```

**Python 脚本 PoC**（适用于复杂检测逻辑）：

```yaml
id: custom-check
info:
  name: 自定义 Python 检测
  severity: critical
transport: script
script:
  interpreter: python3
  code: |
    import json, socket, sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    vulnerable = False
    evidence = ""
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((target, port))
        # ... 检测代码
        s.close()
    except:
        pass
    print(json.dumps({"vulnerable": vulnerable, "evidence": evidence}))
  args: ["{{target}}", "{{port}}"]
  timeout: 30
```

或引用外部脚本文件：

```yaml
transport: script
script:
  interpreter: python3
  file: pocs/ms17-010.py
  args: ["{{target}}", "{{port}}"]
```

脚本输出规范：

```json
{"vulnerable": true, "evidence": "检测到漏洞的证据", "detail": "详细信息"}
```

支持的解释器：`python3`、`python`、`powershell`、`pwsh`、`bash`、`sh`

### 匹配器类型

| 类型 | 说明 | 适用传输 |
|------|------|---------|
| word | 字符串包含匹配 | HTTP, TCP |
| regex | 正则表达式匹配 | HTTP, TCP |
| status | HTTP 状态码匹配 | HTTP |
| binary | 十六进制字节匹配 | TCP |

## AD 域深度枚举

通过 LDAP 协议连接域控，执行 Active Directory 信息收集。

| 功能 | 说明 |
|------|------|
| 用户枚举 | 查询所有域用户（管理员标识、启用状态、组成员关系、SPN） |
| 组枚举 | 查询所有域组（成员列表、管理员组标识） |
| 计算机枚举 | 查询域内主机（操作系统版本、DNS 名称、启用状态） |
| Kerberoasting | 提取所有 SPN 账户，标注服务类型、管理员标识 |
| AS-REP Roasting | 查找不需要预认证的用户账户 |
| 信任关系 | 枚举域信任（方向、类型、属性） |
| GPO 枚举 | 列出域内组策略对象 |
| BloodHound 导出 | 生成 BloodHound 兼容 JSON（users/groups/computers/domains），可直接导入分析 |

| 模式 | 说明 |
|------|------|
| `all`（默认） | 完整枚举 |
| `kerberoast` | 仅提取 Kerberoast 目标 |
| `asrep-roast` | 仅查找 AS-REP Roast 目标 |
| `bloodhound` | 枚举并导出 BloodHound 格式数据 |

## 提权检测

自动化检测当前系统上的提权向量，自动识别平台。

### Windows 检查项

| 类别 | 检查项 | 严重性 |
|------|--------|--------|
| 服务 | 未引用服务路径、弱服务权限、可写服务二进制 | 高危 |
| 注册表 | AlwaysInstallElevated | 严重 |
| 凭据 | cmdkey 存储凭据、自动登录密码、SAM 文件访问 | 严重 |
| 令牌 | SeDebugPrivilege、SeImpersonatePrivilege、SeLoadDriverPrivilege 等 | 高危 |
| 文件 | unattend.xml、sysprep 配置、凭据目录 | 高危~严重 |
| 补丁 | 缺失安全更新 KB（KB4534271 等） | 高危 |

### Linux 检查项

| 类别 | 检查项 | 严重性 |
|------|--------|--------|
| SUID | GTFOBins 已知可利用 SUID 二进制（25+ 种） | 高危 |
| Capabilities | 危险 capabilities（cap_setuid、cap_sys_admin、cap_dac_override 等） | 高危 |
| Cron | 可写 cron 配置、用户 crontab | 高危~严重 |
| 可写文件 | /etc/passwd、/etc/shadow、/etc/sudoers | 严重 |
| Docker | docker 组成员 | 严重 |
| Sudo | 危险 NOPASSWD 规则（GTFOBins） | 高危~严重 |
| SSH | 私钥文件、其他用户密钥 | 高危~严重 |
| 内核 | 已知漏洞匹配（Dirty Cow、Dirty Pipe、PwnKit、Baron Samedit） | 高危~严重 |

## Web 指纹识别

内置 33 条指纹规则，覆盖常见内网 Web 应用：

| 类别 | 支持的应用 |
|------|-----------|
| 中间件 | WebLogic, Apache Tomcat, JBoss, WebSphere, Nginx, Apache HTTPD, IIS, OpenResty |
| 管理面板 | 宝塔面板, phpMyAdmin, Adminer |
| OA 系统 | 泛微OA, 致远OA, 蓝凌OA, 通达OA |
| 开发工具 | Jenkins, GitLab, Gitea, SonarQube |
| 基础设施 | Nacos, SkyWalking, Elasticsearch, Harbor, RabbitMQ 管理, Grafana, Prometheus |
| 框架 | Spring Boot, Django Admin, ThinkPHP |
| 协作/监控 | Confluence, Jira, Zabbix |
| 网络设备 | 路由器管理页面 |

## 版本

v0.3.0

## License

MIT
