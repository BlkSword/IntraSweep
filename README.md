# IntraSweep - 内网渗透辅助工具

IntraSweep 是一个基于 Rust 开发的高性能内网渗透辅助工具，提供扫描、信息收集、密码爆破、漏洞检测、AD 域枚举、提权检测和内网穿透功能。

## 特性

- **高性能扫描** - 异步 I/O 高并发架构
- **交互式向导** - 无需记忆复杂参数
- **漏洞扫描** - 内置 30+ PoC 规则，支持外部 YAML/JSON/Python 脚本 PoC，多步骤变量提取
- **Web 指纹识别** - 自动识别内网 Web 应用（WebLogic、宝塔面板、泛微OA 等）
- **AD 域枚举** - LDAP 查询、Kerberoasting、AS-REP Roasting、BloodHound 数据导出
- **提权检测** - Windows/Linux 自动化提权向量检查
- **密码爆破** - 支持多种服务（SSH/RDP/Redis/PostgreSQL/MySQL/MSSQL/MongoDB/WinRM）
- **内网穿透** - 正向/反向隧道、SOCKS5 代理、链式跳板
- **格式化输出** - 支持 JSON/CSV 格式导出
- **OPSEC 优化** - 发布二进制体积优化、关键字符串混淆

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

## 快速开始

### 漏洞扫描

```bash
# 交互式向导（推荐）
intrasweep vuln

# 对目标运行内置 PoC
intrasweep vuln 192.168.1.0/24
intrasweep vuln 192.168.1.0/24 --severity critical    # 仅检测严重漏洞
intrasweep vuln 192.168.1.0/24 --category 未授权      # 按类别过滤

# 加载外部 PoC 文件/目录
intrasweep vuln 192.168.1.0/24 --poc-file ./pocs/

# 输出格式
intrasweep vuln 192.168.1.0/24 --format csv -o vuln_results.csv
intrasweep vuln 192.168.1.0/24 --format json -o vuln_results.json
```

### AD 域深度枚举

```bash
# 完整枚举（用户、组、计算机、Kerberoast/AS-REP 目标、信任关系、GPO）
intrasweep ad --dc 10.0.0.1 --domain corp.local -u admin -p password

# 仅 Kerberoasting
intrasweep ad --dc 10.0.0.1 --domain corp.local -u admin -p password --mode kerberoast

# 仅 AS-REP Roasting
intrasweep ad --dc 10.0.0.1 --domain corp.local -u admin -p password --mode asrep-roast

# 导出 BloodHound 数据
intrasweep ad --dc 10.0.0.1 --domain corp.local -u admin -p password --mode bloodhound --bloodhound-dir ./bh_data

# 使用 LDAPS
intrasweep ad --dc 10.0.0.1 --domain corp.local -u admin -p password --ssl

# 导出结果
intrasweep ad --dc 10.0.0.1 --domain corp.local -u admin -p password -o ad_result.json
```

### 提权检测

```bash
# 运行所有检查（自动识别平台）
intrasweep privesc

# 指定检查类别
intrasweep privesc --check service       # Windows: 服务相关检查
intrasweep privesc --check credentials   # Windows: 凭据检查
intrasweep privesc --check suid          # Linux: SUID 二进制检查
intrasweep privesc --check sudo          # Linux: Sudo 规则检查

# 导出结果
intrasweep privesc -o privesc_result.json
intrasweep privesc --format csv -o privesc_result.csv
```

### 扫描功能

```bash
# 交互式向导（推荐）
intrasweep scan

# 快速命令
intrasweep scan 192.168.1.1              # 交互式配置
intrasweep scan 192.168.1.0/24 port      # 端口扫描
intrasweep scan 192.168.1.0/24 host      # 主机发现
intrasweep scan 192.168.1.0/24 comprehensive  # 综合扫描

# Web 指纹识别
intrasweep scan 192.168.1.0/24 port --webfinger        # 端口扫描 + Web 指纹
intrasweep scan 192.168.1.0/24 comprehensive --webfinger -o result.json

# CSV 格式输出
intrasweep scan 192.168.1.0/24 port --format csv -o result.csv
```

### 系统信息收集

```bash
intrasweep system all        # 全量收集
intrasweep system network    # 网络信息
intrasweep system domain     # 域环境信息
intrasweep system credential # 凭据信息
```

### 密码爆破

```bash
intrasweep crack              # 交互式向导
intrasweep crack 192.168.1.1 --service ssh -u root -P passwords.txt
```

### 内网穿透

```bash
# 交互式向导（推荐）
intrasweep tunnel

# 正向隧道 - 本地端口转发到远程目标
intrasweep tunnel forward -t 192.168.1.100:3389 -L 8080

# 反向隧道 - 从内网建立连接回外网
intrasweep tunnel reverse -t 10.0.0.1:8888 -L 8080

# SOCKS5 代理 - 动态端口转发
intrasweep tunnel socks5 -L 1080

# 链式隧道 - 多级跳板连接
intrasweep tunnel chain -H 10.0.0.1:2222 -H 10.0.0.2:3333 -t 192.168.2.100:80
```

### 全局选项

```bash
intrasweep -v scan ...       # 详细输出 (DEBUG 级别日志)
intrasweep -q scan ...       # 安静模式 (仅错误)
intrasweep --log-file scan.log scan ...  # 日志写入文件
```

## 命令参考

### System 命令

| 命令 | 缩写 | 功能 |
|-----|------|-----|
| all | a | 全量收集 |
| system | sy | 系统信息 |
| network | n | 网络信息 |
| process | p | 进程信息 |
| credential | c | 凭据信息 |
| file | f | 文件信息 |
| domain | d | 域信息 |

### Scan 命令

| 类型 | 功能 |
|-----|------|
| port | 端口扫描 |
| host | 主机发现 |
| comprehensive | 综合扫描 |

| 参数 | 说明 |
|-----|------|
| `--fast` | 快速扫描 |
| `--webfinger` | 启用 Web 指纹识别 |
| `--format <json\|csv>` | 输出格式 (默认: json) |
| `-o <file>` | 输出文件 |

### Vuln 命令（漏洞扫描）

| 参数 | 说明 |
|-----|------|
| `--poc-file <path>` | 外部 PoC 文件或目录（YAML/JSON/脚本） |
| `--severity <level>` | 按严重性过滤: critical, high, medium, low, info |
| `--category <name>` | 按类别过滤 |
| `--format <json\|csv>` | 输出格式 (默认: json) |
| `-o <file>` | 输出文件 |
| `-c, --concurrency` | 并发数（默认: 20） |
| `-t, --timeout` | 超时秒数（默认: 10） |

### Ad 命令（AD 域枚举）

| 参数 | 说明 |
|-----|------|
| `--dc <ip>` | 域控 IP 地址 |
| `-d, --domain <name>` | 域名（例: corp.local） |
| `-u, --username <user>` | 认证用户名 |
| `-p, --password <pass>` | 认证密码 |
| `--ssl` | 使用 LDAPS（端口 636） |
| `-m, --mode <mode>` | 模式: all, kerberoast, asrep-roast, bloodhound（默认: all） |
| `--bloodhound-dir <path>` | BloodHound 输出目录 |
| `--format <json\|csv>` | 输出格式（默认: json） |
| `-o <file>` | 输出文件 |

### Privesc 命令（提权检测）

| 参数 | 说明 |
|-----|------|
| `-c, --check <category>` | 指定检查类别或 `all`（默认: all） |
| `--format <json\|csv>` | 输出格式（默认: json） |
| `-o <file>` | 输出文件 |

**Windows 检查类别:** `service`, `credentials`, `registry`, `tokens`, `files`, `patches`

**Linux 检查类别:** `suid`, `capabilities`, `cron`, `writable`, `docker`, `sudo`, `ssh`, `kernel`

### Crack 命令

支持服务：`ssh`, `rdp`, `redis`, `postgres`, `mysql`, `mssql`, `mongodb`, `winrm`

| 参数 | 说明 |
|-----|------|
| `-s, --service` | 服务类型 |
| `-p, --port` | 端口 |
| `-u, --usernames` | 用户名（逗号分隔） |
| `-U, --username-file` | 用户名字典文件 |
| `-P, --password-file` | 密码字典文件 |
| `-c, --concurrency` | 并发数（默认: 10） |
| `-t, --timeout` | 超时秒数（默认: 5） |

### Tunnel 命令

| 类型 | 缩写 | 功能 |
|-----|------|-----|
| forward | fo | 正向 TCP 端口转发 |
| reverse | re | 反向 TCP 端口转发 |
| socks5 | so | SOCKS5 代理服务器 |
| chain | ch | 链式隧道（多级跳板）|

| 参数 | 说明 |
|-----|------|
| `-t, --target` | 目标地址 (host:port) |
| `-L, --local-port` | 本地监听端口 |
| `-R, --remote-port` | 远程监听端口 |
| `-H, --hop` | 跳板主机 (可多次指定) |
| `--socks5-username` | SOCKS5 认证用户名 |
| `--socks5-password` | SOCKS5 认证密码 |
| `-c, --max-connections` | 最大并发连接（默认: 100）|
| `--timeout` | 超时时间（秒，默认: 30）|

## 漏洞扫描

### 内置 PoC 规则（30+ 条）

| 类别 | 规则 |
|------|------|
| 反序列化 | Shiro-550, Fastjson, Log4Shell (CVE-2021-44228) |
| 未授权访问 | Nacos, Jenkins, Elasticsearch, Harbor, Redis, MongoDB, Memcached, ZooKeeper, Docker API, FTP 匿名, SMB 空会话, LDAP 空绑定 |
| OA 系统 | 泛微OA, 致远OA, 通达OA, 蓝凌OA |
| RCE | WebLogic CVE-2020-14882, ThinkPHP RCE |
| 数据库 | MSSQL SA 空密码, MySQL Root 空密码 |
| 服务检测 | SMB 签名检测, RDP 开放, WinRM 开放 |
| 信息泄露 | .git 目录, .env 文件, Druid 监控, phpMyAdmin Setup, Spring Boot Actuator |

### 外部 PoC 格式

**YAML 声明式 PoC**（适用于 HTTP/TCP 漏洞）：

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

**TCP 协议 PoC**：

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
    # 实现检测逻辑...
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

脚本输出规范 — JSON 格式：

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

通过 LDAP 协议连接域控，执行全面的 Active Directory 信息收集。

### 功能

| 功能 | 说明 |
|------|------|
| 用户枚举 | 查询所有域用户，含管理员标识、启用状态、组成员关系、SPN |
| 组枚举 | 查询所有域组，含成员列表、管理员组标识 |
| 计算机枚举 | 查询域内主机，含操作系统版本、DNS 名称 |
| Kerberoasting | 提取所有 SPN 账户，标注可利用的服务类型 |
| AS-REP Roasting | 查找不需要预认证的用户账户 |
| 信任关系 | 枚举域信任（方向、类型、属性） |
| GPO 枚举 | 列出域内组策略对象 |
| BloodHound 导出 | 生成 BloodHound 兼容 JSON，可直接导入分析 |

### 模式说明

| 模式 | 说明 |
|------|------|
| `all`（默认） | 执行完整枚举，输出所有信息 |
| `kerberoast` | 仅提取 Kerberoast 目标（SPN 账户） |
| `asrep-roast` | 仅查找 AS-REP Roast 目标（预认证禁用用户） |
| `bloodhound` | 执行完整枚举并导出 BloodHound 格式数据 |

## 提权检测

自动化检测当前系统上的提权向量，支持 Windows 和 Linux。

### Windows 检查项

| 类别 | 检查项 | 严重性 |
|------|--------|--------|
| 服务 | 未引用服务路径、弱服务权限、可写服务二进制 | 高危 |
| 注册表 | AlwaysInstallElevated | 严重 |
| 凭据 | 存储凭据(cmdkey)、自动登录密码、SAM 文件访问 | 严重 |
| 令牌 | SeDebugPrivilege、SeImpersonatePrivilege 等高特权令牌 | 高危 |
| 文件 | unattend.xml、sysprep 配置、凭据目录 | 高危~严重 |
| 补丁 | 缺失的安全更新 KB | 高危 |

### Linux 检查项

| 类别 | 检查项 | 严重性 |
|------|--------|--------|
| SUID | GTFOBins 已知可利用 SUID 二进制（25+ 种） | 高危 |
| Capabilities | 危险 capabilities（cap_setuid、cap_sys_admin 等） | 高危 |
| Cron | 可写 cron 配置、用户 crontab | 高危~严重 |
| 可写文件 | /etc/passwd、/etc/shadow、/etc/sudoers | 严重 |
| Docker | docker 组成员 | 严重 |
| Sudo | 危险 NOPASSWD 规则（GTFOBins） | 高危~严重 |
| SSH | 私钥文件、其他用户密钥 | 高危~严重 |
| 内核 | 已知内核漏洞匹配（Dirty Cow、Dirty Pipe、PwnKit 等） | 高危~严重 |

## Web 指纹识别

内置 30+ 条指纹规则，覆盖常见内网 Web 应用：

| 类别 | 支持的应用 |
|------|-----------|
| 中间件 | WebLogic, Tomcat, JBoss, WebSphere, Nginx, IIS, OpenResty |
| 管理面板 | 宝塔面板, phpMyAdmin, Adminer |
| OA 系统 | 泛微OA, 致远OA, 蓝凌OA, 通达OA |
| 开发工具 | Jenkins, GitLab, Gitea, SonarQube |
| 基础设施 | Nacos, SkyWalking, Elasticsearch, Harbor, RabbitMQ, Grafana, Prometheus |
| 框架 | Spring Boot, Django Admin, ThinkPHP |
| 其他 | Zabbix, Confluence, Jira |

## 扫描预设

| 预设 | 说明 |
|-----|------|
| `--fast` | 快速扫描 |
| `--type <type>` | 扫描类型 |
| `-o <file>` | 输出文件 |

## 版本

v0.3.0

## License

MIT
