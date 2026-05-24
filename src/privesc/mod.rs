//! 后渗透提权模块
//!
//! Windows/Linux 提权检查，检测系统配置错误、敏感文件、可利用权限等

pub mod linux;
pub mod windows;

use serde::{Deserialize, Serialize};

/// 提权检查结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivescResult {
    pub hostname: String,
    pub os: String,
    pub current_user: String,
    pub is_admin: bool,
    pub findings: Vec<PrivescFinding>,
    pub stats: PrivescStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivescStats {
    pub total_checks: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

/// 单条提权发现
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivescFinding {
    pub category: String,
    pub severity: PrivescSeverity,
    pub title: String,
    pub description: String,
    pub detail: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivescSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl PrivescSeverity {
    pub fn display_name(&self) -> &str {
        match self {
            PrivescSeverity::Critical => "严重",
            PrivescSeverity::High => "高危",
            PrivescSeverity::Medium => "中危",
            PrivescSeverity::Low => "低危",
            PrivescSeverity::Info => "信息",
        }
    }

    pub fn color_code(&self) -> &str {
        match self {
            PrivescSeverity::Critical => "\x1b[31m",
            PrivescSeverity::High => "\x1b[33m",
            PrivescSeverity::Medium => "\x1b[36m",
            PrivescSeverity::Low => "\x1b[32m",
            PrivescSeverity::Info => "\x1b[37m",
        }
    }
}

/// 运行所有提权检查
pub fn run_all_checks() -> PrivescResult {
    #[cfg(windows)]
    {
        windows::run_checks()
    }
    #[cfg(not(windows))]
    {
        linux::run_checks()
    }
}

/// 运行指定类别的检查
pub fn run_check(category: &str) -> Vec<PrivescFinding> {
    #[cfg(windows)]
    {
        windows::run_category(category)
    }
    #[cfg(not(windows))]
    {
        linux::run_category(category)
    }
}

/// 获取可用检查类别列表
pub fn available_categories() -> Vec<&'static str> {
    #[cfg(windows)]
    {
        vec![
            "service", "credentials", "registry", "tokens",
            "files", "patches", "dll", "all",
        ]
    }
    #[cfg(not(windows))]
    {
        vec![
            "suid", "capabilities", "cron", "writable",
            "docker", "sudo", "ssh", "kernel", "all",
        ]
    }
}
