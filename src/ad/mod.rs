//! Active Directory 深度枚举模块
//!
//! 提供 LDAP 查询、Kerberoasting、AS-REP Roasting 和 BloodHound 输出

pub mod bloodhound;
pub mod ldap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// AD 枚举结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdEnumResult {
    pub domain_name: String,
    pub domain_controller: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_secs: f64,
    pub users: Vec<AdUser>,
    pub groups: Vec<AdGroup>,
    pub computers: Vec<AdComputer>,
    pub kerberoast_targets: Vec<KerberoastTarget>,
    pub asrep_targets: Vec<AsrepTarget>,
    pub gpos: Vec<String>,
    pub trusts: Vec<AdTrust>,
    pub stats: AdEnumStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdEnumStats {
    pub users_found: usize,
    pub groups_found: usize,
    pub computers_found: usize,
    pub kerberoast_targets: usize,
    pub asrep_targets: usize,
    pub gpos_found: usize,
    pub trusts_found: usize,
    pub admin_accounts: usize,
    pub da_accounts: usize,
}

/// AD 用户
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdUser {
    pub sam_account_name: String,
    pub display_name: Option<String>,
    pub dn: String,
    pub description: Option<String>,
    pub email: Option<String>,
    pub admin_count: bool,
    pub enabled: bool,
    pub password_expired: bool,
    pub last_logon: Option<String>,
    pub member_of: Vec<String>,
    pub spn: Vec<String>,
    pub sid: Option<String>,
}

/// AD 组
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGroup {
    pub name: String,
    pub dn: String,
    pub description: Option<String>,
    pub members: Vec<String>,
    pub admin_count: bool,
}

/// AD 计算机
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdComputer {
    pub name: String,
    pub dn: String,
    pub dns_hostname: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub enabled: bool,
    pub last_logon: Option<String>,
}

/// Kerberoasting 目标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberoastTarget {
    pub username: String,
    pub dn: String,
    pub spn: String,
    pub service_type: String,
    pub admin_count: bool,
    pub enabled: bool,
    pub description: Option<String>,
}

/// AS-REP Roasting 目标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsrepTarget {
    pub username: String,
    pub dn: String,
    pub enabled: bool,
    pub description: Option<String>,
}

/// AD 信任关系
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdTrust {
    pub domain: String,
    pub trust_type: String,
    pub trust_direction: String,
    pub trust_attributes: String,
}

impl Default for AdEnumResult {
    fn default() -> Self {
        Self {
            domain_name: String::new(),
            domain_controller: None,
            start_time: Utc::now(),
            end_time: Utc::now(),
            duration_secs: 0.0,
            users: Vec::new(),
            groups: Vec::new(),
            computers: Vec::new(),
            kerberoast_targets: Vec::new(),
            asrep_targets: Vec::new(),
            gpos: Vec::new(),
            trusts: Vec::new(),
            stats: AdEnumStats::default(),
        }
    }
}
