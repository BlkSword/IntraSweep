//! Token窃取/模拟模块

use serde::{Deserialize, Serialize};

/// Token信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub process_name: String,
    pub pid: u32,
    pub username: String,
    pub token_type: String,
    pub privileges: Vec<String>,
    pub can_impersonate: bool,
}

/// 枚举可用的Token
pub fn enumerate_tokens() -> Result<Vec<TokenInfo>, String> {
    let mut tokens = Vec::new();

    if cfg!(windows) {
        // 使用PowerShell获取进程令牌信息
        let ps_script = r#"
Get-Process | Where-Object { $_.HandleCount -gt 0 } | Select-Object -First 50 |
ForEach-Object {
    try {
        $proc = $_;
        $token = $proc.Handle;
        if ($token) {
            [PSCustomObject]@{
                Name = $proc.Name;
                PID = $proc.Id;
                UserName = (Get-Process -Id $proc.Id -IncludeUserName).UserName;
                SessionId = $proc.SessionId;
            }
        }
    } catch {}
} | ConvertTo-Json
"#;
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", ps_script])
            .output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
                for p in parsed {
                    let name = p["Name"].as_str().unwrap_or("unknown");
                    let pid = p["PID"].as_u64().unwrap_or(0) as u32;
                    let username = p["UserName"].as_str().unwrap_or("unknown");

                    tokens.push(TokenInfo {
                        process_name: name.to_string(),
                        pid,
                        username: username.to_string(),
                        token_type: "ProcessToken".to_string(),
                        privileges: Vec::new(),
                        can_impersonate: username.contains("SYSTEM") || username.contains("Administrator"),
                    });
                }
            }
        }
    }

    Ok(tokens)
}

/// 查找SYSTEM令牌
pub fn find_system_token() -> Option<TokenInfo> {
    enumerate_tokens().ok().and_then(|tokens| {
        tokens.into_iter().find(|t| t.username.contains("SYSTEM"))
    })
}
