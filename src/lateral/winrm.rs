//! WinRM 远程执行模块
//!
//! 远程执行PowerShell命令。WinRM是Windows远程管理的标准方式。

use crate::lateral::LateralConfig;

/// 执行WinRM远程命令
pub async fn execute_winrm(config: &LateralConfig) -> Result<(String, String, i32), String> {
    let target = &config.target;

    tracing::info!("[WinRM] {} -> {}", whoami::hostname(), target);

    // 使用winrs命令
    if let Ok(result) = execute_via_winrs(config) {
        return Ok(result);
    }

    // 备用：PowerShell Invoke-Command
    execute_via_ps_remoting(config)
}

/// 通过winrs执行
fn execute_via_winrs(config: &LateralConfig) -> Result<(String, String, i32), String> {
    let mut cmd = std::process::Command::new("winrs");

    cmd.arg("-r:").arg(&config.target);

    // 添加认证
    match &config.credential {
        crate::lateral::LateralCredential::Cleartext { username, password, .. } => {
            cmd.arg("-u:").arg(username);
            cmd.arg("-p:").arg(password);
        }
        _ => {}
    }

    // 执行命令
    let full_command = format!("{} {}", config.command, config.args.join(" "));
    cmd.arg(&full_command);

    let output = cmd.output()
        .map_err(|e| format!("winrs执行失败: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    Ok((stdout, stderr, exit_code))
}

/// 通过PowerShell Remoting执行
fn execute_via_ps_remoting(config: &LateralConfig) -> Result<(String, String, i32), String> {
    let full_command = format!("{} {}", config.command, config.args.join(" "));

    let cred_block = match &config.credential {
        crate::lateral::LateralCredential::Cleartext { username, password, domain } => {
            let domain_part = domain.as_deref().unwrap_or(".");
            format!(
                "$secpass = ConvertTo-SecureString '{}' -AsPlainText -Force;\
                 $cred = New-Object PSCredential('{}\\{}', $secpass);\
                 ",
                password, domain_part, username
            )
        }
        _ => String::new(),
    };

    let ps_script = format!(
        r#"{}
$session = New-PSSession -ComputerName '{}'{};
$result = Invoke-Command -Session $session -ScriptBlock {{ {} }} -ErrorAction Stop;
$result | Out-String;
Remove-PSSession $session;
"#,
        cred_block,
        config.target,
        if cred_block.is_empty() { "" } else { " -Credential $cred" },
        full_command.replace("'", "''"),
    );

    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .output()
        .map_err(|e| format!("PS Remoting失败: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    Ok((stdout, stderr, exit_code))
}

/// 测试WinRM端口是否开放
pub async fn test_winrm_port(target: &str, port: u16) -> bool {
    let addr = format!("{}:{}", target, port);
    tokio::net::TcpStream::connect(&addr).await.is_ok()
}

/// WinRM命令快捷方式
pub async fn winrm_shell(target: &str, command: &str) -> Result<(String, String, i32), String> {
    let config = LateralConfig::winrm(target, command);
    execute_winrm(&config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_winrm_port_test_localhost() {
        // 测试本地端口（一般不会开放）
        let result = test_winrm_port("127.0.0.1", 5985).await;
        // 可能为true或false
    }
}
