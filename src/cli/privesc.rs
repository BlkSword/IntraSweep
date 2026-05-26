//! 提权检测 CLI

use crate::cli::print_banner;
use crate::core::Result;
use crate::output::color::{print_info, print_success};
use crate::output::format::OutputFormat;
use std::path::PathBuf;

pub fn run_privesc_cmd(
    check: Option<String>,
    format: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    let output_fmt = OutputFormat::from_str(format)
        .unwrap_or(OutputFormat::Json);

    print_banner();
    println!();

    let privesc_label = crate::core::obfstr::sensitive::privesc_label();
    print_info(&format!("开始{}...", privesc_label));
    println!();

    let categories = crate::privesc::available_categories();
    println!("可用检查类别: {}", categories.join(", "));
    println!();

    // 执行检查
    let result = if let Some(ref category) = check {
        if category == "all" {
            crate::privesc::run_all_checks()
        } else {
            let findings = crate::privesc::run_check(category);
            crate::privesc::PrivescResult {
                hostname: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
                os: std::env::consts::OS.to_string(),
                current_user: whoami::username(),
                is_admin: false,
                findings,
                stats: Default::default(),
            }
        }
    } else {
        crate::privesc::run_all_checks()
    };

    // 打印结果
    print_privesc_results(&result);

    // 保存结果
    let path = output.unwrap_or_else(|| {
        PathBuf::from(crate::output::format::generate_output_filename(
            &result.hostname,
            output_fmt,
        ))
    });

    let json = serde_json::to_string_pretty(&result)?;
    std::fs::write(&path, json)?;
    print_success(&format!("结果已保存: {}", path.display()));

    Ok(())
}

fn print_privesc_results(result: &crate::privesc::PrivescResult) {
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  {} 结果", crate::core::obfstr::sensitive::privesc_label());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  主机名: {}", result.hostname);
    println!("  系统: {}", result.os);
    println!("  当前用户: {} {}", result.current_user, if result.is_admin { "[管理员]" } else { "" });
    println!();

    if result.findings.is_empty() {
        print_success("未发现提权风险");
        return;
    }

    // 统计
    let stats = &result.stats;
    println!("  发现风险: {}", stats.total_checks);
    if stats.critical_count > 0 {
        println!("  {}{}严重: {}{}", "\x1b[31m", "■", stats.critical_count, "\x1b[0m");
    }
    if stats.high_count > 0 {
        println!("  {}{}高危: {}{}", "\x1b[33m", "■", stats.high_count, "\x1b[0m");
    }
    if stats.medium_count > 0 {
        println!("  {}{}中危: {}{}", "\x1b[36m", "■", stats.medium_count, "\x1b[0m");
    }
    println!();

    // 详细发现
    for finding in &result.findings {
        println!("  {}[{}] {} [{}]{}",
            finding.severity.color_code(),
            finding.severity.display_name(),
            finding.title,
            finding.category,
            "\x1b[0m");
        if !finding.description.is_empty() {
            println!("    {}", finding.description);
        }
        if !finding.detail.is_empty() {
            let detail: String = finding.detail.chars().take(200).collect();
            println!("    详情: {}", detail.replace('\n', " "));
        }
        if !finding.remediation.is_empty() {
            println!("    修复: {}", finding.remediation);
        }
        println!();
    }
}
