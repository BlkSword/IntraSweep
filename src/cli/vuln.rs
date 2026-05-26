//! 漏洞扫描 CLI

use crate::cli::{print_banner, InteractiveMenu};
use crate::core::Result;
use crate::output::color::{print_error, print_info, print_success};
use crate::output::format::OutputFormat;
use std::path::PathBuf;

pub fn run_vuln_cmd(
    targets: Option<Vec<String>>,
    poc_file: Option<PathBuf>,
    severity: Option<String>,
    category: Option<String>,
    format: &str,
    output: Option<PathBuf>,
    concurrency: usize,
    timeout: u64,
) -> Result<()> {
    let output_fmt = OutputFormat::from_str(format)
        .unwrap_or(OutputFormat::Json);

    if targets.is_none() {
        run_interactive_vuln(poc_file, severity, category, output_fmt, output, concurrency, timeout)
    } else {
        run_vuln_scan(targets.unwrap(), poc_file, severity, category, output_fmt, output, concurrency, timeout)
    }
}

fn run_vuln_scan(
    targets: Vec<String>,
    poc_file: Option<PathBuf>,
    severity: Option<String>,
    category: Option<String>,
    output_fmt: OutputFormat,
    output: Option<PathBuf>,
    concurrency: usize,
    timeout: u64,
) -> Result<()> {
    print_banner();
    println!();

    let vuln_label = crate::core::obfstr::sensitive::vuln_label();
    print_info(&format!("开始{}...", vuln_label));

    let mut pocs = crate::vuln::builtin::get_builtin_pocs();

    if let Some(ref poc_path) = poc_file {
        match crate::vuln::loader::load_pocs_from_path(poc_path) {
            Ok(external_pocs) => {
                print_success(&format!("已加载 {} 条外部PoC", external_pocs.len()));
                pocs.extend(external_pocs);
            }
            Err(e) => {
                print_error(&format!("加载外部PoC失败: {}", e));
            }
        }
    }

    let sev_filter = severity
        .as_deref()
        .and_then(crate::vuln::poc::Severity::from_str_opt);
    if sev_filter.is_some() || category.is_some() {
        pocs = crate::vuln::builtin::filter_builtin_pocs(sev_filter, category.as_deref());
        if let Some(ref sev) = sev_filter {
            println!("严重性过滤: {}", sev.display_name());
        }
        if let Some(ref cat) = category {
            println!("类别过滤: {}", cat);
        }
    }

    let expanded = crate::vuln::expand_targets(&targets);

    println!("目标数: {}", expanded.len());
    println!("PoC规则数: {}", pocs.len());
    println!("并发数: {}", concurrency);
    println!();

    let config = crate::vuln::VulnScanConfig::new(expanded, pocs)
        .with_timeout(std::time::Duration::from_secs(timeout))
        .with_concurrency(concurrency);

    let scanner = crate::vuln::VulnScanner::new(config);
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(scanner.scan());

    print_vuln_results(&result);

    let path = output.unwrap_or_else(|| {
        let base = if !result.targets.is_empty() {
            result.targets[0].replace('.', "_").replace(':', "_")
        } else {
            "vuln".to_string()
        };
        PathBuf::from(crate::output::format::generate_output_filename(&base, output_fmt))
    });

    match output_fmt {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&result)?;
            std::fs::write(&path, json)?;
        }
        OutputFormat::Csv => {
            export_vuln_csv(&result, &path)?;
        }
    }

    print_success(&format!("结果已保存: {}", path.display()));
    Ok(())
}

fn run_interactive_vuln(
    poc_file: Option<PathBuf>,
    severity: Option<String>,
    category: Option<String>,
    output_fmt: OutputFormat,
    output: Option<PathBuf>,
    concurrency: usize,
    timeout: u64,
) -> Result<()> {
    print_banner();
    println!();
    let vuln_label = crate::core::obfstr::sensitive::vuln_label();
    print_info(&format!("IntraSweep 交互式{}向导", vuln_label));
    println!();

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [1/4] 扫描目标");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("输入格式: IP, CIDR, IP范围, host:port (逗号分隔)");
    println!();

    let targets_input = InteractiveMenu::read_input("请输入扫描目标: ");
    if targets_input.is_empty() {
        print_error("未输入目标");
        return Ok(());
    }
    let targets: Vec<String> = targets_input.split(',').map(|s| s.trim().to_string()).collect();
    println!();

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [2/4] PoC 规则");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  1. 使用内置PoC规则 ({} 条)", crate::vuln::builtin::get_builtin_pocs().len());
    println!("  2. 加载外部PoC文件");
    println!("  3. 内置 + 外部");
    println!();

    let choice = InteractiveMenu::read_number("请选择 [1-3]: ", 1, 3);
    let external_path = if choice >= 2 {
        let path = InteractiveMenu::read_input("请输入PoC文件/目录路径: ");
        if !path.is_empty() {
            Some(PathBuf::from(path))
        } else {
            None
        }
    } else {
        poc_file
    };

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [3/4] 严重性过滤 (可选)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  可选: critical, high, medium, low, info (留空不过滤)");
    let sev_input = InteractiveMenu::read_input("严重性: ");
    let final_severity = if sev_input.is_empty() { severity } else { Some(sev_input) };

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [4/4] 确认配置");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  目标: {}", targets.join(", "));
    println!("  并发数: {}", concurrency);
    println!("  超时: {}s", timeout);
    if final_severity.is_some() {
        println!("  严重性过滤: {}", final_severity.as_deref().unwrap());
    }
    if external_path.is_some() {
        println!("  外部PoC: {:?}", external_path.as_ref().unwrap());
    }
    println!();

    let confirm = InteractiveMenu::read_input("开始扫描? [Y/n]: ");
    if confirm.eq_ignore_ascii_case("n") {
        print_info("已取消");
        return Ok(());
    }

    run_vuln_scan(targets, external_path, final_severity, category, output_fmt, output, concurrency, timeout)
}

fn print_vuln_results(result: &crate::vuln::VulnScanResult) {
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  {} 结果", crate::core::obfstr::sensitive::vuln_label());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    println!("  扫描目标: {}", result.stats.total_targets);
    println!("  PoC规则数: {}", result.stats.total_pocs);
    println!("  总请求数: {}", result.stats.total_requests);
    println!("  耗时: {:.2}s", result.duration_secs);
    println!();

    if result.findings.is_empty() {
        print_info("未发现漏洞");
        return;
    }

    println!("  发现漏洞: {}", result.stats.vulnerabilities_found);
    if result.stats.critical_count > 0 {
        println!("  {}{}严重: {}{}", "\x1b[31m", "■", result.stats.critical_count, "\x1b[0m");
    }
    if result.stats.high_count > 0 {
        println!("  {}{}高危: {}{}", "\x1b[33m", "■", result.stats.high_count, "\x1b[0m");
    }
    if result.stats.medium_count > 0 {
        println!("  {}{}中危: {}{}", "\x1b[36m", "■", result.stats.medium_count, "\x1b[0m");
    }
    if result.stats.low_count > 0 {
        println!("  {}{}低危: {}{}", "\x1b[32m", "■", result.stats.low_count, "\x1b[0m");
    }
    println!();

    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ {:<18} {:<6} {:<15} {:<8} {:<20} │",
        "目标", "端口", "漏洞ID", "严重性", "名称");
    println!("├────────────────────────────────────────────────────────────────────────────┤");

    for finding in &result.findings {
        let severity_str = format!("{}{}{}", finding.severity.color_code(),
            finding.severity.display_name(), "\x1b[0m");
        let target = if finding.target.len() > 16 {
            format!("{}...", &finding.target[..13])
        } else {
            finding.target.clone()
        };
        let name = if finding.vuln_name.len() > 18 {
            format!("{}...", &finding.vuln_name[..15])
        } else {
            finding.vuln_name.clone()
        };

        println!("│ {:<18} {:<6} {:<15} {:<4}    {:<20} │",
            target, finding.port, finding.vuln_id, severity_str, name);
    }

    println!("└────────────────────────────────────────────────────────────────────────────┘");
    println!();

    for finding in &result.findings {
        println!("  {}[{}] {} {}{} - {}:{}",
            finding.severity.color_code(),
            finding.severity.display_name(),
            finding.vuln_id,
            finding.vuln_name,
            "\x1b[0m",
            finding.target,
            finding.port);
        if !finding.description.is_empty() {
            println!("    {}", finding.description);
        }
        if !finding.evidence.is_empty() {
            let evidence: String = finding.evidence.chars().take(100).collect();
            println!("    证据: {}", evidence.replace('\n', " ").replace('\r', ""));
        }
        if !finding.remediation.is_empty() {
            println!("    修复: {}", finding.remediation);
        }
        println!();
    }
}

fn export_vuln_csv(result: &crate::vuln::VulnScanResult, path: &std::path::Path) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    wtr.write_record(&[
        "目标", "端口", "漏洞ID", "漏洞名称", "严重性", "类别",
        "描述", "证据", "修复建议",
    ])?;

    for finding in &result.findings {
        wtr.write_record(&[
            &finding.target,
            &finding.port.to_string(),
            &finding.vuln_id,
            &finding.vuln_name,
            finding.severity.display_name(),
            &finding.category,
            &finding.description,
            &finding.evidence,
            &finding.remediation,
        ])?;
    }

    wtr.flush()?;
    Ok(())
}
