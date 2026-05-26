//! AD 域深度枚举 CLI

use crate::core::error::FlyWheelError;
use crate::core::Result;
use crate::output::color::{print_info, print_success};
use crate::output::format::OutputFormat;
use std::path::PathBuf;

pub fn run_ad_cmd(
    dc: String,
    domain: String,
    username: Option<String>,
    password: Option<String>,
    ssl: bool,
    mode: String,
    bloodhound_dir: Option<PathBuf>,
    format: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    let output_fmt = OutputFormat::from_str(format)
        .unwrap_or(OutputFormat::Json);
    let ad_label = "AD域枚举";
    print_info(&format!("开始{}...", ad_label));

    let mut config = crate::ad::ldap::LdapConfig::new(&dc, &domain).use_ssl(ssl);
    if let (Some(user), Some(pass)) = (&username, &password) {
        config = config.with_credentials(user, pass);
    }

    let rt = tokio::runtime::Runtime::new()?;
    let ad_err = |e: String| -> FlyWheelError { FlyWheelError::Other { message: e } };

    let result = match mode.as_str() {
        "kerberoast" => {
            let enumerator = crate::ad::ldap::AdEnumerator::new(config);
            let targets = rt.block_on(enumerator.kerberoast()).map_err(ad_err)?;
            print_kerberoast_results(&targets);
            save_ad_result(&output_fmt, &output, &serde_json::to_value(&targets)?)?;
            return Ok(());
        }
        "asrep-roast" => {
            let enumerator = crate::ad::ldap::AdEnumerator::new(config);
            let targets = rt.block_on(enumerator.asrep_roast()).map_err(ad_err)?;
            print_asrep_results(&targets);
            save_ad_result(&output_fmt, &output, &serde_json::to_value(&targets)?)?;
            return Ok(());
        }
        "bloodhound" => {
            let enumerator = crate::ad::ldap::AdEnumerator::new(config);
            let result = rt.block_on(enumerator.enumerate_all()).map_err(ad_err)?;
            let bh_dir = bloodhound_dir.unwrap_or_else(|| std::path::PathBuf::from("bloodhound_output"));
            crate::ad::bloodhound::export_bloodhound(&result, &bh_dir)?;
            print_success(&format!("BloodHound 数据已导出到: {}", bh_dir.display()));
            return Ok(());
        }
        _ => {
            let enumerator = crate::ad::ldap::AdEnumerator::new(config);
            let result = rt.block_on(enumerator.enumerate_all()).map_err(ad_err)?;
            print_ad_enum_results(&result);
            result
        }
    };

    save_ad_result(&output_fmt, &output, &serde_json::to_value(&result)?)?;
    Ok(())
}

fn save_ad_result(
    fmt: &OutputFormat,
    output: &Option<PathBuf>,
    data: &serde_json::Value,
) -> Result<()> {
    if let Some(path) = output {
        let content = match fmt {
            OutputFormat::Json => serde_json::to_string_pretty(data)?,
            OutputFormat::Csv => serde_json::to_string_pretty(data)?,
        };
        std::fs::write(path, content)?;
        print_success(&format!("结果已保存到: {}", path.display()));
    }
    Ok(())
}

fn print_ad_enum_results(result: &crate::ad::AdEnumResult) {
    println!("\n{}", "═".repeat(70));
    println!("║  AD 域枚举结果");
    println!("║  域名: {:<58}║", result.domain_name);
    if let Some(ref dc) = result.domain_controller {
        println!("║  域控: {:<58}║", dc);
    }
    println!("║  耗时: {:.2}s{:<51}║", result.duration_secs, "");
    println!("╠{}", "═".repeat(69));

    println!("║  用户: {}  组: {}  计算机: {}", result.users.len(), result.groups.len(), result.computers.len());
    println!("║  Kerberoast目标: {}  AS-REP目标: {}", result.kerberoast_targets.len(), result.asrep_targets.len());
    println!("║  信任关系: {}  GPO: {}", result.trusts.len(), result.gpos.len());

    let admin_count = result.users.iter().filter(|u| u.admin_count).count();
    let da_count = result.users.iter().filter(|u| u.member_of.iter().any(|m| m.contains("Domain Admins"))).count();
    println!("║  管理员账户: {}  Domain Admins: {}", admin_count, da_count);

    println!("╠{}", "═".repeat(69));

    if !result.kerberoast_targets.is_empty() {
        println!("║  Kerberoast 目标:");
        for t in result.kerberoast_targets.iter().take(10) {
            let status = if t.enabled { "启用" } else { "禁用" };
            println!("║    {} ({}) SPN: {} [{}]", t.username, status, t.spn, t.service_type);
        }
        if result.kerberoast_targets.len() > 10 {
            println!("║    ... 还有 {} 个目标", result.kerberoast_targets.len() - 10);
        }
    }

    if !result.asrep_targets.is_empty() {
        println!("║  AS-REP Roast 目标:");
        for t in &result.asrep_targets {
            let status = if t.enabled { "启用" } else { "禁用" };
            println!("║    {} ({})", t.username, status);
        }
    }

    println!("{}{}\n", "╚", "═".repeat(69));
}

fn print_kerberoast_results(targets: &[crate::ad::KerberoastTarget]) {
    println!("\n{}", "═".repeat(70));
    println!("║  Kerberoast 目标 (共 {} 个)", targets.len());
    println!("╠{}", "═".repeat(69));
    for t in targets.iter().take(20) {
        let status = if t.enabled { "启用" } else { "禁用" };
        let admin = if t.admin_count { " [管理员]" } else { "" };
        println!("║  {} | {} | {} ({}){}", t.username, t.spn, t.service_type, status, admin);
    }
    if targets.len() > 20 {
        println!("║  ... 还有 {} 个目标", targets.len() - 20);
    }
    println!("{}{}\n", "╚", "═".repeat(69));
}

fn print_asrep_results(targets: &[crate::ad::AsrepTarget]) {
    println!("\n{}", "═".repeat(70));
    println!("║  AS-REP Roast 目标 (共 {} 个)", targets.len());
    println!("╠{}", "═".repeat(69));
    for t in targets {
        let status = if t.enabled { "启用" } else { "禁用" };
        println!("║  {} ({})", t.username, status);
    }
    println!("{}{}\n", "╚", "═".repeat(69));
}
