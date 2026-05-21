//! 漏洞扫描模块
//!
//! 提供基于 PoC 规则的漏洞扫描引擎

pub mod builtin;
pub mod engine;
pub mod loader;
pub mod matchers;
pub mod poc;

use chrono::{DateTime, Utc};
use poc::{PoCRule, Severity, Transport};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// 漏洞扫描配置
pub struct VulnScanConfig {
    pub targets: Vec<String>,
    pub pocs: Vec<PoCRule>,
    pub timeout: Duration,
    pub concurrency: usize,
}

impl VulnScanConfig {
    pub fn new(targets: Vec<String>, pocs: Vec<PoCRule>) -> Self {
        Self {
            targets,
            pocs,
            timeout: Duration::from_secs(10),
            concurrency: 20,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }
}

/// 单条漏洞发现
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnResult {
    pub target: String,
    pub port: u16,
    pub vuln_id: String,
    pub vuln_name: String,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

/// 漏洞扫描聚合结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanResult {
    pub targets: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_secs: f64,
    pub findings: Vec<VulnResult>,
    pub stats: VulnScanStats,
}

/// 漏洞扫描统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanStats {
    pub total_targets: usize,
    pub total_pocs: usize,
    pub total_requests: usize,
    pub vulnerabilities_found: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

/// 漏洞扫描器
pub struct VulnScanner {
    config: VulnScanConfig,
}

impl VulnScanner {
    pub fn new(config: VulnScanConfig) -> Self {
        Self { config }
    }

    /// 运行漏洞扫描
    pub async fn scan(&self) -> VulnScanResult {
        let start_time = Utc::now();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));
        let mut tasks = Vec::new();

        let total_requests = self.config.targets.len() * self.config.pocs.len();

        for target in &self.config.targets {
            let (ip, default_port) = parse_target(target);
            for poc in &self.config.pocs {
                let sem = semaphore.clone();
                let ip = ip.clone();
                let default_port = default_port;
                let poc = poc.clone();
                let timeout = self.config.timeout;

                tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.ok()?;
                    execute_poc(&ip, default_port, &poc, timeout).await
                }));
            }
        }

        let mut findings = Vec::new();
        let mut completed = 0usize;
        let total = tasks.len();

        for task in tasks {
            if let Ok(Some(result)) = task.await {
                findings.push(result);
            }
            completed += 1;
            if completed % 50 == 0 || completed == total {
                tracing::debug!(
                    "漏洞扫描进度: {}/{} ({:.1}%)",
                    completed,
                    total,
                    completed as f64 / total as f64 * 100.0
                );
            }
        }

        let end_time = Utc::now();
        let duration = (end_time - start_time).num_milliseconds() as f64 / 1000.0;

        let stats = VulnScanStats {
            total_targets: self.config.targets.len(),
            total_pocs: self.config.pocs.len(),
            total_requests,
            vulnerabilities_found: findings.len(),
            critical_count: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            high_count: findings.iter().filter(|f| f.severity == Severity::High).count(),
            medium_count: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            low_count: findings.iter().filter(|f| f.severity == Severity::Low).count(),
            info_count: findings.iter().filter(|f| f.severity == Severity::Info).count(),
        };

        VulnScanResult {
            targets: self.config.targets.clone(),
            start_time,
            end_time,
            duration_secs: duration,
            findings,
            stats,
        }
    }

    /// 对已知的 IP:Port 列表运行指定类别的 PoC
    pub async fn scan_targets_with_ports(
        targets: Vec<(String, u16)>,
        pocs: Vec<PoCRule>,
        timeout: Duration,
        concurrency: usize,
    ) -> Vec<VulnResult> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut tasks = Vec::new();

        for (ip, port) in &targets {
            for poc in &pocs {
                let sem = semaphore.clone();
                let ip = ip.clone();
                let port = *port;
                let poc = poc.clone();

                tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.ok()?;
                    execute_poc(&ip, port, &poc, timeout).await
                }));
            }
        }

        let mut findings = Vec::new();
        for task in tasks {
            if let Ok(Some(result)) = task.await {
                findings.push(result);
            }
        }
        findings
    }
}

/// 解析目标地址
fn parse_target(target: &str) -> (String, u16) {
    // 处理 IPv6 (含方括号)
    if target.starts_with('[') {
        if let Some(bracket_end) = target.find(']') {
            let ip = target[1..bracket_end].to_string();
            if target.len() > bracket_end + 1 && &target[bracket_end + 1..bracket_end + 2] == ":" {
                if let Ok(port) = target[bracket_end + 2..].parse::<u16>() {
                    return (ip, port);
                }
            }
            return (ip, 0);
        }
    }

    // IPv4:port 或 hostname:port
    if let Some(idx) = target.rfind(':') {
        if let Ok(port) = target[idx + 1..].parse::<u16>() {
            return (target[..idx].to_string(), port);
        }
    }

    (target.to_string(), 0)
}

/// 执行单个 PoC 检测
async fn execute_poc(
    target: &str,
    port: u16,
    poc: &PoCRule,
    timeout: Duration,
) -> Option<VulnResult> {
    for request in &poc.rules {
        let actual_port = if port > 0 {
            port
        } else {
            poc.default_port.unwrap_or(80)
        };

        let matched = match poc.transport {
            Transport::Http => {
                match engine::execute_http_request(target, actual_port, request, timeout).await {
                    Ok(ctx) => {
                        let matched = matchers::match_http_response(
                            &request.matchers,
                            &request.matchers_condition,
                            &ctx,
                        );
                        if matched {
                            let evidence = extract_http_evidence(&ctx.body, &ctx.headers);
                            return Some(VulnResult {
                                target: target.to_string(),
                                port: actual_port,
                                vuln_id: poc.id.clone(),
                                vuln_name: poc.info.name.clone(),
                                severity: poc.info.severity,
                                category: poc.info.category.clone(),
                                description: poc.info.description.clone(),
                                evidence,
                                remediation: poc.info.remediation.clone(),
                            });
                        }
                        matched
                    }
                    Err(_) => false,
                }
            }
            Transport::Tcp => {
                match engine::execute_tcp_request(target, actual_port, request, timeout).await {
                    Ok(ctx) => {
                        let matched = matchers::match_tcp_response(
                            &request.matchers,
                            &request.matchers_condition,
                            &ctx.data,
                        );
                        if matched {
                            let evidence: String =
                                String::from_utf8_lossy(&ctx.data).chars().take(200).collect();
                            return Some(VulnResult {
                                target: target.to_string(),
                                port: actual_port,
                                vuln_id: poc.id.clone(),
                                vuln_name: poc.info.name.clone(),
                                severity: poc.info.severity,
                                category: poc.info.category.clone(),
                                description: poc.info.description.clone(),
                                evidence,
                                remediation: poc.info.remediation.clone(),
                            });
                        }
                        matched
                    }
                    Err(_) => false,
                }
            }
        };

        if !matched {
            return None;
        }
    }
    None
}

fn extract_http_evidence(body: &str, _headers: &str) -> String {
    body.chars().take(200).collect()
}

/// 解析 CIDR/范围/单个IP 为目标列表
pub fn expand_targets(targets: &[String]) -> Vec<String> {
    let mut expanded = Vec::new();

    for target in targets {
        // CIDR
        if target.contains('/') {
            if let Ok(network) = target.parse::<ipnet::Ipv4Net>() {
                for ip in network.hosts() {
                    expanded.push(ip.to_string());
                }
                continue;
            }
        }

        // IP 范围 (192.168.1.1-192.168.1.254)
        if target.contains('-') && !target.contains(':') {
            let parts: Vec<&str> = target.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (parts[0].parse(), parts[1].parse()) {
                    let start_num = u32::from(start);
                    let end_num = u32::from(end);
                    for num in start_num..=end_num {
                        expanded.push(std::net::Ipv4Addr::from(num).to_string());
                    }
                    continue;
                }
            }
        }

        // 单个 IP 或 host:port
        expanded.push(target.clone());
    }

    expanded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_ip_port() {
        let (ip, port) = parse_target("192.168.1.1:8080");
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_target_ip_only() {
        let (ip, port) = parse_target("192.168.1.1");
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_parse_target_ipv6() {
        let (ip, port) = parse_target("[::1]:8080");
        assert_eq!(ip, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_expand_targets_single_ip() {
        let targets = vec!["192.168.1.1".to_string()];
        let expanded = expand_targets(&targets);
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0], "192.168.1.1");
    }

    #[test]
    fn test_expand_targets_cidr() {
        let targets = vec!["192.168.1.0/30".to_string()];
        let expanded = expand_targets(&targets);
        assert_eq!(expanded.len(), 2); // .1 and .2
    }

    #[test]
    fn test_expand_targets_range() {
        let targets = vec!["192.168.1.1-192.168.1.3".to_string()];
        let expanded = expand_targets(&targets);
        assert_eq!(expanded.len(), 3);
        assert_eq!(expanded[0], "192.168.1.1");
        assert_eq!(expanded[2], "192.168.1.3");
    }

    #[test]
    fn test_vuln_scan_config_builder() {
        let config = VulnScanConfig::new(vec!["127.0.0.1".to_string()], vec![])
            .with_timeout(Duration::from_secs(5))
            .with_concurrency(10);

        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.concurrency, 10);
    }
}
