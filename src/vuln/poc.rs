//! PoC 规则数据模型
//!
//! 定义 PoC 规则的 serde 反序列化结构体，支持 YAML 和 JSON 格式

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 漏洞严重性级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Severity {
    #[serde(rename = "critical")]
    Critical,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "info")]
    Info,
}

impl Severity {
    pub fn display_name(&self) -> &str {
        match self {
            Severity::Critical => "严重",
            Severity::High => "高危",
            Severity::Medium => "中危",
            Severity::Low => "低危",
            Severity::Info => "信息",
        }
    }

    pub fn color_code(&self) -> &str {
        match self {
            Severity::Critical => "\x1b[31m", // 红色
            Severity::High => "\x1b[33m",     // 黄色
            Severity::Medium => "\x1b[36m",   // 青色
            Severity::Low => "\x1b[32m",      // 绿色
            Severity::Info => "\x1b[37m",     // 白色
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" | "严重" => Some(Severity::Critical),
            "high" | "高危" => Some(Severity::High),
            "medium" | "中危" => Some(Severity::Medium),
            "low" | "低危" => Some(Severity::Low),
            "info" | "信息" => Some(Severity::Info),
            _ => None,
        }
    }
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Medium
    }
}

/// 传输协议类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Http,
    Tcp,
}

impl Default for Transport {
    fn default() -> Self {
        Transport::Http
    }
}

/// PoC 规则完整定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoCRule {
    pub id: String,
    pub info: PoCInfo,
    #[serde(default)]
    pub transport: Transport,
    #[serde(rename = "default-port", default)]
    pub default_port: Option<u16>,
    #[serde(default)]
    pub rules: Vec<PoCRequest>,
}

/// PoC 元信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoCInfo {
    pub name: String,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub remediation: String,
}

/// 单个请求规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoCRequest {
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(rename = "read-size", default)]
    pub read_size: Option<usize>,
    #[serde(rename = "matchers-condition", default = "default_matchers_condition")]
    pub matchers_condition: String,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_matchers_condition() -> String {
    "and".to_string()
}

/// 匹配器类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatcherType {
    Word,
    Regex,
    Status,
    Binary,
}

/// 匹配器定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub matcher_type: MatcherType,
    #[serde(default = "default_part")]
    pub part: String,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub binary: Vec<String>,
    #[serde(default)]
    pub negative: bool,
}

fn default_part() -> String {
    "body".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str_opt("critical"), Some(Severity::Critical));
        assert_eq!(Severity::from_str_opt("high"), Some(Severity::High));
        assert_eq!(Severity::from_str_opt("medium"), Some(Severity::Medium));
        assert_eq!(Severity::from_str_opt("unknown"), None);
    }

    #[test]
    fn test_deserialize_http_poc() {
        let yaml = r#"
id: test-poc
info:
  name: Test PoC
  severity: high
  category: test
transport: http
rules:
  - method: GET
    path: "/test"
    matchers:
      - type: word
        words:
          - "test_string"
"#;
        let poc: PoCRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(poc.id, "test-poc");
        assert_eq!(poc.info.severity, Severity::High);
        assert_eq!(poc.transport, Transport::Http);
        assert_eq!(poc.rules.len(), 1);
        assert_eq!(poc.rules[0].method, "GET");
        assert_eq!(poc.rules[0].matchers.len(), 1);
    }

    #[test]
    fn test_deserialize_tcp_poc() {
        let yaml = r#"
id: tcp-test
info:
  name: TCP Test
  severity: critical
transport: tcp
default-port: 6379
rules:
  - data: "PING\r\n"
    matchers:
      - type: word
        words:
          - "PONG"
"#;
        let poc: PoCRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(poc.transport, Transport::Tcp);
        assert_eq!(poc.default_port, Some(6379));
        assert_eq!(poc.rules[0].data, Some("PING\r\n".to_string()));
    }

    #[test]
    fn test_deserialize_json_poc() {
        let json = r#"{
            "id": "json-test",
            "info": {"name": "JSON Test", "severity": "low"},
            "transport": "http",
            "rules": [{"method": "POST", "path": "/api", "matchers": [{"type": "status", "status": [200]}]}]
        }"#;
        let poc: PoCRule = serde_json::from_str(json).unwrap();
        assert_eq!(poc.id, "json-test");
        assert_eq!(poc.info.severity, Severity::Low);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.display_name(), "严重");
        assert_eq!(Severity::High.display_name(), "高危");
        assert_eq!(Severity::Medium.display_name(), "中危");
    }
}
