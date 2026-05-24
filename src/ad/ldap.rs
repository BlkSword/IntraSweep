//! LDAP 查询引擎
//!
//! 通过 ldap3 crate 连接域控执行 LDAP 查询

use crate::ad::{
    AdComputer, AdEnumResult, AdEnumStats, AdGroup, AdTrust, AdUser, AsrepTarget, KerberoastTarget,
};
use std::time::Duration;

/// LDAP 连接配置
#[derive(Clone)]
pub struct LdapConfig {
    pub domain_controller: String,
    pub port: u16,
    pub use_ssl: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub domain: String,
    pub timeout: Duration,
}

impl LdapConfig {
    pub fn new(dc: &str, domain: &str) -> Self {
        Self {
            domain_controller: dc.to_string(),
            port: 389,
            use_ssl: false,
            username: None,
            password: None,
            domain: domain.to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_credentials(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self
    }

    pub fn use_ssl(mut self, ssl: bool) -> Self {
        self.port = if ssl { 636 } else { 389 };
        self.use_ssl = ssl;
        self
    }
}

/// AD 深度枚举器
pub struct AdEnumerator {
    config: LdapConfig,
}

impl AdEnumerator {
    pub fn new(config: LdapConfig) -> Self {
        Self { config }
    }

    /// 执行完整 AD 枚举
    pub async fn enumerate_all(&self) -> Result<AdEnumResult, String> {
        // 在独立线程中执行同步 LDAP 操作
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || enumerate_all_sync(&config))
            .await
            .map_err(|e| format!("任务执行失败: {}", e))?
    }

    /// 仅执行 Kerberoasting
    pub async fn kerberoast(&self) -> Result<Vec<KerberoastTarget>, String> {
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || {
            let mut ldap = connect(&config)?;
            let base_dn = domain_to_dn(&config.domain);
            query_kerberoast_targets(&mut ldap, &base_dn)
        })
        .await
        .map_err(|e| format!("任务执行失败: {}", e))?
    }

    /// 仅执行 AS-REP Roasting
    pub async fn asrep_roast(&self) -> Result<Vec<AsrepTarget>, String> {
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || {
            let mut ldap = connect(&config)?;
            let base_dn = domain_to_dn(&config.domain);
            query_asrep_targets(&mut ldap, &base_dn)
        })
        .await
        .map_err(|e| format!("任务执行失败: {}", e))?
    }
}

fn ldap_url(config: &LdapConfig) -> String {
    let scheme = if config.use_ssl { "ldaps" } else { "ldap" };
    format!("{}://{}:{}", scheme, config.domain_controller, config.port)
}

fn connect(config: &LdapConfig) -> Result<ldap3::LdapConn, String> {
    ldap3::LdapConn::new(&ldap_url(config)).map_err(|e| format!("LDAP连接失败: {}", e))
}

fn bind(ldap: &mut ldap3::LdapConn, config: &LdapConfig) -> Result<(), String> {
    match (&config.username, &config.password) {
        (Some(user), Some(pass)) => {
            let bind_dn = if user.contains('=') {
                user.clone()
            } else {
                format!("{}@{}", user, config.domain)
            };
            ldap.simple_bind(&bind_dn, pass)
                .map_err(|e| format!("LDAP认证失败: {}", e))?;
        }
        _ => {
            ldap.simple_bind("", "")
                .map_err(|e| format!("LDAP匿名绑定失败: {}", e))?;
        }
    }
    Ok(())
}

/// 同步执行完整枚举
fn enumerate_all_sync(config: &LdapConfig) -> Result<AdEnumResult, String> {
    let start_time = chrono::Utc::now();
    let mut result = AdEnumResult {
        domain_name: config.domain.clone(),
        domain_controller: Some(config.domain_controller.clone()),
        start_time,
        end_time: start_time,
        ..Default::default()
    };

    let mut ldap = connect(config)?;
    bind(&mut ldap, config)?;

    let base_dn = domain_to_dn(&config.domain);
    tracing::info!("LDAP基础DN: {}", base_dn);

    result.users = query_users(&mut ldap, &base_dn).unwrap_or_default();
    result.groups = query_groups(&mut ldap, &base_dn).unwrap_or_default();
    result.computers = query_computers(&mut ldap, &base_dn).unwrap_or_default();
    result.kerberoast_targets = query_kerberoast_targets(&mut ldap, &base_dn).unwrap_or_default();
    result.asrep_targets = query_asrep_targets(&mut ldap, &base_dn).unwrap_or_default();
    result.trusts = query_trusts(&mut ldap, &base_dn).unwrap_or_default();
    result.gpos = query_gpos(&mut ldap, &base_dn).unwrap_or_default();

    let _ = ldap.unbind();

    let end_time = chrono::Utc::now();
    result.end_time = end_time;
    result.duration_secs = (end_time - start_time).num_milliseconds() as f64 / 1000.0;

    result.stats = AdEnumStats {
        users_found: result.users.len(),
        groups_found: result.groups.len(),
        computers_found: result.computers.len(),
        kerberoast_targets: result.kerberoast_targets.len(),
        asrep_targets: result.asrep_targets.len(),
        gpos_found: result.gpos.len(),
        trusts_found: result.trusts.len(),
        admin_accounts: result.users.iter().filter(|u| u.admin_count).count(),
        da_accounts: result.users.iter().filter(|u| u.member_of.iter().any(|m| m.contains("Domain Admins"))).count(),
    };

    Ok(result)
}

fn search_attrs(
    ldap: &mut ldap3::LdapConn,
    base_dn: &str,
    filter: &str,
    attrs: &[&str],
) -> Result<Vec<ldap3::SearchEntry>, String> {
    let sr = ldap
        .search(base_dn, ldap3::Scope::Subtree, filter, attrs)
        .map_err(|e| format!("LDAP查询失败: {}", e))?;
    Ok(sr.0.into_iter().map(ldap3::SearchEntry::construct).collect())
}

fn get_attr(entry: &ldap3::SearchEntry, name: &str) -> Option<String> {
    entry.attrs.get(name).and_then(|v| v.first().cloned()).filter(|v| !v.is_empty())
}

fn get_attr_multi(entry: &ldap3::SearchEntry, name: &str) -> Vec<String> {
    entry.attrs.get(name).cloned().unwrap_or_default()
}

fn query_users(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<AdUser>, String> {
    let rs = search_attrs(ldap, base_dn,
        "(&(objectClass=user)(objectCategory=person))",
        &["sAMAccountName","displayName","distinguishedName","description","mail","adminCount",
          "userAccountControl","memberOf","servicePrincipalName"])?;

    Ok(rs.iter().map(|entry| {
        let uac: u32 = get_attr(entry, "userAccountControl").and_then(|v| v.parse().ok()).unwrap_or(512);
        AdUser {
            sam_account_name: get_attr(entry, "sAMAccountName").unwrap_or_default(),
            display_name: get_attr(entry, "displayName"),
            dn: get_attr(entry, "distinguishedName").unwrap_or_default(),
            description: get_attr(entry, "description"),
            email: get_attr(entry, "mail"),
            admin_count: get_attr(entry, "adminCount").is_some(),
            enabled: uac & 2 == 0,
            password_expired: uac & 0x800000 != 0,
            last_logon: None,
            member_of: get_attr_multi(entry, "memberOf"),
            spn: get_attr_multi(entry, "servicePrincipalName"),
            sid: None,
        }
    }).collect())
}

fn query_groups(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<AdGroup>, String> {
    let rs = search_attrs(ldap, base_dn, "(objectClass=group)",
        &["cn","distinguishedName","description","member","adminCount"])?;

    Ok(rs.iter().map(|entry| AdGroup {
        name: get_attr(entry, "cn").unwrap_or_default(),
        dn: get_attr(entry, "distinguishedName").unwrap_or_default(),
        description: get_attr(entry, "description"),
        members: get_attr_multi(entry, "member"),
        admin_count: get_attr(entry, "adminCount").is_some(),
    }).collect())
}

fn query_computers(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<AdComputer>, String> {
    let rs = search_attrs(ldap, base_dn, "(objectClass=computer)",
        &["cn","distinguishedName","dNSHostName","operatingSystem","operatingSystemVersion","userAccountControl"])?;

    Ok(rs.iter().map(|entry| {
        let uac: u32 = get_attr(entry, "userAccountControl").and_then(|v| v.parse().ok()).unwrap_or(4096);
        AdComputer {
            name: get_attr(entry, "cn").unwrap_or_default(),
            dn: get_attr(entry, "distinguishedName").unwrap_or_default(),
            dns_hostname: get_attr(entry, "dNSHostName"),
            os: get_attr(entry, "operatingSystem"),
            os_version: get_attr(entry, "operatingSystemVersion"),
            enabled: uac & 2 == 0,
            last_logon: None,
        }
    }).collect())
}

fn query_kerberoast_targets(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<KerberoastTarget>, String> {
    let rs = search_attrs(ldap, base_dn,
        "(&(servicePrincipalName=*)(objectClass=user)(!(objectClass=computer)))",
        &["sAMAccountName","distinguishedName","servicePrincipalName","adminCount",
          "userAccountControl","description"])?;

    let mut targets = Vec::new();
    for entry in &rs {
        let username = get_attr(entry, "sAMAccountName").unwrap_or_default();
        let dn = get_attr(entry, "distinguishedName").unwrap_or_default();
        let spns = get_attr_multi(entry, "servicePrincipalName");
        let admin_count = get_attr(entry, "adminCount").is_some();
        let uac: u32 = get_attr(entry, "userAccountControl").and_then(|v| v.parse().ok()).unwrap_or(0);
        let enabled = uac & 2 == 0;
        let description = get_attr(entry, "description");

        for spn in spns {
            let service_type = spn.split('/').next().unwrap_or("").to_string();
            targets.push(KerberoastTarget {
                username: username.clone(),
                dn: dn.clone(),
                spn,
                service_type,
                admin_count,
                enabled,
                description: description.clone(),
            });
        }
    }

    Ok(targets)
}

fn query_asrep_targets(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<AsrepTarget>, String> {
    let rs = search_attrs(ldap, base_dn,
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        &["sAMAccountName","distinguishedName","userAccountControl","description"])?;

    Ok(rs.iter().map(|entry| {
        let uac: u32 = get_attr(entry, "userAccountControl").and_then(|v| v.parse().ok()).unwrap_or(0);
        AsrepTarget {
            username: get_attr(entry, "sAMAccountName").unwrap_or_default(),
            dn: get_attr(entry, "distinguishedName").unwrap_or_default(),
            enabled: uac & 2 == 0,
            description: get_attr(entry, "description"),
        }
    }).collect())
}

fn query_trusts(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<AdTrust>, String> {
    let rs = search_attrs(ldap, &format!("CN=System,{}", base_dn),
        "(objectClass=trustedDomain)",
        &["cn","trustType","trustDirection","trustAttributes"])?;

    Ok(rs.iter().map(|entry| {
        AdTrust {
            domain: get_attr(entry, "cn").unwrap_or_default(),
            trust_type: get_attr(entry, "trustType").map(|v| match v.as_str() {
                "1" => "Windows NT".to_string(),
                "2" => "Windows 2000".to_string(),
                "3" => "Kerberos".to_string(),
                _ => v,
            }).unwrap_or_else(|| "未知".to_string()),
            trust_direction: get_attr(entry, "trustDirection").map(|v| match v.as_str() {
                "0" => "禁用".to_string(),
                "1" => "入站".to_string(),
                "2" => "出站".to_string(),
                "3" => "双向".to_string(),
                _ => v,
            }).unwrap_or_else(|| "未知".to_string()),
            trust_attributes: get_attr(entry, "trustAttributes").map(|v| match v.as_str() {
                "1" => "非传递".to_string(),
                "2" => "上级".to_string(),
                "4" => "可传递".to_string(),
                _ => v,
            }).unwrap_or_else(|| "未知".to_string()),
        }
    }).collect())
}

fn query_gpos(ldap: &mut ldap3::LdapConn, base_dn: &str) -> Result<Vec<String>, String> {
    let rs = search_attrs(ldap, base_dn, "(objectClass=groupPolicyContainer)",
        &["cn","displayName"])?;

    Ok(rs.iter().map(|entry| {
        get_attr(entry, "displayName").unwrap_or_else(|| get_attr(entry, "cn").unwrap_or_default())
    }).collect())
}

/// 域名转 DN 格式 (corp.local → DC=corp,DC=local)
pub fn domain_to_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_to_dn() {
        assert_eq!(domain_to_dn("corp.local"), "DC=corp,DC=local");
        assert_eq!(domain_to_dn("sub.corp.local"), "DC=sub,DC=corp,DC=local");
    }

    #[test]
    fn test_ldap_config_builder() {
        let config = LdapConfig::new("10.0.0.1", "corp.local")
            .with_credentials("admin", "password")
            .use_ssl(true);
        assert_eq!(config.port, 636);
        assert!(config.use_ssl);
    }
}
