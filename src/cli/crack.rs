//! 爆破 CLI
//!
//! 处理密码爆破子命令的交互式配置向导和直接模式

use crate::cli::{colorize, print_banner, InteractiveMenu};
use crate::core::error::FlyWheelError;
use crate::core::Result;
use crate::cracker::service::Cracker;
use crate::cracker::{CrackConfig, CrackService, DictManager};
use crate::output::color::{print_error, print_info, print_success, Color};

/// 爆破命令入口
pub fn run_crack_cmd(
    target: Option<String>,
    port: Option<u16>,
    service: Option<String>,
    usernames: Option<String>,
    password_file: Option<String>,
    username_file: Option<String>,
    concurrency: usize,
    timeout: u64,
    delay: Option<u64>,
) -> Result<()> {
    if target.is_none() {
        run_interactive_crack(
            port,
            service,
            usernames,
            password_file,
            username_file,
            concurrency,
            timeout,
            delay,
        )
    } else {
        run_crack(
            target.unwrap(),
            port,
            service,
            usernames,
            password_file,
            username_file,
            concurrency,
            timeout,
            delay,
        )
    }
}

/// 运行交互式爆破向导
fn run_interactive_crack(
    initial_port: Option<u16>,
    initial_service: Option<String>,
    _initial_usernames: Option<String>,
    initial_password_file: Option<String>,
    _initial_username_file: Option<String>,
    initial_concurrency: usize,
    initial_timeout: u64,
    initial_delay: Option<u64>,
) -> Result<()> {
    print_banner();
    println!();
    print_info(&format!("IntraSweep 交互式{}配置向导", crate::core::obfstr::sensitive::crack_label()));
    println!();

    // 步骤 1: 目标主机
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [1/7] 目标主机");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("输入格式示例:");
    println!("  IP地址:       192.168.1.1");
    println!("  域名:         example.com");
    println!();

    let target = loop {
        let input = InteractiveMenu::read_input("请输入目标主机: ");
        if !input.is_empty() {
            break input;
        }
        print_error("目标不能为空，请重新输入");
    };
    println!();
    print_success(&format!("已设置目标: {}", target));
    println!();

    // 步骤 2: 服务类型
    let service = if let Some(s) = &initial_service {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [2/7] 服务类型");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("已指定: {}", s);
        println!();
        s.clone()
    } else {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [2/7] 服务类型");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("  1. SSH       - SSH 爆破 (默认端口: 22)");
        println!("  2. RDP       - RDP 爆破 (默认端口: 3389)");
        println!("  3. Redis     - Redis 爆破 (默认端口: 6379)");
        println!("  4. Postgres  - PostgreSQL 爆破 (默认端口: 5432)");
        println!("  5. MongoDB   - MongoDB 爆破 (默认端口: 27017)");
        println!("  6. MSSQL     - MSSQL 爆破 (默认端口: 1433)");
        println!("  7. MySQL     - MySQL 爆破 (默认端口: 3306)");
        println!("  8. WinRM     - WinRM 爆破 (默认端口: 5985)");
        println!();

        let choice = InteractiveMenu::read_number("请选择服务类型 [1-8]: ", 1, 8);
        let service = match choice {
            1 => "ssh".to_string(),
            2 => "rdp".to_string(),
            3 => "redis".to_string(),
            4 => "postgres".to_string(),
            5 => "mongodb".to_string(),
            6 => "mssql".to_string(),
            7 => "mysql".to_string(),
            8 => "winrm".to_string(),
            _ => "ssh".to_string(),
        };
        println!();
        print_success(&format!("已选择: {}", service.to_uppercase()));
        println!();
        service
    };

    // 解析服务类型
    let service_type = match service.to_lowercase().as_str() {
        "ssh" => CrackService::Ssh,
        "rdp" => CrackService::Rdp,
        "redis" => CrackService::Redis,
        "postgres" | "postgresql" => CrackService::Postgres,
        "mongodb" | "mongo" => CrackService::Mongodb,
        "mssql" => CrackService::Mssql,
        "mysql" => CrackService::Mysql,
        "winrm" => CrackService::Winrm,
        _ => CrackService::Ssh,
    };

    // 步骤 3: 端口
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [3/7] 端口");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let default_port = service_type.default_port();
    println!("默认端口: {}", default_port);
    println!();

    let port = if let Some(p) = initial_port {
        println!("已指定端口: {}", p);
        println!();
        p
    } else {
        let port_input =
            InteractiveMenu::read_input(&format!("按 Enter 使用默认端口或输入自定义端口: "));
        println!();
        if port_input.is_empty() {
            print_success(&format!("使用默认端口: {}", default_port));
            println!();
            default_port
        } else {
            let p = port_input.parse::<u16>().unwrap_or(default_port);
            print_success(&format!("已设置端口: {}", p));
            println!();
            p
        }
    };

    // 步骤 4: 用户名配置
    let usernames = if service_type.requires_username() {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [4/7] 用户名配置");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("  1. 手动输入用户名 (逗号分隔)");
        println!("  2. 从文件加载用户名字典");
        println!("  3. 使用默认用户名列表");
        println!();

        let choice = InteractiveMenu::read_number("请选择 [1-3]: ", 1, 3);
        println!();

        match choice {
            1 => {
                let input = InteractiveMenu::read_input("请输入用户名 (多个用逗号分隔): ");
                println!();
                print_success("已设置用户名");
                println!();
                Some(input)
            }
            2 => {
                loop {
                    let file = InteractiveMenu::read_input("请输入用户名字典文件路径: ");
                    println!();

                    // 验证字典文件
                    match DictManager::validate_dict_file(&file) {
                        Ok(count) => {
                            print_success(&format!("字典文件验证通过 (包含 {} 个用户名)", count));
                            println!();
                            break Some(format!("@{}", file));
                        }
                        Err(e) => {
                            print_error(&format!("字典文件验证失败: {}", e));
                            println!();
                            let retry = InteractiveMenu::read_input("是否重新输入? [Y/n]: ");
                            if retry.to_lowercase() == "n" {
                                println!();
                                print_info("将使用默认用户名列表");
                                println!();
                                break None;
                            }
                            println!();
                        }
                    }
                }
            }
            3 => {
                println!();
                print_info("将使用默认用户名列表");
                println!();
                None
            }
            _ => None,
        }
    } else {
        None
    };

    // 步骤 5: 密码字典
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [5/7] 密码字典");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let password_file = if initial_password_file.is_some() {
        println!("已指定密码字典文件");
        println!();
        initial_password_file
    } else {
        println!("  1. 从文件加载密码字典");
        println!("  2. 使用默认密码字典");
        println!();

        let choice = InteractiveMenu::read_number("请选择 [1-2]: ", 1, 2);
        println!();

        match choice {
            1 => {
                loop {
                    let file = InteractiveMenu::read_input("请输入密码字典文件路径: ");
                    println!();

                    // 验证字典文件
                    match DictManager::validate_dict_file(&file) {
                        Ok(count) => {
                            print_success(&format!("字典文件验证通过 (包含 {} 个密码)", count));
                            println!();
                            break Some(file);
                        }
                        Err(e) => {
                            print_error(&format!("字典文件验证失败: {}", e));
                            println!();
                            let retry = InteractiveMenu::read_input("是否重新输入? [Y/n]: ");
                            if retry.to_lowercase() == "n" {
                                println!();
                                print_info("将使用默认密码字典");
                                println!();
                                break None;
                            }
                            println!();
                        }
                    }
                }
            }
            2 => {
                println!();
                print_info("将使用默认密码字典");
                println!();
                None
            }
            _ => None,
        }
    };

    // 步骤 6: 性能配置
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [6/7] 性能配置");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let concurrency = if initial_concurrency == 10 {
        let input = InteractiveMenu::read_input(&format!("并发数 (默认: 10): "));
        println!();
        if input.is_empty() {
            10
        } else {
            let c = input.parse::<usize>().unwrap_or(10);
            print_success(&format!("已设置并发数: {}", c));
            println!();
            c
        }
    } else {
        println!("已指定并发数: {}", initial_concurrency);
        println!();
        initial_concurrency
    };

    let timeout = if initial_timeout == 5 {
        let input = InteractiveMenu::read_input(&format!("超时时间/秒 (默认: 5): "));
        println!();
        if input.is_empty() {
            5
        } else {
            let t = input.parse::<u64>().unwrap_or(5);
            print_success(&format!("已设置超时: {} 秒", t));
            println!();
            t
        }
    } else {
        println!("已指定超时: {} 秒", initial_timeout);
        println!();
        initial_timeout
    };

    // 步骤 7: 高级选项
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [7/7] 高级选项");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let delay = if initial_delay.is_some() {
        println!("已指定延迟");
        println!();
        initial_delay
    } else {
        let input = InteractiveMenu::read_input("设置延迟/毫秒，可选 (按 Enter 跳过): ");
        println!();
        if input.is_empty() {
            print_info("未设置延迟");
            println!();
            None
        } else {
            let d = input.parse::<u64>().ok();
            if let Some(delay_val) = d {
                print_success(&format!("已设置延迟: {} 毫秒", delay_val));
            } else {
                print_info("输入无效，未设置延迟");
            }
            println!();
            d
        }
    };

    // 调用 run_crack 执行爆破
    run_crack(
        target,
        Some(port),
        Some(service),
        usernames,
        password_file,
        None, // username_file 从 usernames 参数解析
        concurrency,
        timeout,
        delay,
    )
}

/// 运行爆破
fn run_crack(
    target: String,
    port: Option<u16>,
    service: Option<String>,
    usernames: Option<String>,
    password_file: Option<String>,
    username_file: Option<String>,
    concurrency: usize,
    timeout: u64,
    delay: Option<u64>,
) -> Result<()> {
    use std::time::Duration;

    // 显示 Banner
    print_banner();
    println!();

    // 解析服务类型
    let service_type = if let Some(s) = service {
        match s.to_lowercase().as_str() {
            "ssh" => CrackService::Ssh,
            "rdp" => CrackService::Rdp,
            "redis" => CrackService::Redis,
            "postgres" | "postgresql" => CrackService::Postgres,
            "mongodb" | "mongo" => CrackService::Mongodb,
            "mssql" => CrackService::Mssql,
            "mysql" => CrackService::Mysql,
            "winrm" => CrackService::Winrm,
            _ => {
                print_error(&format!("不支持的服务类型: {}", s));
                println!("支持的服务: ssh, rdp, redis, postgres, mongodb, mssql, mysql, winrm");
                return Ok(());
            }
        }
    } else {
        // 如果没有指定服务，交互式选择
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  选择服务类型");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("  1. SSH       - SSH 爆破 (22)");
        println!("  2. RDP       - RDP 爆破 (3389)");
        println!("  3. Redis     - Redis 爆破 (6379)");
        println!("  4. Postgres  - PostgreSQL 爆破 (5432)");
        println!("  5. MongoDB   - MongoDB 爆破 (27017)");
        println!("  6. MSSQL     - MSSQL 爆破 (1433)");
        println!("  7. MySQL     - MySQL 爆破 (3306)");
        println!("  8. WinRM     - WinRM 爆破 (5985)");
        println!();

        let choice = InteractiveMenu::read_number("请选择服务类型 [1-8]: ", 1, 8);
        match choice {
            1 => CrackService::Ssh,
            2 => CrackService::Rdp,
            3 => CrackService::Redis,
            4 => CrackService::Postgres,
            5 => CrackService::Mongodb,
            6 => CrackService::Mssql,
            7 => CrackService::Mysql,
            8 => CrackService::Winrm,
            _ => CrackService::Ssh,
        }
    };

    // 创建配置
    let mut config = CrackConfig::new(target.clone(), service_type);

    // 设置端口
    if let Some(p) = port {
        config = config.with_port(p);
    }

    // 初始化字典管理器
    let mut dict_manager = DictManager::new();

    // 加载用户名
    if service_type.requires_username() {
        if let Some(username_file) = username_file {
            match dict_manager.load_usernames_from_file(&username_file) {
                Ok(count) => {
                    println!();
                    print_success(&format!("已加载 {} 个用户名", count));
                }
                Err(e) => {
                    print_error(&format!("加载用户名字典失败: {}", e));
                    return Err(FlyWheelError::Other {
                        message: "加载用户名字典失败".to_string(),
                    });
                }
            }
        } else if let Some(usernames_str) = usernames {
            let username_list: Vec<String> = usernames_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            dict_manager.set_usernames(username_list);
            println!();
            print_success(&format!(
                "已设置 {} 个用户名",
                dict_manager.username_count()
            ));
        }
    }

    // 加载密码
    if let Some(pwd_file) = password_file {
        match dict_manager.load_passwords_from_file(&pwd_file) {
            Ok(count) => {
                print_success(&format!("已加载 {} 个密码", count));
            }
            Err(e) => {
                print_error(&format!("加载密码字典失败: {}", e));
                return Err(FlyWheelError::Other {
                    message: "加载密码字典失败".to_string(),
                });
            }
        }
    } else {
        println!();
        print_info(&format!(
            "使用默认密码字典 ({} 个密码)",
            dict_manager.password_count()
        ));
    }

    // 设置用户名和密码
    config = config.with_usernames(dict_manager.usernames().to_vec());
    config = config.with_passwords(dict_manager.passwords().to_vec());
    config = config.with_concurrency(concurrency);
    config = config.with_timeout(Duration::from_secs(timeout));
    if let Some(d) = delay {
        config = config.with_delay(d);
    }

    // 显示配置摘要
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  配置摘要");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  目标:         {}:{}", config.target, config.port);
    println!("  服务:         {}", service_type.name());
    if service_type.requires_username() {
        println!("  用户名数:     {}", config.usernames.len());
    }
    println!("  密码数:       {}", config.passwords.len());
    if service_type.requires_username() {
        println!(
            "  总尝试次数:   {}",
            config.usernames.len() * config.passwords.len()
        );
    } else {
        println!("  总尝试次数:   {}", config.passwords.len());
    }
    println!("  并发数:       {}", config.concurrency);
    println!("  超时:         {} 秒", timeout);
    if let Some(d) = config.delay_ms {
        println!("  延迟:         {} 毫秒", d);
    }
    println!();

    // 确认
    let confirm = InteractiveMenu::read_input("确认开始爆破? [Y/n]: ");
    if confirm.to_lowercase() == "n" {
        print_info("已取消爆破");
        return Ok(());
    }

    println!();

    // 执行爆破
    let rt = tokio::runtime::Runtime::new()?;

    // 创建进度条
    use indicatif::{ProgressBar, ProgressStyle};
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("创建进度条样式失败"),
    );
    pb.set_message("正在爆破...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    // 根据服务类型选择爆破器
    let result = rt.block_on(async {
        match service_type {
            CrackService::Ssh => {
                let cracker = crate::cracker::ssh::SshCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Rdp => {
                let cracker = crate::cracker::rdp::RdpCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Redis => {
                let cracker = crate::cracker::redis_crack::RedisCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Postgres => {
                let cracker = crate::cracker::postgres::PostgresCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Mysql => {
                let cracker = crate::cracker::mysql::MysqlCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Mssql => {
                let cracker = crate::cracker::mssql::MssqlCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Mongodb => {
                let cracker = crate::cracker::mongodb_crack::MongodbCracker::new();
                cracker.crack(&config).await
            }
            CrackService::Winrm => {
                let cracker = crate::cracker::winrm::WinrmCracker::new();
                cracker.crack(&config).await
            }
        }
    });

    pb.finish_with_message("爆破完成");
    println!();

    // 显示结果
    if result.is_success() {
        println!("╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║  {}", colorize(&format!("{}!", crate::core::obfstr::sensitive::crack_success_label()), Color::BrightGreen));
        println!("╠════════════════════════════════════════════════════════════════════════════╣");
        println!("║  目标:        {}:{}", result.target, result.port);
        println!("║  服务:        {}", result.service);
        if let Some(username) = &result.username {
            println!("║  用户名:      {}", username);
        }
        if let Some(password) = &result.password {
            println!("║  密码:        {}", password);
        }
        println!("║  耗时:        {} ms", result.elapsed_ms);
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
    } else {
        println!("╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║  {}", colorize(&crate::core::obfstr::sensitive::crack_failed_label(), Color::BrightRed));
        println!("╠════════════════════════════════════════════════════════════════════════════╣");
        println!("║  目标:        {}:{}", result.target, result.port);
        println!("║  服务:        {}", result.service);
        println!("║  消息:        {}", result.message);
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
    }
    println!();

    Ok(())
}
