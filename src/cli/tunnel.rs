//! 隧道 CLI
//!
//! 处理隧道子命令的交互式配置向导和直接模式

use crate::cli::{print_banner, InteractiveMenu, TUNNEL_TYPES};
use crate::core::error::FlyWheelError;
use crate::core::Result;
use crate::output::color::{print_error, print_info, print_success};
use crate::tunnel::{TunnelConfig, TunnelManager, TunnelType};

/// 隧道命令入口
pub fn run_tunnel_cmd(
    tunnel_type: Option<String>,
    target: Option<String>,
    local_port: Option<u16>,
    remote_port: Option<u16>,
    hop: Option<Vec<String>>,
    socks5_username: Option<String>,
    socks5_password: Option<String>,
    max_connections: usize,
    timeout: u64,
) -> Result<()> {
    if tunnel_type.is_none() {
        run_interactive_tunnel(
            tunnel_type,
            target,
            local_port,
            remote_port,
            hop,
            socks5_username,
            socks5_password,
            max_connections,
            timeout,
        )
    } else {
        run_tunnel(
            tunnel_type.unwrap(),
            target,
            local_port,
            remote_port,
            hop,
            socks5_username,
            socks5_password,
            max_connections,
            timeout,
        )
    }
}

/// 运行隧道（直接模式）
fn run_tunnel(
    tunnel_type: String,
    target: Option<String>,
    local_port: Option<u16>,
    _remote_port: Option<u16>,
    hop: Option<Vec<String>>,
    socks5_username: Option<String>,
    socks5_password: Option<String>,
    max_connections: usize,
    timeout: u64,
) -> Result<()> {
    // 解析隧道类型
    let tunnel_type_enum = match TunnelType::from_str(&tunnel_type) {
        Some(t) => t,
        None => {
            print_error(&format!("未知的隧道类型: {}", tunnel_type));
            print_tunnel_types();
            std::process::exit(1);
        }
    };

    // 确定本地端口
    let local_port = local_port.unwrap_or(match tunnel_type_enum {
        TunnelType::Forward => 8080,
        TunnelType::Reverse => 8080,
        TunnelType::Socks5 => 1080,
        TunnelType::Chain => 8080,
    });

    let local_addr_str = format!("127.0.0.1:{}", local_port);
    let local_addr = local_addr_str.parse()
        .map_err(|_| FlyWheelError::Other {
            message: format!("无效的本地地址: {}", local_addr_str),
        })?;

    // 创建配置
    let mut config = TunnelConfig::new(tunnel_type_enum, local_addr)
        .with_max_connections(max_connections)
        .with_timeout(timeout);

    // 设置远程目标
    if let Some(t) = target {
        config = config.with_remote_target(t);
    }

    // 设置跳板
    if let Some(h) = hop {
        config = config.with_hops(h);
    }

    // 设置 SOCKS5 认证
    if let (Some(username), Some(password)) = (socks5_username, socks5_password) {
        config = config.with_socks5_auth(username, password);
    }

    // 验证配置
    config
        .validate()
        .map_err(|e| FlyWheelError::Other { message: e })?;

    // 创建隧道管理器
    let manager = TunnelManager::new();

    // 启动隧道
    let rt = tokio::runtime::Runtime::new()?;

    match tunnel_type_enum {
        TunnelType::Forward => {
            let tunnel = manager.create_forward_tunnel(config);
            rt.block_on(tunnel.start())?;
        }
        TunnelType::Reverse => {
            let tunnel = manager.create_reverse_tunnel(config);
            // 默认使用客户端模式
            rt.block_on(tunnel.start_client())?;
        }
        TunnelType::Socks5 => {
            let server = manager.create_socks5_server(config);
            rt.block_on(server.start())?;
        }
        TunnelType::Chain => {
            let tunnel = manager.create_chain_tunnel(config);
            rt.block_on(tunnel.start())?;
        }
    }

    Ok(())
}

/// 运行交互式隧道向导
fn run_interactive_tunnel(
    initial_tunnel_type: Option<String>,
    initial_target: Option<String>,
    initial_local_port: Option<u16>,
    _initial_remote_port: Option<u16>,
    initial_hop: Option<Vec<String>>,
    _initial_socks5_username: Option<String>,
    _initial_socks5_password: Option<String>,
    initial_max_connections: usize,
    initial_timeout: u64,
) -> Result<()> {
    print_banner();
    println!();
    print_info(&format!("IntraSweep 交互式{}配置向导", crate::core::obfstr::sensitive::tunnel_label()));
    println!();

    // 步骤 1: 隧道类型
    let tunnel_type = if let Some(tt) = initial_tunnel_type {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [1/5] 隧道类型");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("已指定: {}", tt);
        println!();
        tt
    } else {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  [1/5] 隧道类型");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();
        println!("  1. 正向隧道       - 本地端口转发到远程目标");
        println!("  2. 反向隧道       - 从内网建立连接回外网");
        println!("  3. SOCKS5 代理    - 动态端口转发代理");
        println!("  4. 链式隧道       - 多级跳板连接");
        println!();

        let choice = InteractiveMenu::read_number("请选择隧道类型 [1-4]: ", 1, 4);
        let tunnel_type = match choice {
            1 => "forward".to_string(),
            2 => "reverse".to_string(),
            3 => "socks5".to_string(),
            4 => "chain".to_string(),
            _ => "forward".to_string(),
        };
        println!();
        print_success(&format!("已选择: {}", format_tunnel_type(&tunnel_type)));
        println!();
        tunnel_type
    };

    let tunnel_type_enum = TunnelType::from_str(&tunnel_type).unwrap();

    // 步骤 2: 本地端口
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [2/5] 本地监听端口");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let default_port = match tunnel_type_enum {
        TunnelType::Forward => 8080,
        TunnelType::Reverse => 8080,
        TunnelType::Socks5 => 1080,
        TunnelType::Chain => 8080,
    };

    let local_port = if let Some(lp) = initial_local_port {
        println!("已指定端口: {}", lp);
        println!();
        lp
    } else {
        let port_input = InteractiveMenu::read_input(&format!(
            "按 Enter 使用默认端口({}) 或输入自定义端口: ",
            default_port
        ));
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

    // 步骤 3: 远程目标/跳板
    let mut config = TunnelConfig::new(
        tunnel_type_enum,
        format!("127.0.0.1:{}", local_port).parse().unwrap(),
    );

    match tunnel_type_enum {
        TunnelType::Forward | TunnelType::Reverse => {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  [3/5] 目标地址");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();

            let target = if let Some(t) = &initial_target {
                println!("已指定目标: {}", t);
                println!();
                t.clone()
            } else {
                loop {
                    let input = InteractiveMenu::read_input("请输入目标地址 (host:port): ");
                    println!();
                    if !input.is_empty() {
                        break input;
                    }
                    print_error("目标不能为空，请重新输入");
                }
            };

            config = config.with_remote_target(target);
        }
        TunnelType::Chain => {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  [3/5] 跳板和目标");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();

            let hops = if let Some(h) = &initial_hop {
                println!("已指定跳板: {}", h.join(", "));
                println!();
                h.clone()
            } else {
                let mut hops = Vec::new();
                loop {
                    let input =
                        InteractiveMenu::read_input("请输入跳板地址 (host:port)，留空结束: ");
                    if input.is_empty() {
                        break;
                    }
                    hops.push(input);
                }
                println!();
                hops
            };

            let target = if let Some(t) = &initial_target {
                println!("已指定目标: {}", t);
                println!();
                t.clone()
            } else {
                InteractiveMenu::read_input("请输入最终目标地址 (host:port): ")
            };

            config = config.with_hops(hops).with_remote_target(target);
            println!();
        }
        TunnelType::Socks5 => {
            // SOCKS5 不需要预先指定目标
        }
    }

    // 步骤 4: 高级选项
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [4/5] 高级选项");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let max_connections = if initial_max_connections == 100 {
        let input = InteractiveMenu::read_input("最大并发连接 (默认: 100): ");
        println!();
        if input.is_empty() {
            100
        } else {
            input.parse::<usize>().unwrap_or(100)
        }
    } else {
        println!("已指定最大连接: {}", initial_max_connections);
        println!();
        initial_max_connections
    };

    let timeout = if initial_timeout == 30 {
        let input = InteractiveMenu::read_input("超时时间/秒 (默认: 30): ");
        println!();
        if input.is_empty() {
            30
        } else {
            input.parse::<u64>().unwrap_or(30)
        }
    } else {
        println!("已指定超时: {} 秒", initial_timeout);
        println!();
        initial_timeout
    };

    config = config
        .with_max_connections(max_connections)
        .with_timeout(timeout);

    // 步骤 5: 确认
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  [5/5] 配置确认");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!(
        "  隧道类型:     {}",
        format_tunnel_type(tunnel_type_enum.as_str())
    );
    println!("  本地端口:     {}", local_port);
    if let Some(ref target) = config.remote_target {
        println!("  目标:         {}", target);
    }
    if !config.hops.is_empty() {
        println!("  跳板:         {}", config.hops.join(", "));
    }
    println!("  最大连接:     {}", max_connections);
    println!("  超时:         {} 秒", timeout);
    println!();

    let confirm = InteractiveMenu::read_input("确认启动隧道? [Y/n]: ");
    if confirm.to_lowercase() == "n" {
        print_info("已取消隧道");
        return Ok(());
    }

    println!();
    print_info("启动隧道...");
    println!();

    // 启动隧道
    let manager = TunnelManager::new();
    let rt = tokio::runtime::Runtime::new()?;

    match tunnel_type_enum {
        TunnelType::Forward => {
            let tunnel = manager.create_forward_tunnel(config);
            rt.block_on(tunnel.start())?;
        }
        TunnelType::Reverse => {
            let tunnel = manager.create_reverse_tunnel(config);
            rt.block_on(tunnel.start_client())?;
        }
        TunnelType::Socks5 => {
            let server = manager.create_socks5_server(config);
            rt.block_on(server.start())?;
        }
        TunnelType::Chain => {
            let tunnel = manager.create_chain_tunnel(config);
            rt.block_on(tunnel.start())?;
        }
    }

    Ok(())
}

/// 格式化隧道类型
fn format_tunnel_type(ty: &str) -> String {
    match ty {
        "forward" => crate::core::obfstr::sensitive::forward_tunnel_label(),
        "reverse" => crate::core::obfstr::sensitive::reverse_tunnel_label(),
        "socks5" => crate::core::obfstr::sensitive::socks5_proxy_label(),
        "chain" => crate::core::obfstr::sensitive::chain_tunnel_label(),
        _ => ty.to_string(),
    }
}

/// 打印可用的隧道类型
fn print_tunnel_types() {
    println!("可用的隧道类型:");
    for (full, abbr) in TUNNEL_TYPES {
        println!("  {} ({})", full, abbr);
    }
}
