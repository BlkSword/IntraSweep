//! IntraSweep - 内网渗透辅助工具

mod ad;
mod cli;
mod collector;
mod core;
mod cracker;
mod modules;
mod output;
mod privesc;
mod scanner;
mod tunnel;
mod vuln;

use cli::Commands;
use clap::Parser;
use output::color::print_error;

fn main() {
    let cli = cli::Cli::parse();

    core::log::init_logging(&core::log::LogConfig {
        verbose: cli.verbose,
        quiet: cli.quiet,
        log_file: cli.log_file.clone(),
    });

    // 加载配置文件
    let app_config = cli.config.as_ref().and_then(|path| {
        match core::config::load_config(path) {
            Ok(cfg) => {
                tracing::info!("已加载配置文件: {}", path.display());
                Some(cfg)
            }
            Err(e) => {
                tracing::warn!("加载配置文件失败: {}", e);
                None
            }
        }
    });

    tracing::debug!("启动 IntraSweep");

    let result = match cli.command {
        Commands::System { item, output, quiet } => {
            cli::system::run_system(&item, output, quiet)
        }

        Commands::Scan { targets, scan_type, fast, webfinger, format, output } => {
            cli::scan::run_scan(targets, scan_type, fast, webfinger, &format, output)
        }

        Commands::Crack { target, port, service, usernames, password_file,
                          username_file, concurrency, timeout, delay } => {
            cli::crack::run_crack_cmd(target, port, service, usernames,
                                      password_file, username_file,
                                      concurrency, timeout, delay)
        }

        Commands::Tunnel { tunnel_type, target, local_port, remote_port,
                           hop, socks5_username, socks5_password,
                           max_connections, timeout } => {
            let _cfg = &app_config;
            cli::tunnel::run_tunnel_cmd(tunnel_type, target, local_port,
                                       remote_port, hop, socks5_username,
                                       socks5_password, max_connections, timeout)
        }

        Commands::Vuln { targets, poc_file, severity, category,
                         format, output, concurrency, timeout } => {
            cli::vuln::run_vuln_cmd(targets, poc_file, severity, category,
                                    &format, output, concurrency, timeout)
        }

        Commands::Ad { dc, domain, username, password, ssl, mode,
                       bloodhound_dir, format, output } => {
            cli::ad::run_ad_cmd(dc, domain, username, password, ssl,
                               mode, bloodhound_dir, &format, output)
        }

        Commands::Privesc { check, format, output } => {
            cli::privesc::run_privesc_cmd(check, &format, output)
        }
    };

    if let Err(e) = result {
        print_error(&format!("{}", e));
        std::process::exit(1);
    }
}
