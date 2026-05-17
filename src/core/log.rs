//! 日志初始化模块
//!
//! 基于 tracing + tracing-subscriber 的日志系统

use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

/// 日志配置
pub struct LogConfig {
    pub verbose: bool,
    pub quiet: bool,
    pub log_file: Option<PathBuf>,
}

/// 初始化日志系统
pub fn init_logging(config: &LogConfig) {
    let env_filter = if config.verbose {
        EnvFilter::new("debug")
    } else if config.quiet {
        EnvFilter::new("error")
    } else {
        EnvFilter::new("warn")
    };

    if let Some(log_path) = &config.log_file {
        if let Ok(file) = std::fs::File::create(log_path) {
            tracing_subscriber::fmt()
                .with_writer(std::sync::Mutex::new(file))
                .with_ansi(false)
                .with_target(true)
                .with_env_filter(env_filter)
                .init();
            return;
        }
    }

    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_env_filter(env_filter)
        .init();
}
