//! 核心功能模块
//!
//! 包含错误处理等核心基础设施

pub mod config;
pub mod error;
pub mod log;
pub mod obfstr;

pub use error::Result;
