//! 优雅关闭模块
//!
//! 基于 `CancellationToken` 提供隧道优雅关闭能力，
//! 支持 Ctrl+C 信号监听。

use tokio_util::sync::CancellationToken;

/// 优雅关闭信号
///
/// 所有隧道 `start()` 方法接受此类型的引用，
/// 在 accept 循环中定期检查是否需要关闭。
#[derive(Clone)]
pub struct Shutdown {
    token: CancellationToken,
}

impl Shutdown {
    /// 创建新的关闭信号（不自动注册 Ctrl+C）
    pub fn new() -> Self {
        Self {
            token: CancellationToken::new(),
        }
    }

    /// 创建并注册 Ctrl+C handler，按下时自动触发关闭
    pub fn on_ctrl_c() -> Self {
        let shutdown = Self::new();
        let token = shutdown.token.clone();

        tokio::spawn(async move {
            tokio::signal::ctrl_c()
                .await
                .expect("注册 Ctrl+C handler 失败");
            eprintln!();
            eprintln!("收到中断信号，正在关闭隧道...");
            token.cancel();
        });

        shutdown
    }

    /// 手动触发关闭
    #[allow(dead_code)]
    pub fn signal(&self) {
        self.token.cancel();
    }

    /// 检查是否已触发关闭
    pub fn is_signalled(&self) -> bool {
        self.token.is_cancelled()
    }

    /// 等待关闭信号
    pub async fn wait(&self) {
        self.token.cancelled().await;
    }

    /// 获取内部的 CancellationToken（用于 select!）
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_new() {
        let s = Shutdown::new();
        assert!(!s.is_signalled());
    }

    #[test]
    fn test_shutdown_signal() {
        let s = Shutdown::new();
        assert!(!s.is_signalled());
        s.signal();
        assert!(s.is_signalled());
    }

    #[test]
    fn test_shutdown_clone() {
        let s1 = Shutdown::new();
        let s2 = s1.clone();
        assert!(!s1.is_signalled());
        assert!(!s2.is_signalled());
        s1.signal();
        assert!(s2.is_signalled());
    }
}
