//! 双向流量转发公共模块
//!
//! 提供统一的 TCP 双向转发功能，被 forward/chain/socks5 模块共用。
//! 支持泛型流类型（TcpStream / EncryptedStream）。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing;

/// 数据传输统计
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferStats {
    pub sent: u64,
    pub received: u64,
}

/// 双向流量转发（泛型版本）
///
/// 在 client 和 target 之间进行双向数据转发，
/// 直到任一方关闭连接或发生错误。
/// 支持 `TcpStream`、`EncryptedStream` 等组合。
pub async fn relay<C, T>(mut client: C, mut target: T) -> TransferStats
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_buf = vec![0u8; 32768];
    let mut target_buf = vec![0u8; 32768];
    let mut sent = 0u64;
    let mut received = 0u64;

    loop {
        tokio::select! {
            result = client.read(&mut client_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = target.write_all(&client_buf[..n]).await {
                            tracing::error!("写入目标失败: {}", e);
                            break;
                        }
                        sent += n as u64;
                    }
                    Err(e) => {
                        tracing::error!("读取客户端失败: {}", e);
                        break;
                    }
                }
            }
            result = target.read(&mut target_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = client.write_all(&target_buf[..n]).await {
                            tracing::error!("写入客户端失败: {}", e);
                            break;
                        }
                        received += n as u64;
                    }
                    Err(e) => {
                        tracing::error!("读取目标失败: {}", e);
                        break;
                    }
                }
            }
        }
    }

    TransferStats { sent, received }
}
