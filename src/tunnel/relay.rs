//! 双向流量转发公共模块
//!
//! 提供统一的 TCP 双向转发功能，被 forward/chain/socks5 模块共用

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 数据传输统计
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferStats {
    pub sent: u64,
    pub received: u64,
}

/// 双向流量转发
///
/// 在 client 和 target 之间进行双向数据转发，
/// 直到任一方关闭连接或发生错误。
pub async fn relay(mut client: TcpStream, mut target: TcpStream) -> TransferStats {
    let mut client_buf = vec![0u8; 32768];
    let mut target_buf = vec![0u8; 32768];
    let mut sent = 0u64;
    let mut received = 0u64;

    loop {
        tokio::select! {
            // 客户端 -> 目标
            result = client.read(&mut client_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = target.write_all(&client_buf[..n]).await {
                            eprintln!("[错误] 写入目标失败: {}", e);
                            break;
                        }
                        sent += n as u64;
                    }
                    Err(e) => {
                        eprintln!("[错误] 读取客户端失败: {}", e);
                        break;
                    }
                }
            }
            // 目标 -> 客户端
            result = target.read(&mut target_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = client.write_all(&target_buf[..n]).await {
                            eprintln!("[错误] 写入客户端失败: {}", e);
                            break;
                        }
                        received += n as u64;
                    }
                    Err(e) => {
                        eprintln!("[错误] 读取目标失败: {}", e);
                        break;
                    }
                }
            }
        }
    }

    TransferStats { sent, received }
}
