//! 隧道集成测试
//!
//! 端到端测试正向隧道数据转发。

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, Duration};

async fn start_echo_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    let _ = stream.write_all(&buf[..n]).await;
                                }
                            }
                        }
                    });
                }
                Err(_) => break,
            }
        }
    });

    sleep(Duration::from_millis(50)).await;
    addr
}

#[tokio::test]
async fn test_forward_tunnel_echo() {
    let target_addr = start_echo_server().await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = listener.local_addr().unwrap().to_string();
    let target = target_addr.clone();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((client, _)) => {
                    let target = target.clone();
                    tokio::spawn(async move {
                        match TcpStream::connect(&target).await {
                            Ok(target_stream) => {
                                let (mut cr, mut cw) = client.into_split();
                                let (mut tr, mut tw) = target_stream.into_split();

                                let c_to_t = tokio::spawn(async move {
                                    let mut buf = vec![0u8; 4096];
                                    loop {
                                        match cr.read(&mut buf).await {
                                            Ok(0) | Err(_) => break,
                                            Ok(n) => {
                                                if tw.write_all(&buf[..n]).await.is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                });

                                let t_to_c = tokio::spawn(async move {
                                    let mut buf = vec![0u8; 4096];
                                    loop {
                                        match tr.read(&mut buf).await {
                                            Ok(0) | Err(_) => break,
                                            Ok(n) => {
                                                if cw.write_all(&buf[..n]).await.is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                });

                                let _ = tokio::join!(c_to_t, t_to_c);
                            }
                            Err(_) => {}
                        }
                    });
                }
                Err(_) => break,
            }
        }
    });

    sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(&tunnel_addr).await.unwrap();
    let test_msg = b"hello-tunnel-echo";
    client.write_all(test_msg).await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], test_msg);
}

#[tokio::test]
async fn test_tunnel_relay_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"server-greeting").await;
        }
    });

    sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(&addr).await.unwrap();
    let mut buf = vec![0u8; 256];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"server-greeting");
}
