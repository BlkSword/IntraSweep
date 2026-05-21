//! PoC 执行引擎
//!
//! HTTP 传输通过 reqwest 执行，TCP 传输通过 tokio TcpStream 执行

use crate::core::Result;
use crate::vuln::matchers::HttpResponseContext;
use crate::vuln::poc::PoCRequest;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 执行 HTTP PoC 请求
pub async fn execute_http_request(
    target: &str,
    port: u16,
    request: &PoCRequest,
    timeout: Duration,
) -> Result<HttpResponseContext> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .no_proxy()
        .build()
        .map_err(|e| crate::core::error::FlyWheelError::Other {
            message: format!("构建HTTP客户端失败: {}", e),
        })?;

    let scheme = if matches!(port, 443 | 8443 | 9443) {
        "https"
    } else {
        "http"
    };
    let url = format!("{}://{}:{}{}", scheme, target, port, request.path);

    let mut builder = match request.method.to_uppercase().as_str() {
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, &url),
        "PATCH" => client.patch(&url),
        _ => client.get(&url),
    };

    builder = builder.header(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    );

    for (key, value) in &request.headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    if let Some(body) = &request.body {
        builder = builder.body(body.clone());
    }

    let resp = builder.send().await.map_err(|e| {
        crate::core::error::FlyWheelError::Other {
            message: format!("HTTP请求失败: {}", e),
        }
    })?;

    let status_code = resp.status().as_u16();
    let headers_str = resp
        .headers()
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\n");
    let body = resp.text().await.unwrap_or_default();

    Ok(HttpResponseContext {
        status_code,
        headers: headers_str,
        body,
    })
}

/// TCP 响应数据
pub struct TcpResponseData {
    pub data: Vec<u8>,
}

/// 执行 TCP PoC 请求
pub async fn execute_tcp_request(
    target: &str,
    port: u16,
    request: &PoCRequest,
    timeout: Duration,
) -> Result<TcpResponseData> {
    use crate::core::error::FlyWheelError;

    let addr = format!("{}:{}", target, port);
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| FlyWheelError::Other {
            message: format!("TCP连接超时: {}", addr),
        })??;

    if let Some(data) = &request.data {
        tokio::time::timeout(timeout, stream.write_all(data.as_bytes()))
            .await
            .map_err(|_| FlyWheelError::Other {
                message: "TCP写入超时".to_string(),
            })??;
    }

    let read_size = request.read_size.unwrap_or(4096);
    let mut buf = vec![0u8; read_size];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .map_err(|_| FlyWheelError::Other {
            message: "TCP读取超时".to_string(),
        })??;
    buf.truncate(n);

    Ok(TcpResponseData { data: buf })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheme_selection() {
        assert_eq!(
            if matches!(443u16, 443 | 8443 | 9443) {
                "https"
            } else {
                "http"
            },
            "https"
        );
        assert_eq!(
            if matches!(8080u16, 443 | 8443 | 9443) {
                "https"
            } else {
                "http"
            },
            "http"
        );
    }
}
