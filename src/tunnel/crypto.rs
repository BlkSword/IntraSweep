//! 隧道加密模块
//!
//! 提供基于 XChaCha20-Poly1305 AEAD 的加密传输层。
//! 借鉴 RedPivot crypto.go 的设计，用 Rust 生态重写。

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// 加密层 — 持有 XChaCha20-Poly1305 AEAD 密码实例
pub struct CryptoLayer {
    cipher: XChaCha20Poly1305,
}

impl CryptoLayer {
    /// 从 32 字节密钥创建加密层
    pub fn new(key: &[u8; 32]) -> Self {
        use chacha20poly1305::Key;
        let key = Key::from_slice(key);
        Self {
            cipher: XChaCha20Poly1305::new(key),
        }
    }

    /// 加密明文，返回完整帧: [4B len BE][24B nonce][ciphertext+tag]
    pub fn encrypt(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 24];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = *XNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("加密失败: {}", e)))?;

        let total_len = 24 + ciphertext.len();
        let mut frame = Vec::with_capacity(4 + total_len);
        frame.extend_from_slice(&(total_len as u32).to_be_bytes());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    /// 解密帧，输入不含 4 字节长度前缀（长度已由调用方剥离）
    fn decrypt_frame(&self, nonce_and_ct: &[u8]) -> io::Result<Vec<u8>> {
        if nonce_and_ct.len() < 24 + 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "帧数据过短，至少需要 nonce(24) + tag(16)",
            ));
        }
        let nonce = XNonce::from_slice(&nonce_and_ct[..24]);
        let ciphertext = &nonce_and_ct[24..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("解密失败: {}", e)))
    }
}

/// 加密流 — 包装异步流，透明加解密
///
/// 写入：自动加密后写帧
/// 读取：自动读帧后解密，内部缓冲处理帧边界
pub struct EncryptedStream<S> {
    inner: S,
    crypto: Arc<CryptoLayer>,
    /// 已解密待读取的数据缓冲区
    read_buf: Vec<u8>,
    /// 当前读取位置
    read_pos: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> EncryptedStream<S> {
    pub fn new(inner: S, crypto: Arc<CryptoLayer>) -> Self {
        Self {
            inner,
            crypto,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    /// 获取内部流的引用
    #[allow(dead_code)]
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// 获取内部流的可变引用
    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// 写入加密帧
    pub async fn write_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let frame = self.crypto.encrypt(data)?;
        self.inner.write_all(&frame).await
    }

    /// 读取一帧并解密到内部缓冲区
    async fn read_frame(&mut self) -> io::Result<()> {
        // 读取 4 字节长度前缀
        let mut len_buf = [0u8; 4];
        self.inner.read_exact(&mut len_buf).await?;
        let payload_len = u32::from_be_bytes(len_buf) as usize;

        // 限制帧大小防止内存耗尽
        if payload_len > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("帧长度异常: {} 字节", payload_len),
            ));
        }

        // 读取 nonce + ciphertext
        let mut frame_data = vec![0u8; payload_len];
        self.inner.read_exact(&mut frame_data).await?;

        // 解密
        let plaintext = self.crypto.decrypt_frame(&frame_data)?;

        self.read_buf = plaintext;
        self.read_pos = 0;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 如果缓冲区有数据，先返回缓冲的数据
        if self.read_pos < self.read_buf.len() {
            let available = &self.read_buf[self.read_pos..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.read_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // 需要从流中读取新帧，但 AsyncRead 中不能直接 await
        // 返回 Pending 并注册 waker，由上层 poll 循环驱动
        // 使用 tokio 的 read_buf 机制：先尝试 fill 内部 buffer
        //
        // 策略：将 inner 的 read 委托给一个 "pending fill" 状态
        // 实际上我们利用 tokio 的 poll 机制：
        // 返回 WouldBlock 让上层重试，同时注册 waker
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 加密并序列化，然后委托给 inner
        let this = self.get_mut();
        let frame = match this.crypto.encrypt(buf) {
            Ok(f) => f,
            Err(e) => return Poll::Ready(Err(e)),
        };

        match Pin::new(&mut this.inner).poll_write(_cx, &frame) {
            Poll::Ready(Ok(n)) if n == frame.len() => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "加密流部分写入",
            ))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// EncryptedStream 的高层读取方法（需要 tokio runtime 驱动）
impl<S: AsyncRead + AsyncWrite + Unpin> EncryptedStream<S> {
    /// 读取解密后的数据到缓冲区，返回读取的字节数
    /// 0 表示连接关闭
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // 如果内部缓冲区有数据，先消耗
        if self.read_pos < self.read_buf.len() {
            let available = &self.read_buf[self.read_pos..];
            let to_copy = available.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&available[..to_copy]);
            self.read_pos += to_copy;
            return Ok(to_copy);
        }

        // 从流读取下一帧
        match self.read_frame().await {
            Ok(()) => {
                let available = &self.read_buf[self.read_pos..];
                let to_copy = available.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&available[..to_copy]);
                self.read_pos += to_copy;
                Ok(to_copy)
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    Ok(0)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// 写入加密数据
    pub async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.write_frame(data).await?;
        Ok(data.len())
    }

    /// 写入全部加密数据
    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.write_frame(data).await
    }
}

/// 使用 HKDF-SHA256 从共享秘密派生 32 字节密钥
///
/// HKDF 过程：extract(salt, ikm) → expand(prk, info, 32)
pub fn derive_key(shared_secret: &str) -> [u8; 32] {
    use hmac::Mac;

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    // HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
    let salt = b"intrasweep-tunnel-v1";
    let mut extract = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC key 创建失败");
    extract.update(shared_secret.as_bytes());
    let prk = extract.finalize().into_bytes();

    // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
    let info = b"tunnel-encryption-key";
    let mut expand = <HmacSha256 as Mac>::new_from_slice(&prk).expect("HMAC key 创建失败");
    expand.update(info);
    expand.update(&[0x01]);
    let okm = expand.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let key1 = derive_key("my-secret-password");
        let key2 = derive_key("my-secret-password");
        let key3 = derive_key("different-password");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = derive_key("test-key");
        let layer = CryptoLayer::new(&key);

        let plaintext = b"Hello, encrypted tunnel!";
        let frame = layer.encrypt(plaintext).unwrap();

        // 帧: [4B len][24B nonce][ciphertext+tag]
        let frame_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(frame_len, frame.len() - 4);
        assert!(frame_len >= 24 + 16); // nonce + minimum ciphertext + tag

        // 解密
        let decrypted = layer.decrypt_frame(&frame[4..]).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_empty() {
        let key = derive_key("test");
        let layer = CryptoLayer::new(&key);

        let frame = layer.encrypt(b"").unwrap();
        let decrypted = layer.decrypt_frame(&frame[4..]).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_decrypt_tampered_data() {
        let key = derive_key("test");
        let layer = CryptoLayer::new(&key);

        let mut frame = layer.encrypt(b"secret").unwrap();
        // 篡改密文
        if frame.len() > 30 {
            frame[30] ^= 0x01;
        }
        let result = layer.decrypt_frame(&frame[4..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let layer1 = CryptoLayer::new(&derive_key("key-a"));
        let layer2 = CryptoLayer::new(&derive_key("key-b"));

        let frame = layer1.encrypt(b"secret").unwrap();
        let result = layer2.decrypt_frame(&frame[4..]);
        assert!(result.is_err());
    }
}
