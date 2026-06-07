//! 连接多路复用模块
//!
//! 在单一长连接上承载多个逻辑流 (stream)，每个流独立读写。
//! 借鉴 RedPivot mux.go 的设计，用 Rust 异步通道实现。

use crate::core::Result;
use std::collections::HashMap;
use tracing;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

/// 帧类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Open = 0x01,
    Data = 0x02,
    Close = 0x03,
    Ping = 0x04,
    Pong = 0x05,
}

impl FrameType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(FrameType::Open),
            0x02 => Some(FrameType::Data),
            0x03 => Some(FrameType::Close),
            0x04 => Some(FrameType::Ping),
            0x05 => Some(FrameType::Pong),
            _ => None,
        }
    }
}

const FRAME_MAGIC: u32 = 0x4953_574D; // "ISWM"
const FRAME_VERSION: u8 = 0x01;
const HEADER_SIZE: usize = 14; // magic(4) + ver(1) + type(1) + stream_id(4) + payload_len(4)
const MAX_FRAME_SIZE: usize = 1024 * 1024; // 1 MB

/// Mux 内部动作（MuxStream → Mux 主循环）
pub(crate) enum MuxAction {
    /// 写数据帧
    Data { stream_id: u32, payload: Vec<u8> },
    /// 关闭流
    Close { stream_id: u32 },
}

/// 单个多路复用流
///
/// 实现 `AsyncRead` + `AsyncWrite`，可在流上透明读写数据帧。
pub struct MuxStream {
    stream_id: u32,
    /// 从 Mux 主循环接收数据
    rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    /// 向 Mux 主循环发送动作
    action_tx: mpsc::UnboundedSender<MuxAction>,
    /// 读取缓冲区
    read_buf: Mutex<Vec<u8>>,
    read_pos: Mutex<usize>,
    /// 写入缓冲区
    write_buf: Mutex<Vec<u8>>,
    closed: AtomicBool,
}

impl MuxStream {
    fn new(
        stream_id: u32,
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
        action_tx: mpsc::UnboundedSender<MuxAction>,
    ) -> Self {
        Self {
            stream_id,
            rx: Mutex::new(rx),
            action_tx,
            read_buf: Mutex::new(Vec::new()),
            read_pos: Mutex::new(0),
            write_buf: Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        }
    }

    /// 获取流 ID
    #[allow(dead_code)]
    pub fn id(&self) -> u32 {
        self.stream_id
    }

    /// 关闭流
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let _ = self.action_tx.send(MuxAction::Close {
            stream_id: self.stream_id,
        });
    }

    /// 刷新写入缓冲区（发送 Data 帧）
    fn flush_write(&self) {
        let mut buf = self.write_buf.lock()
            .expect("Mutex 不应被毒化 (write_buf)");

        if buf.is_empty() {
            return;
        }
        let payload = std::mem::take(&mut *buf);
        let _ = self.action_tx.send(MuxAction::Data {
            stream_id: self.stream_id,
            payload,
        });
    }

    /// 从内部缓冲区读取数据到输出缓冲区
    fn drain_buf(&self, out: &mut ReadBuf<'_>) -> usize {
        let mut buf = self.read_buf.lock()
            .expect("Mutex 不应被毒化 (read_buf)");
        let mut pos = self.read_pos.lock()
            .expect("Mutex 不应被毒化 (read_pos)");


        if *pos >= buf.len() {
            return 0;
        }

        let available = &buf[*pos..];
        let to_copy = available.len().min(out.remaining());
        out.put_slice(&available[..to_copy]);
        *pos += to_copy;

        if *pos >= buf.len() {
            buf.clear();
            *pos = 0;
        }

        to_copy
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.closed.load(Ordering::SeqCst) {
            return std::task::Poll::Ready(Ok(()));
        }

        // 先尝试从内部缓冲区读取
        let copied = self.drain_buf(buf);
        if copied > 0 {
            return std::task::Poll::Ready(Ok(()));
        }

        // 尝试从通道接收新数据
        let mut rx = self.rx.lock()
            .expect("Mutex 不应被毒化 (rx)");
        match rx.try_recv() {

            Ok(data) => {
                *self.read_buf.lock()
                    .expect("Mutex 不应被毒化 (read_buf)") = data;
                *self.read_pos.lock()
                    .expect("Mutex 不应被毒化 (read_pos)") = 0;
                drop(rx);
                self.drain_buf(buf);
                std::task::Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                // 注册 waker，当通道有新数据时被唤醒
                // mpsc 通道会在 sender 端发送数据时唤醒 receiver 的 waker
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                self.closed.store(true, Ordering::SeqCst);
                std::task::Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.closed.load(Ordering::SeqCst) {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "流已关闭",
            )));
        }

        let mut write_buf = self.write_buf.lock()
            .expect("Mutex 不应被毒化 (write_buf)");
        write_buf.extend_from_slice(buf);

        // 如果缓冲区超过阈值，自动刷新
        if write_buf.len() >= 8192 {
            let payload = std::mem::take(&mut *write_buf);
            drop(write_buf);
            let _ = self.action_tx.send(MuxAction::Data {
                stream_id: self.stream_id,
                payload,
            });
        }

        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.flush_write();
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.flush_write();
        self.closed.store(true, Ordering::SeqCst);
        let _ = self.action_tx.send(MuxAction::Close {
            stream_id: self.stream_id,
        });
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        let _ = self.action_tx.send(MuxAction::Close {
            stream_id: self.stream_id,
        });
    }
}

/// 连接多路复用管理器
///
/// 在单个连接上承载多个逻辑流。
/// 创建后调用 `run()` 进入主循环（通常 spawn 为后台任务）。
pub struct Mux<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    streams: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    action_rx: mpsc::UnboundedReceiver<MuxAction>,
    action_tx: mpsc::UnboundedSender<MuxAction>,
    next_id: u32,
    /// 等待接受的流通道
    accept_tx: mpsc::UnboundedSender<MuxStream>,
    accept_rx: mpsc::UnboundedReceiver<MuxStream>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Mux<S> {
    /// 从已建立的连接创建多路复用器
    pub fn new(stream: S) -> Self {
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();

        Self {
            stream,
            streams: Arc::new(Mutex::new(HashMap::new())),
            action_rx,
            action_tx,
            next_id: 1, // 客户端从奇数开始
            accept_tx,
            accept_rx,
        }
    }

    /// 打开新流（客户端模式，奇数 ID）
    pub fn open_stream(&mut self) -> MuxStream {
        let stream_id = self.next_id;
        self.next_id += 2;

        let (tx, rx) = mpsc::unbounded_channel();
        self.streams.lock()
            .expect("Mutex 不应被毒化 (streams)")
            .insert(stream_id, tx);

        
        MuxStream::new(stream_id, rx, self.action_tx.clone())
    }

    /// 接受对端发起的流（服务端模式，等待 Open 帧）
    pub async fn accept(&mut self) -> Option<MuxStream> {
        self.accept_rx.recv().await
    }

    /// 获取 action sender 的克隆（用于外部创建 MuxStream）
    pub(crate) fn sender(&self) -> mpsc::UnboundedSender<MuxAction> {
        self.action_tx.clone()
    }

    /// 主循环：读帧并分发，监听内部动作并写帧
    pub async fn run(mut self) -> Result<()> {
        let mut buf = vec![0u8; MAX_FRAME_SIZE];
        let ping_interval = Duration::from_secs(30);
        let mut last_ping = tokio::time::Instant::now();

        // 提前取出需要独立借用的字段，避免 select! 中的借用冲突
        let streams = self.streams.clone();
        let accept_tx = self.accept_tx;
        let action_tx = self.action_tx;

        loop {
            tokio::select! {
                read_result = Self::read_frame_raw(&mut self.stream, &mut buf) => {
                    match read_result {
                        Ok(Some((ft, stream_id, payload))) => {
                            Self::dispatch_raw(
                                ft, stream_id, payload,
                                &streams, &accept_tx, &action_tx,
                            );
                        }
                        Ok(None) => break,
                        Err(e) => {
                            tracing::error!("[Mux] 读取帧错误: {}", e);
                            break;
                        }
                    }
                }
                action = self.action_rx.recv() => {
                    match action {
                        Some(MuxAction::Data { stream_id, payload }) => {
                            if let Err(e) = Self::write_frame_raw(
                                &mut self.stream, FrameType::Data, stream_id, &payload
                            ).await {
                                tracing::error!("[Mux] 写数据帧错误: {}", e);
                                break;
                            }
                        }
                        Some(MuxAction::Close { stream_id }) => {
                            let _ = Self::write_frame_raw(
                                &mut self.stream, FrameType::Close, stream_id, &[]
                            ).await;
                            streams.lock()
                                .expect("Mutex 不应被毒化 (streams)")
                                .remove(&stream_id);
                        }
                        None => break,
                    }
                }
                _ = sleep(ping_interval) => {
                    if last_ping.elapsed() >= ping_interval {
                        if let Err(e) = Self::write_frame_raw(
                            &mut self.stream, FrameType::Ping, 0, &[]
                        ).await {
                            tracing::error!("[Mux] 写 Ping 错误: {}", e);
                            break;
                        }
                        last_ping = tokio::time::Instant::now();
                    }
                }
            }
        }

        streams.lock()
            .expect("Mutex 不应被毒化 (streams)")
            .clear();
        Ok(())
    }

    /// 从流中读取一个完整帧（关联函数，避免借用冲突）
    async fn read_frame_raw(
        stream: &mut S,
        buf: &mut [u8],
    ) -> std::io::Result<Option<(FrameType, u32, Vec<u8>)>> {
        let mut header = [0u8; HEADER_SIZE];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }

        // 验证魔数
        let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        if magic != FRAME_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("无效魔数: 0x{:08X}", magic),
            ));
        }

        let version = header[4];
        if version != FRAME_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("不支持的版本: {}", version),
            ));
        }

        let frame_type = FrameType::from_u8(header[5]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("未知帧类型: 0x{:02X}", header[5]),
            )
        })?;

        let stream_id = u32::from_be_bytes([header[6], header[7], header[8], header[9]]);
        let payload_len = u32::from_be_bytes([header[10], header[11], header[12], header[13]]) as usize;

        if payload_len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("帧载荷过大: {}", payload_len),
            ));
        }

        let payload = if payload_len > 0 {
            let payload_slice = &mut buf[..payload_len];
            stream.read_exact(payload_slice).await?;
            payload_slice.to_vec()
        } else {
            Vec::new()
        };

        Ok(Some((frame_type, stream_id, payload)))
    }

    /// 向流写入一个完整帧（关联函数，避免借用冲突）
    async fn write_frame_raw(
        stream: &mut S,
        frame_type: FrameType,
        stream_id: u32,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let mut header = [0u8; HEADER_SIZE];

        // Magic
        header[0..4].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        // Version
        header[4] = FRAME_VERSION;
        // Frame type
        header[5] = frame_type as u8;
        // Stream ID
        header[6..10].copy_from_slice(&stream_id.to_be_bytes());
        // Payload length
        let plen = payload.len() as u32;
        header[10..14].copy_from_slice(&plen.to_be_bytes());

        stream.write_all(&header).await?;
        if !payload.is_empty() {
            stream.write_all(payload).await?;
        }

        Ok(())
    }

    /// 分发帧到对应的流（关联函数，避免借用冲突）
    fn dispatch_raw(
        frame_type: FrameType,
        stream_id: u32,
        payload: Vec<u8>,
        streams: &Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
        accept_tx: &mpsc::UnboundedSender<MuxStream>,
        action_tx: &mpsc::UnboundedSender<MuxAction>,
    ) {
        match frame_type {
            FrameType::Open => {
                let (tx, rx) = mpsc::unbounded_channel();
                streams.lock()
                    .expect("Mutex 不应被毒化 (streams)")
                    .insert(stream_id, tx);

                let stream = MuxStream::new(stream_id, rx, action_tx.clone());
                let _ = accept_tx.send(stream);
            }
            FrameType::Data => {
                if let Some(tx) = streams.lock()
                    .expect("Mutex 不应被毒化 (streams)")
                    .get(&stream_id) {
                    let _ = tx.send(payload);
                }
            }
            FrameType::Close => {
                streams.lock()
                    .expect("Mutex 不应被毒化 (streams)")
                    .remove(&stream_id);
            }
            FrameType::Ping => {}
            FrameType::Pong => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn make_test_stream() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        duplex(65536)
    }

    #[tokio::test]
    async fn test_frame_read_write() {
        let (mut client, mut server) = make_test_stream();

        let mut buf = vec![0u8; MAX_FRAME_SIZE];

        // 写帧
        Mux::<tokio::io::DuplexStream>::write_frame_raw(
            &mut client,
            FrameType::Data,
            1,
            b"hello",
        )
        .await
        .unwrap();

        // 读帧
        let (ft, sid, payload) = Mux::<tokio::io::DuplexStream>::read_frame_raw(
            &mut server,
            &mut buf,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(ft, FrameType::Data);
        assert_eq!(sid, 1);
        assert_eq!(&payload, b"hello");
    }

    #[test]
    fn test_frame_type_from_u8() {
        assert_eq!(FrameType::from_u8(0x01), Some(FrameType::Open));
        assert_eq!(FrameType::from_u8(0x02), Some(FrameType::Data));
        assert_eq!(FrameType::from_u8(0x03), Some(FrameType::Close));
        assert_eq!(FrameType::from_u8(0x04), Some(FrameType::Ping));
        assert_eq!(FrameType::from_u8(0x05), Some(FrameType::Pong));
        assert_eq!(FrameType::from_u8(0xFF), None);
    }
}
