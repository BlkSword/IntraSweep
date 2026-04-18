//! NTLMv2 认证模块
//!
//! 提供完整的 NTLMSSP 协议实现，支持 NTLMv2 响应计算。
//! RDP (CredSSP/NLA) 和 WinRM (NTLM over HTTP) 共享此模块。

use hmac::{Hmac, Mac};
use md5::Md5;
use digest::Digest;

type HmacMd5 = Hmac<Md5>;

/// NTLMSSP 签名
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// NTLMSSP 消息类型
const MSG_TYPE_NEGOTIATE: u32 = 1;
const MSG_TYPE_CHALLENGE: u32 = 2;
const MSG_TYPE_AUTHENTICATE: u32 = 3;

/// NTLMSSP 协商标志
const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x00000001;
const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x00000200;
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x00008000;
const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x00080000;
const NTLMSSP_NEGOTIATE_IDENTIFY: u32 = 0x00100000;
const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x02000000;
const NTLMSSP_NEGOTIATE_128: u32 = 0x20000000;
const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x40000000;
const NTLMSSP_NEGOTIATE_56: u32 = 0x80000000;

/// NTLMSSP Type 2 Challenge 解析结果
#[derive(Debug)]
pub struct NtlmChallenge {
    /// 服务器挑战（8 字节）
    pub server_challenge: [u8; 8],
    /// 目标信息块
    pub target_info: Vec<u8>,
    /// 协商标志
    pub negotiate_flags: u32,
}

// ==================== NT Hash 计算 ====================

/// 计算 NT Hash: MD4(UTF-16LE(password))
pub fn nt_hash(password: &str) -> [u8; 16] {
    let utf16le: Vec<u8> = password.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    md4_hash(&utf16le)
}

/// 计算 NTLMv2 Hash: HMAC-MD5(NT_Hash, Unicode(uppercase(username) + domain))
pub fn ntlmv2_hash(nt_hash: &[u8], username: &str, domain: &str) -> [u8; 16] {
    let identity: Vec<u8> = format!("{}{}", username.to_uppercase(), domain.to_uppercase())
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut mac = HmacMd5::new_from_slice(nt_hash)
        .expect("HMAC key length is valid");
    mac.update(&identity);
    let result = mac.finalize().into_bytes();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// 计算 NTLMv2 响应
pub fn ntlmv2_response(
    ntlmv2_hash: &[u8],
    server_challenge: &[u8],
    target_info: &[u8],
) -> Vec<u8> {
    // 构造 blob
    let blob = build_ntlmv2_blob(target_info);

    // NTProofStr = HMAC-MD5(NTLMv2_Hash, ServerChallenge + Blob)
    let mut mac = HmacMd5::new_from_slice(ntlmv2_hash)
        .expect("HMAC key length is valid");
    mac.update(server_challenge);
    mac.update(&blob);
    let nt_proof_str = mac.finalize().into_bytes();

    // 响应 = NTProofStr + Blob
    let mut response = Vec::with_capacity(16 + blob.len());
    response.extend_from_slice(&nt_proof_str);
    response.extend_from_slice(&blob);
    response
}

/// 构造 NTLMv2 Blob
fn build_ntlmv2_blob(target_info: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(32 + target_info.len());

    // Blob 签名 (0x01010000)
    blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
    // 保留
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // 时间戳 (64-bit，从 1601-01-01 起的 100ns 间隔)
    let timestamp = get_nt_timestamp();
    blob.extend_from_slice(&timestamp.to_le_bytes());

    // Client Challenge (8 字节随机数)
    let client_challenge = generate_client_challenge();
    blob.extend_from_slice(&client_challenge);

    // 保留
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Target Info (从 Type 2 消息中获取)
    blob.extend_from_slice(target_info);

    // 末尾 Terminator
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    blob
}

/// 获取 Windows NT 时间戳（从 1601-01-01 UTC 起的 100 纳秒间隔数）
fn get_nt_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Unix epoch (1970) 到 NT epoch (1601) 的间隔: 11644473600 秒
    const EPOCH_DIFF_SECS: u64 = 11644473600;
    let nt_ticks = (duration.as_secs() + EPOCH_DIFF_SECS) * 10_000_000
        + duration.subsec_nanos() as u64 / 100;

    nt_ticks
}

/// 生成 8 字节 Client Challenge（使用简单随机数）
fn generate_client_challenge() -> [u8; 8] {
    use std::time::{SystemTime, UNIX_EPOCH};

    // 使用时间戳和计数器作为简易随机源
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let mut challenge = [0u8; 8];
    challenge[0..8].copy_from_slice(&ts.to_le_bytes()[0..8]);
    // 混入一些变化
    challenge[0] ^= challenge[4];
    challenge[1] ^= challenge[5];
    challenge[2] ^= challenge[6];
    challenge[3] ^= challenge[7];

    challenge
}

// ==================== NTLMSSP 消息构建/解析 ====================

/// 构建 NTLMSSP Type 1 (Negotiate) 消息
pub fn build_type1(hostname: &str, domain: &str) -> Vec<u8> {
    let flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56;

    let hostname_upper = hostname.to_uppercase();
    let domain_upper = domain.to_uppercase();

    let hostname_bytes: Vec<u8> = hostname_upper.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let domain_bytes: Vec<u8> = domain_upper.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // 消息结构: 签名(8) + 类型(4) + 标志(4) + 域名安全缓冲(8) + 主机名安全缓冲(8) + 数据
    let data_offset = 32 + domain_bytes.len() + hostname_bytes.len();
    let mut msg = Vec::with_capacity(data_offset);

    // 签名
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    // 消息类型
    msg.extend_from_slice(&MSG_TYPE_NEGOTIATE.to_le_bytes());
    // 标志
    msg.extend_from_slice(&flags.to_le_bytes());

    // 域名安全缓冲 (length, allocated, offset)
    let domain_offset = 32u16;
    msg.extend_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&domain_offset.to_le_bytes());

    // 主机名安全缓冲
    let host_offset = (32 + domain_bytes.len()) as u16;
    msg.extend_from_slice(&(hostname_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(hostname_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&host_offset.to_le_bytes());

    // 数据
    msg.extend_from_slice(&domain_bytes);
    msg.extend_from_slice(&hostname_bytes);

    msg
}

/// 解析 NTLMSSP Type 2 (Challenge) 消息
pub fn parse_type2(data: &[u8]) -> Result<NtlmChallenge, String> {
    if data.len() < 48 {
        return Err("Type 2 消息太短".to_string());
    }

    // 验证签名
    if &data[0..8] != NTLMSSP_SIGNATURE {
        return Err("无效的 NTLMSSP 签名".to_string());
    }

    // 验证消息类型
    let msg_type = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4]));
    if msg_type != MSG_TYPE_CHALLENGE {
        return Err(format!("期望 Type 2 消息，收到类型 {}", msg_type));
    }

    // 读取协商标志
    let negotiate_flags = u32::from_le_bytes(data[12..16].try_into().unwrap_or([0; 4]));

    // 读取服务器挑战 (offset 24, 8 字节)
    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&data[24..32]);

    // 读取 Target Info 安全缓冲 (offset 40, length at 40, offset at 44)
    let target_info = if data.len() >= 48 {
        let ti_len = u16::from_le_bytes(data[40..42].try_into().unwrap_or([0; 2])) as usize;
        let ti_offset = u16::from_le_bytes(data[44..46].try_into().unwrap_or([0; 2])) as usize;

        if ti_offset + ti_len <= data.len() {
            data[ti_offset..ti_offset + ti_len].to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok(NtlmChallenge {
        server_challenge,
        target_info,
        negotiate_flags,
    })
}

/// 构建 NTLMSSP Type 3 (Authenticate) 消息
pub fn build_type3(
    username: &str,
    password: &str,
    domain: &str,
    hostname: &str,
    challenge: &NtlmChallenge,
) -> Vec<u8> {
    // 计算 NT 响应
    let nt_h = nt_hash(password);
    let ntlmv2_h = ntlmv2_hash(&nt_h, username, domain);
    let nt_response = ntlmv2_response(&ntlmv2_h, &challenge.server_challenge, &challenge.target_info);

    // LM 响应 (NTLMv2 中 LM 响应为 8 字节零 + client challenge，或直接空)
    let lm_response = vec![0u8; 24];

    let flags = challenge.negotiate_flags
        | NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_NTLM;

    // Unicode 编码
    let domain_upper = domain.to_uppercase();
    let username_upper = username; // 用户名保留原始大小写
    let hostname_upper = hostname.to_uppercase();

    let domain_bytes: Vec<u8> = domain_upper.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let username_bytes: Vec<u8> = username_upper.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let hostname_bytes: Vec<u8> = hostname_upper.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // 消息头部: 签名(8) + 类型(4) + LM缓冲(8) + NT缓冲(8) + 域名缓冲(8) + 用户名缓冲(8) + 主机名缓冲(8) + 会话缓冲(8) + 标志(4) = 64
    let header_len = 64usize;
    let data_offset = header_len
        + lm_response.len()
        + nt_response.len()
        + domain_bytes.len()
        + username_bytes.len()
        + hostname_bytes.len();

    let mut msg = Vec::with_capacity(data_offset);

    // 签名
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    // 消息类型
    msg.extend_from_slice(&MSG_TYPE_AUTHENTICATE.to_le_bytes());

    // LM Response 安全缓冲
    let mut offset = header_len as u16;
    append_security_buffer(&mut msg, &lm_response, &mut offset);

    // NT Response 安全缓冲
    append_security_buffer(&mut msg, &nt_response, &mut offset);

    // 域名安全缓冲
    append_security_buffer(&mut msg, &domain_bytes, &mut offset);

    // 用户名安全缓冲
    append_security_buffer(&mut msg, &username_bytes, &mut offset);

    // 主机名安全缓冲
    append_security_buffer(&mut msg, &hostname_bytes, &mut offset);

    // 会话密钥安全缓冲 (空)
    append_security_buffer(&mut msg, &[], &mut offset);

    // 标志
    msg.extend_from_slice(&flags.to_le_bytes());

    // 数据部分
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);
    msg.extend_from_slice(&domain_bytes);
    msg.extend_from_slice(&username_bytes);
    msg.extend_from_slice(&hostname_bytes);

    msg
}

/// 附加安全缓冲描述符 (length, allocated, offset) + 数据
fn append_security_buffer(msg: &mut Vec<u8>, data: &[u8], offset: &mut u16) {
    msg.extend_from_slice(&(data.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(data.len() as u16).to_le_bytes());
    msg.extend_from_slice(&offset.to_le_bytes());
    *offset += data.len() as u16;
}

// ==================== TSRequest (CredSSP) ASN.1 编解码 ====================

/// 编码 CredSSP TSRequest (ASN.1 DER)
///
/// TSRequest ::= SEQUENCE {
///     version    [0] INTEGER,
///     negoTokens [1] SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING } OPTIONAL,
/// }
pub fn encode_ts_request(version: u32, nego_token: &[u8]) -> Vec<u8> {
    // 内层 OCTET STRING 包裹 negoToken
    let nego_token_octet_string = der_wrap(0x04, nego_token);
    // [0] EXPLICIT 包裹
    let nego_token_wrapped = der_wrap(0xA0, &nego_token_octet_string);
    // SEQUENCE 包裹
    let nego_token_seq_inner = der_wrap(0x30, &nego_token_wrapped);
    let nego_token_seq_outer = der_wrap(0x30, &nego_token_seq_inner);
    // [1] EXPLICIT 包裹
    let nego_tokens = der_wrap(0xA1, &nego_token_seq_outer);

    // version [0] EXPLICIT INTEGER
    let version_bytes = if version < 128 {
        vec![0x02, 0x01, version as u8]
    } else {
        vec![0x02, 0x02, (version >> 8) as u8, (version & 0xFF) as u8]
    };
    let version_wrapped = der_wrap(0xA0, &version_bytes);

    // 最外层 SEQUENCE
    let mut inner = Vec::new();
    inner.extend_from_slice(&version_wrapped);
    inner.extend_from_slice(&nego_tokens);

    der_wrap(0x30, &inner)
}

/// 解码 CredSSP TSRequest，提取 negoToken
pub fn decode_ts_request(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("空的 TSRequest 数据".to_string());
    }

    // 查找 [1] negoTokens 标签 (0xA1)
    let mut pos = 0;
    while pos < data.len() {
        if data[pos] == 0xA1 {
            // 找到 negoTokens
            let (_, content_start) = der_read_length(&data[pos + 1..])?;
            let nego_tokens_data = &data[pos + 1 + content_start.0..];

            // 跳过外层 SEQUENCE
            if nego_tokens_data.is_empty() || nego_tokens_data[0] != 0x30 {
                return Err("期望 SEQUENCE".to_string());
            }
            let (_, seq_start) = der_read_length(&nego_tokens_data[1..])?;
            let seq_data = &nego_tokens_data[1 + seq_start.0..];

            // 跳过内层 SEQUENCE
            if seq_data.is_empty() || seq_data[0] != 0x30 {
                return Err("期望内层 SEQUENCE".to_string());
            }
            let (_, inner_start) = der_read_length(&seq_data[1..])?;
            let inner_data = &seq_data[1 + inner_start.0..];

            // 跳过 [0] 标签
            if inner_data.is_empty() || inner_data[0] != 0xA0 {
                return Err("期望 [0] OCTET STRING 标签".to_string());
            }
            let (_, a0_start) = der_read_length(&inner_data[1..])?;
            let octet_data = &inner_data[1 + a0_start.0..];

            // 读取 OCTET STRING
            if octet_data.is_empty() || octet_data[0] != 0x04 {
                return Err("期望 OCTET STRING".to_string());
            }
            let (len_info, str_start) = der_read_length(&octet_data[1..])?;
            return Ok(octet_data[1 + str_start.0..1 + str_start.0 + len_info.1].to_vec());
        }
        pos += 1;
    }

    Err("未找到 negoToken".to_string())
}

/// DER 编码包裹
fn der_wrap(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(2 + data.len());
    result.push(tag);
    der_write_length(&mut result, data.len());
    result.extend_from_slice(data);
    result
}

/// DER 写入长度
fn der_write_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push(((len >> 8) & 0xFF) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

/// DER 读取长度，返回 (LengthInfo { bytes_consumed, length }, data_start_offset)
fn der_read_length(data: &[u8]) -> Result<(LengthInfo, LengthInfo), String> {
    if data.is_empty() {
        return Err("数据为空".to_string());
    }

    let first = data[0];
    if first < 128 {
        Ok((
            LengthInfo { consumed: 1, value: first as usize },
            LengthInfo { consumed: 1, value: first as usize },
        ))
    } else if first == 0x81 {
        if data.len() < 2 {
            return Err("长度字段不完整".to_string());
        }
        Ok((
            LengthInfo { consumed: 2, value: data[1] as usize },
            LengthInfo { consumed: 2, value: data[1] as usize },
        ))
    } else if first == 0x82 {
        if data.len() < 3 {
            return Err("长度字段不完整".to_string());
        }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Ok((
            LengthInfo { consumed: 3, value: len },
            LengthInfo { consumed: 3, value: len },
        ))
    } else {
        Err(format!("不支持的 DER 长度格式: 0x{:02X}", first))
    }
}

struct LengthInfo {
    consumed: usize,
    value: usize,
}

// ==================== MD4 哈希自实现 ====================

/// MD4 哈希函数（RFC 1320）
///
/// 用于 NTLM 的 NT Hash 计算。 crates.io 上没有官方 MD4 crate，因此自行实现。
fn md4_hash(input: &[u8]) -> [u8; 16] {
    // 填充
    let mut data = input.to_vec();
    let bit_len = (input.len() as u64) * 8;

    // 追加 0x80
    data.push(0x80);

    // 填充到 56 mod 64 字节
    while data.len() % 64 != 56 {
        data.push(0);
    }

    // 追加原始长度 (little-endian, 64-bit)
    data.extend_from_slice(&bit_len.to_le_bytes());

    // 初始状态
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xEFCDAB89;
    let mut c: u32 = 0x98BADCFE;
    let mut d: u32 = 0x10325476;

    // 处理每个 64 字节块
    for chunk in data.chunks_exact(64) {
        let m: [u32; 16] = std::array::from_fn(|i| {
            u32::from_le_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]])
        });

        let (aa, bb, cc, dd) = (a, b, c, d);

        // Round 1
        for i in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            a = a.wrapping_add(f(b, c, d)).wrapping_add(m[i]);
            a = rotate_left(a, if i % 4 == 0 { 3 } else if i % 4 == 1 { 7 } else if i % 4 == 2 { 11 } else { 19 });
            let tmp = d; d = c; c = b; b = a; a = tmp;
        }

        // Round 2
        for i in [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15] {
            a = a.wrapping_add(g(b, c, d)).wrapping_add(m[i]).wrapping_add(0x5A827999);
            a = rotate_left(a, if [0, 4, 8, 12].contains(&i) { 3 } else if [1, 5, 9, 13].contains(&i) { 5 } else if [2, 6, 10, 14].contains(&i) { 9 } else { 13 });
            let tmp = d; d = c; c = b; b = a; a = tmp;
        }

        // Round 3
        for i in [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15] {
            a = a.wrapping_add(h(b, c, d)).wrapping_add(m[i]).wrapping_add(0x6ED9EBA1);
            a = rotate_left(a, if i == 0 || i == 4 || i == 8 || i == 12 { 3 } else if i == 2 || i == 6 || i == 10 || i == 14 { 9 } else { 11 });
            let tmp = d; d = c; c = b; b = a; a = tmp;
        }

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a.to_le_bytes());
    result[4..8].copy_from_slice(&b.to_le_bytes());
    result[8..12].copy_from_slice(&c.to_le_bytes());
    result[12..16].copy_from_slice(&d.to_le_bytes());
    result
}

#[inline]
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline]
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[inline]
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline]
fn rotate_left(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_hash_empty() {
        // 空密码的 NT Hash 已知向量
        let hash = nt_hash("");
        let expected: [u8; 16] = [
            0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31,
            0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0,
        ];
        assert_eq!(hash, expected, "空密码 NT Hash 不匹配");
    }

    #[test]
    fn test_nt_hash_password() {
        let hash = nt_hash("password");
        let expected: [u8; 16] = [
            0x88, 0x46, 0xF7, 0xEA, 0xEE, 0x8F, 0xB1, 0x17,
            0xAD, 0x06, 0xBD, 0xD8, 0x30, 0xB7, 0x58, 0x6C,
        ];
        assert_eq!(hash, expected, "\"password\" NT Hash 不匹配");
    }

    #[test]
    fn test_nt_hash_securesecret() {
        let hash = nt_hash("SecREt01");
        let expected: [u8; 16] = [
            0xCD, 0xED, 0xBA, 0x41, 0x87, 0x0C, 0x47, 0xA7,
            0x49, 0x2F, 0x2D, 0x1E, 0x92, 0x34, 0x4D, 0x3B,
        ];
        assert_eq!(hash, expected, "\"SecREt01\" NT Hash 不匹配");
    }

    #[test]
    fn test_build_type1_basic() {
        let msg = build_type1("workstation", "domain");
        // 验证签名
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        // 验证类型
        let msg_type = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(msg_type, MSG_TYPE_NEGOTIATE);
    }

    #[test]
    fn test_parse_type2_valid() {
        // 构造一个最小的 Type 2 消息
        let mut msg = Vec::new();
        msg.extend_from_slice(NTLMSSP_SIGNATURE);  // 签名
        msg.extend_from_slice(&MSG_TYPE_CHALLENGE.to_le_bytes());  // 类型
        msg.extend_from_slice(&[0u8; 4]);  // 目标名安全缓冲
        let mut flags = [0u8; 4];
        flags[0] = 0x01; // NTLMSSP_NEGOTIATE_UNICODE
        msg.extend_from_slice(&flags);  // 标志
        msg.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // 挑战
        msg.extend_from_slice(&[0u8; 8]);  // 保留
        msg.extend_from_slice(&[0u8; 8]);  // 目标信息安全缓冲 (空)
        msg.extend_from_slice(&[0u8; 8]);  // 版本等

        let result = parse_type2(&msg).unwrap();
        assert_eq!(result.server_challenge, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_parse_type2_invalid_signature() {
        let msg = vec![0u8; 48];
        let result = parse_type2(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_type2_too_short() {
        let msg = vec![0u8; 20];
        let result = parse_type2(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_ts_request_roundtrip() {
        let token = b"test_nego_token_data";
        let encoded = encode_ts_request(2, token);
        let decoded = decode_ts_request(&encoded).unwrap();
        assert_eq!(decoded, token);
    }

    #[test]
    fn test_der_wrap() {
        let data = b"hello";
        let wrapped = der_wrap(0x04, data);
        assert_eq!(wrapped[0], 0x04); // tag
        assert_eq!(wrapped[1], 5); // length
        assert_eq!(&wrapped[2..7], data);
    }

    #[test]
    fn test_ntlmv2_response_not_empty() {
        let nt_h = nt_hash("password");
        let ntlmv2_h = ntlmv2_hash(&nt_h, "user", "DOMAIN");
        let server_challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let target_info = vec![
            0x02, 0x00, 0x0C, 0x00,  // AvPair: NetBIOS domain name
            0x44, 0x00, 0x4F, 0x00, 0x4D, 0x00, 0x41, 0x00,
            0x49, 0x00, 0x4E, 0x00,
            0x00, 0x00, 0x00, 0x00,  // AvPair terminator
        ];
        let response = ntlmv2_response(&ntlmv2_h, &server_challenge, &target_info);
        // NTProofStr (16 bytes) + Blob
        assert!(response.len() > 16);
    }

    #[test]
    fn test_build_type3_full() {
        let challenge = NtlmChallenge {
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
            target_info: vec![0x00, 0x00, 0x00, 0x00], // 最小 target info
            negotiate_flags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM,
        };

        let msg = build_type3("user", "password", "DOMAIN", "WORKSTATION", &challenge);

        // 验证签名
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        // 验证类型
        let msg_type = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(msg_type, MSG_TYPE_AUTHENTICATE);
    }
}
