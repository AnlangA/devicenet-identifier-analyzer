//! AI 配置的本地加密存储。
//!
//! 目标：把 `api_key` 等敏感字段以密文形式交给 eframe 的 `Storage`，避免明文落盘。
//!
//! 设计要点：
//! - 对称加密使用 `ring::aead::AES_256_GCM`（AEAD 同时保证机密性与完整性）。
//! - 密钥从机器绑定信息（用户名 + 主机名 + 应用标识）派生，让密文与当前用户/机器绑定；
//!   这无法抵御拥有该账户的攻击者，但能防止配置文件被复制到其他机器后被直接读取。
//! - 存储格式：`base64(nonce(12B) || ciphertext_with_tag)`。
//!
//! 局限性：这是离线加密，不是系统凭据管理器（如 Windows Credential Manager）。
//! 如果对安全性有更高要求，可改用 `keyring` crate 把密钥交给操作系统托管。

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::digest::{Context, SHA256};
use ring::rand::{SecureRandom, SystemRandom};

/// 应用绑定的盐，混入密钥派生，避免与其他使用相同派生策略的应用撞车。
const KEY_SALT: &[u8] = b"devicenet-identifier-analyzer/v1/ai-config";

/// AES-256-GCM 的 nonce 长度（固定 12 字节）。
const NONCE_LEN: usize = 12;

/// 加密一段 UTF-8 明文，返回 Base64 编码的 `nonce || ciphertext||tag`。
///
/// 出错时返回 `None` 而不是 panic，让调用方按「无配置」处理。
pub(crate) fn encrypt(plaintext: &str) -> Option<String> {
    let rng = SystemRandom::new();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes).ok()?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let key = derive_key()?;
    let less_safe_key = less_safe_key_from_bytes(&key)?;

    let mut in_out = plaintext.as_bytes().to_vec();
    less_safe_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .ok()?;

    let mut bundle = Vec::with_capacity(NONCE_LEN + in_out.len());
    bundle.extend_from_slice(&nonce_bytes);
    bundle.extend_from_slice(&in_out);

    Some(BASE64.encode(&bundle))
}

/// 解密 `encrypt()` 产生的 Base64 字符串，返回 UTF-8 明文。
///
/// 任何环节失败（格式错误、密钥不匹配、tag 校验失败等）都返回 `None`，
/// 调用方应当回退到默认配置，相当于「无保存配置」。
pub(crate) fn decrypt(encoded: &str) -> Option<String> {
    let bundle = BASE64.decode(encoded).ok()?;

    // AES-256-GCM 的 tag 长度由算法常量提供。
    let tag_len = AES_256_GCM.tag_len();
    if bundle.len() <= NONCE_LEN + tag_len {
        return None;
    }

    let nonce_bytes: [u8; NONCE_LEN] = bundle[..NONCE_LEN].try_into().ok()?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let key = derive_key()?;
    let less_safe_key = less_safe_key_from_bytes(&key)?;

    let mut ciphertext = bundle[NONCE_LEN..].to_vec();
    let plaintext = less_safe_key
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .ok()?;

    String::from_utf8(plaintext.to_vec()).ok()
}

/// 从机器绑定信息派生 32 字节的 AES-256 密钥。
///
/// 采集 `USERNAME` 与 `COMPUTERNAME` / `HOSTNAME` 作为机器绑定输入；
/// 缺失任何一个不会失败（用空串替代），只是绑定强度下降。
fn derive_key() -> Option<[u8; 32]> {
    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();
    let machine = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default();

    let mut ctx = Context::new(&SHA256);
    ctx.update(KEY_SALT);
    ctx.update(username.as_bytes());
    ctx.update(machine.as_bytes());

    // 迭代 4096 轮增加暴力破解成本（类 PBKDF2 思路，但保持依赖最小）。
    let mut digest = ctx.finish();
    for _ in 0..4096 {
        let mut ctx = Context::new(&SHA256);
        ctx.update(digest.as_ref());
        ctx.update(KEY_SALT);
        digest = ctx.finish();
    }

    let key: [u8; 32] = digest.as_ref().try_into().ok()?;
    Some(key)
}

/// 从 32 字节原始密钥构造用于加解密的 `LessSafeKey`。
/// `ring::aead` 要求先用 `UnboundKey::new` 绑定算法，再转成 `LessSafeKey`。
fn less_safe_key_from_bytes(key: &[u8; 32]) -> Option<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).ok()?;
    Some(LessSafeKey::new(unbound))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let plaintext = "sk-test-api-key-1234567890-中文字符";
        let encoded = encrypt(plaintext).expect("encrypt should succeed");
        assert_ne!(encoded, plaintext);
        let decoded = decrypt(&encoded).expect("decrypt should succeed");
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn decrypt_rejects_garbage_input() {
        assert_eq!(decrypt("not-valid-base64!!!"), None);
        assert_eq!(decrypt(&BASE64.encode(b"too-short")), None);
    }

    #[test]
    fn each_encryption_uses_unique_nonce() {
        let plaintext = "same-input";
        let a = encrypt(plaintext).expect("encrypt a");
        let b = encrypt(plaintext).expect("encrypt b");
        // nonce 随机 -> 同明文也会产生不同密文。
        assert_ne!(a, b);
        assert_eq!(decrypt(&a).unwrap(), plaintext);
        assert_eq!(decrypt(&b).unwrap(), plaintext);
    }
}
