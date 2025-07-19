pub mod crc;
pub mod sha1;
pub mod sha256;
pub mod sha512;

use crate::*;

/// 所有支持的哈希算法
pub enum HashAlgorithm {
    Crc32,
    Crc32c,
    Sha1,
    Sha256,
    Sha512,
}

/// 哈希操作
pub trait HasherTrait {
    const OUTPUT_LENGTH: usize;

    /// 计算一个消息的哈希值
    fn update_message(&mut self, message: &str) -> ();
    /// 计算一个字节数组的哈希值
    fn update_bytes(&mut self, vec: &[u8]) -> ();
    /// 获取结果
    fn finalize(&self) -> ByteVector;
}
