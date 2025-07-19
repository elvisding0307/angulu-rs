use std::hash::Hasher as _;
// crc32fast和crc32c是两个库，要注意区分
use crc32c::Crc32cHasher as ExCrc32cHasher;
use crc32fast::Hasher as Crc32FastHasher;

use crate::hash::HasherTrait;
use crate::*;

pub const CRC32_OUTPUT_LENGTH: usize = 4;

/// CRC32 哈希实现
pub struct Crc32Hasher {
    m_hasher: Crc32FastHasher,
}

impl Default for Crc32Hasher {
    /// 创建新的 Crc32Hasher
    fn default() -> Self {
        Crc32Hasher {
            m_hasher: Crc32FastHasher::new(),
        }
    }
}

impl HasherTrait for Crc32Hasher {
    const OUTPUT_LENGTH: usize = CRC32_OUTPUT_LENGTH;

    fn update_message(&mut self, message: &str) {
        self.m_hasher.update(message.as_bytes());
    }

    fn update_bytes(&mut self, vec: &[u8]) {
        self.m_hasher.update(vec);
    }

    fn finalize(&self) -> ByteVector {
        let checksum = self.m_hasher.clone().finalize();
        let checksum_bytes = checksum.to_le_bytes();
        checksum_bytes.to_vec()
    }
}

/// CRC32c 哈希实现
pub struct Crc32cHasher {
    m_hasher: ExCrc32cHasher,
}

impl Default for Crc32cHasher {
    /// 创建新的 Crc32Hasher
    fn default() -> Self {
        Crc32cHasher {
            m_hasher: ExCrc32cHasher::default(),
        }
    }
}

impl HasherTrait for Crc32cHasher {
    const OUTPUT_LENGTH: usize = CRC32_OUTPUT_LENGTH;

    fn update_message(&mut self, message: &str) {
        self.m_hasher.write(message.as_bytes());
    }

    fn update_bytes(&mut self, vec: &[u8]) {
        self.m_hasher.write(vec);
    }

    fn finalize(&self) -> ByteVector {
        let checksum = self.m_hasher.finish() as u32;
        let checksum_bytes = checksum.to_le_bytes();
        checksum_bytes.to_vec()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::encoding::hex::HexEncoding;
    use crate::encoding::EncodingTrait;

    #[test]
    fn test_crc32_operation() {
        let hexe = HexEncoding::default();
        let mut crc32_hasher = Crc32Hasher::default();
        // 123456
        crc32_hasher.update_message("123456");
        let res = crc32_hasher.finalize();
        let res = hexe.encode(&res);
        assert_eq!("61D37209".to_string(), res);
        // 12345678910
        crc32_hasher.update_message("78910");
        let res = crc32_hasher.finalize();
        let res = hexe.encode(&res);
        assert_eq!("39E5863D".to_string(), res);
    }

    #[test]
    fn test_crc32c_operation() {
        let hexe = HexEncoding::default();
        let mut crc32c_hasher = Crc32cHasher::default();
        // 123456
        crc32c_hasher.update_message("123456");
        let res = crc32c_hasher.finalize();
        let res = hexe.encode(&res);
        assert_eq!("86713541".to_string(), res);
        // 12345678910
        crc32c_hasher.update_message("78910");
        let res = crc32c_hasher.finalize();
        let res = hexe.encode(&res);
        assert_eq!("1189D92E".to_string(), res);
    }
}
