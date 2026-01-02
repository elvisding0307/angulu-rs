use ring::digest;
use ring::digest::SHA512_OUTPUT_LEN;

use crate::hash::HasherTrait;
use crate::*;

pub const SHA512_OUTPUT_LENGTH: usize = SHA512_OUTPUT_LEN;

/// Sha1哈希操作
pub struct Sha512Hasher {
    m_ctx: digest::Context,
}

impl Default for Sha512Hasher {
    fn default() -> Sha512Hasher {
        Sha512Hasher {
            m_ctx: digest::Context::new(&digest::SHA512),
        }
    }
}

impl HasherTrait for Sha512Hasher {
    const OUTPUT_LENGTH: usize = SHA512_OUTPUT_LENGTH;

    /// 计算一个消息的哈希值
    fn update_message(&mut self, message: &str) -> () {
        self.m_ctx.update(message.as_bytes());
    }
    /// 计算一个字节数组的哈希值
    fn update_bytes(&mut self, vec: &[u8]) -> () {
        self.m_ctx.update(vec);
    }
    /// 获取结果
    fn finalize(&self) -> ByteVector {
        let res = self.m_ctx.clone().finish();
        // 获取引用的结果
        let ref_res = res.as_ref();
        let mut res = vec![0u8; Self::OUTPUT_LENGTH];
        for i in 0..SHA512_OUTPUT_LENGTH {
            res[i] = ref_res[i];
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::EncodingTrait;
    use crate::encoding::hex::HexEncoding;

    #[test]
    fn test_sha512_operation() {
        let hexe = HexEncoding::default();
        let mut sha512_hasher = Sha512Hasher::default();
        // 123456
        sha512_hasher.update_message("123456");
        let res = sha512_hasher.finalize();
        let res = hexe.encode(&res);
        assert_eq!(
            "BA3253876AED6BC22D4A6FF53D8406C6AD864195ED144AB5C87621B6C233B548BAEAE6956DF346EC8C17F5EA10F35EE3CBC514797ED7DDD3145464E2A0BAB413".to_string(),
            res
        );
        // 12345678910
        sha512_hasher.update_message("78910");
        let res = sha512_hasher.finalize();
        let res = hexe.encode(&res);
        assert_eq!(
            "16D4074E1A1F081538A09B801586DA6881E547DEF93E643E4BAC5195D9EF14ECB45D636F34C7CD166408DE6CB2ED987D3E53212E3AD12A597CAC49E5B64197AB".to_string(),
            res
        );
    }
}
