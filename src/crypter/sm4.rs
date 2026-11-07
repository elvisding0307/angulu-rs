use gm_sm4::Sm4Cipher;

use crate::crypter::{
    CipherAlgorithmBaseTrait, CipherAlgorithmTrait, CipherAlgorithmType, IVKeyNewTrait,
};

use crate::*;

/// SM4的IV长度
pub const SM4_IV_LENGTH: usize = 16;
/// SM4的Key长度
pub const SM4_KEY_LENGTH: usize = 16;
/// SM4的分组长度
pub const SM4_BLOCK_LENGTH: usize = 16;

/// SM4密码算法，使用OFB模式；加密和解密使用相同的crypt操作。
pub struct Sm4CipherAlgorithm {
    m_cipher: Sm4Cipher,
    m_iv: [u8; SM4_IV_LENGTH],
    m_prev_block: [u8; SM4_IV_LENGTH],
}

impl CipherAlgorithmBaseTrait for Sm4CipherAlgorithm {
    const IV_LENGTH: usize = SM4_IV_LENGTH;
    const KEY_LENGTH: usize = SM4_KEY_LENGTH;
    const CIPHER_ALGORITHM_TYPE: CipherAlgorithmType = CipherAlgorithmType::Block(SM4_BLOCK_LENGTH);
}

impl CipherAlgorithmTrait for Sm4CipherAlgorithm {
    fn crypt(&mut self, src_data: &[u8], dst_data: &mut [u8]) -> Result<()> {
        if src_data.len() != dst_data.len() {
            return Err(CrypterError::CryptionFailed.into());
        }

        if src_data.len() % SM4_BLOCK_LENGTH != 0 {
            return Err(CrypterError::CryptionFailed.into());
        }

        // 使用保存的prev_block状态，而不是每次都重置为IV
        let mut prev_block = self.m_prev_block;

        for (src_chunk, dst_chunk) in src_data
            .chunks_exact(SM4_BLOCK_LENGTH)
            .zip(dst_data.chunks_exact_mut(SM4_BLOCK_LENGTH))
        {
            // 加密上一个密钥流分组，再与输入异或。
            let encrypted = self
                .m_cipher
                .encrypt(&prev_block)
                .map_err(|_| CrypterError::CryptionFailed)?;

            for i in 0..SM4_BLOCK_LENGTH {
                dst_chunk[i] = src_chunk[i] ^ encrypted[i];
            }
            prev_block.copy_from_slice(&encrypted);
        }

        // 保存最后一个密钥流分组作为下次调用的prev_block
        self.m_prev_block = prev_block;

        Ok(())
    }
}

impl IVKeyNewTrait for Sm4CipherAlgorithm {
    fn new(iv: &[u8], key: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        if iv.len() != Self::IV_LENGTH {
            return Err(CrypterError::InvalidIVLength.into());
        }
        if key.len() != Self::KEY_LENGTH {
            return Err(CrypterError::InvalidKeyLength.into());
        }

        let cipher = Sm4Cipher::new(key).map_err(|_| CrypterError::CryptionFailed)?;

        let mut iv_array = [0u8; SM4_IV_LENGTH];
        iv_array.copy_from_slice(iv);

        Ok(Sm4CipherAlgorithm {
            m_cipher: cipher,
            m_iv: iv_array,
            // 初始化时，prev_block设置为IV
            m_prev_block: iv_array,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypter::{
        StreamGenerator, StreamGeneratorMode, StreamGeneratorTrait, StringCrypter,
        StringCrypterTrait,
    };

    #[test]
    fn test_sm4() {
        let string_crypter = StringCrypter::<Sm4CipherAlgorithm>::default();
        let ciphertext = string_crypter
            .encrypt("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", "qwerty")
            .unwrap();
        println!("ciphertext: {ciphertext}");
        let plaintext = string_crypter.decrypt(&ciphertext, "qwerty").unwrap();
        println!("plaintext: {plaintext}");
        assert_eq!(plaintext, "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

    #[test]
    fn test_sm4_long_string() {
        let string_crypter = StringCrypter::<Sm4CipherAlgorithm>::default();

        // 优化后的字符串生成过程
        let pattern = "1234567890abcdefghij";
        let target_length = 10_000;

        // 计算需要重复的完整次数和剩余字符数
        let full_repeats = target_length / pattern.len();
        let remainder = target_length % pattern.len();

        // 使用repeat方法生成完整重复部分，然后添加剩余部分
        let test_string = if remainder == 0 {
            pattern.repeat(full_repeats)
        } else {
            format!("{}{}", pattern.repeat(full_repeats), &pattern[..remainder])
        };

        println!("测试字符串长度: {}", test_string.len());

        // 加密
        let ciphertext = string_crypter.encrypt(&test_string, "qwerty").unwrap();
        println!("密文长度: {}", ciphertext.len());
        println!("密文: {}", &ciphertext[..]);

        // 解密
        let plaintext = string_crypter.decrypt(&ciphertext, "qwerty").unwrap();
        println!("解密后字符串长度: {}", plaintext.len());

        // 验证加密解密后是否相等
        assert_eq!(plaintext, test_string);
        println!("SM4长字符串加密解密测试通过！");
    }

    #[test]
    fn test_sm4_string() {
        let crypter = StringCrypter::<Sm4CipherAlgorithm>::default();
        assert_eq!(
            crypter
                .decrypt("9PL2/F6R7XjwFLDHhZpbA+I7+vtwJ8GmgcvaaWgK6g==", "123456")
                .unwrap(),
            "ABCDEFGHIJK"
        );
        assert_eq!(
            crypter
                .decrypt(
                    "Ncu6ITby0ijTyvLwTcbka20hj0O5B/zUekzyO6vNcoDvfcIlVazpivQ6PDOUM04m4RhkUDg=",
                    "qwerty"
                )
                .unwrap(),
            "original SM4 algorithm ciphertext"
        );
    }

    #[test]
    fn test_sm4_crypt() {
        let iv: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (16..32).collect();
        let plain: Vec<u8> = (0..32).map(|i| (i * 3 + 1) as u8).collect();
        let mut cipher = Sm4CipherAlgorithm::new(&iv, &key).unwrap();
        let mut encrypted = vec![0; 32];
        cipher.crypt(&plain, &mut encrypted).unwrap();
        assert_eq!(
            hex::encode_upper(&encrypted),
            "BBABF901BA82FBFD1AC19D5B32C5C17EC04CAFCFF2EF3776B3AEF11D71A926D7"
        );

        let mut decrypted = vec![0; 32];
        Sm4CipherAlgorithm::new(&iv, &key)
            .unwrap()
            .crypt(&encrypted, &mut decrypted)
            .unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_sm4_stream_generator() {
        let iv: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (16..32).collect();
        let mut stream =
            StreamGenerator::<Sm4CipherAlgorithm>::new(&iv, &key, StreamGeneratorMode::Short)
                .unwrap();
        assert_eq!(
            hex::encode_upper(stream.generate(32).unwrap()),
            "BAAFFE0BB792E8EB03DD827917EDEA50F17898F5CFAF7430FAE2BE4F24F17D89"
        );
    }

    #[test]
    fn test_sm4_boundaries() {
        let iv = [0; SM4_IV_LENGTH];
        let key = [0; SM4_KEY_LENGTH];
        for len in [0, SM4_IV_LENGTH - 1, SM4_IV_LENGTH + 1] {
            assert!(Sm4CipherAlgorithm::new(&vec![0; len], &key).is_err());
        }
        for len in [0, SM4_KEY_LENGTH - 1, SM4_KEY_LENGTH + 1] {
            assert!(Sm4CipherAlgorithm::new(&iv, &vec![0; len]).is_err());
        }

        let mut cipher = Sm4CipherAlgorithm::new(&iv, &key).unwrap();
        assert!(cipher.crypt(&[], &mut []).is_ok());
        assert!(cipher.crypt(&[0; 16], &mut [0; 15]).is_err());
        assert!(cipher.crypt(&[0; 16], &mut [0; 17]).is_err());
        assert!(cipher.crypt(&[0; 15], &mut [0; 15]).is_err());
        assert!(cipher.crypt(&[0; 17], &mut [0; 17]).is_err());

        // 两次完整分组调用应与一次处理两个分组一致；失败调用不应推进状态。
        let plain = [1; 32];
        let mut split = [0; 32];
        cipher.crypt(&plain[..16], &mut split[..16]).unwrap();
        cipher.crypt(&[], &mut []).unwrap();
        cipher.crypt(&plain[16..], &mut split[16..]).unwrap();
        let mut whole = [0; 32];
        Sm4CipherAlgorithm::new(&iv, &key)
            .unwrap()
            .crypt(&plain, &mut whole)
            .unwrap();
        assert_eq!(split, whole);
    }
}
