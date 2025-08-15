use ::chacha20::cipher::{KeyIvInit, StreamCipher};
use ::chacha20::ChaCha20 as ExChaCha20;

use crate::crypter::{
    CipherAlgorithmBaseTrait, CipherAlgorithmTrait, CipherAlgorithmType, IVKeyNewTrait,
};

use crate::*;

/// ChaCha20的IV长度
pub const CHACHA20_IV_LENGTH: usize = 12;
/// ChaCha20的Key长度
pub const CHACHA20_KEY_LENGTH: usize = 32;

/// ChaCha20密码算法
pub struct ChaCha20CipherAlgorithm {
    m_algo: ExChaCha20,
}

impl CipherAlgorithmBaseTrait for ChaCha20CipherAlgorithm {
    const IV_LENGTH: usize = CHACHA20_IV_LENGTH;
    const KEY_LENGTH: usize = CHACHA20_KEY_LENGTH;
    const CIPHER_ALGORITHM_TYPE: CipherAlgorithmType = CipherAlgorithmType::Stream;
}

impl CipherAlgorithmTrait for ChaCha20CipherAlgorithm {
    fn crypt(&mut self, src_data: &[u8], dst_data: &mut [u8]) -> Result<()> {
        // 这里为了减少拷贝次数，先将src复制到dst中
        memcpy(dst_data, &src_data)?;
        self.m_algo.apply_keystream(dst_data);
        Ok(())
    }
}

impl IVKeyNewTrait for ChaCha20CipherAlgorithm {
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
        let cipher: ExChaCha20 = ExChaCha20::new(key.into(), iv.into());
        Ok(ChaCha20CipherAlgorithm { m_algo: cipher })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypter::{StringCrypter, StringCrypterTrait};

    #[test]
    fn test_chacha20() {
        let string_crypter = StringCrypter::<ChaCha20CipherAlgorithm>::default();
        let ciphertext = string_crypter.encrypt("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", "qwerty").unwrap();
        println!("ciphertext: {ciphertext}");
        let plaintext = string_crypter.decrypt(&ciphertext, "qwerty").unwrap();
        println!("plaintext: {plaintext}");
        assert_eq!(plaintext, "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

    // 该测试主要是由于StringCrypter单词生成密码流的长度为1024，
    // 当被加密的文本超过该长度时，StringCrypter需要继续生成密码流
    // 为了避免在继续生成密码流时，生成出重复的或者是错误的密码流，故需要进行该测试
    #[test]
    fn test_chacha20_long_string() {
        let string_crypter = StringCrypter::<ChaCha20CipherAlgorithm>::default();
        
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
        println!("长字符串加密解密测试通过！");
    }
}
