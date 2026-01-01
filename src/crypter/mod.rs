#![allow(dead_code)]
#![allow(unused_assignments)]
pub mod chacha20;
pub mod sm4;

use std::cmp::min;
use std::marker;
use std::vec;

use rand::prelude::*;

use crate::encoding::base64::Base64Encoding;
use crate::encoding::EncodingTrait as _;
use crate::hash::crc::Crc32cHasher;
use crate::hash::sha256::Sha256Hasher;
use crate::hash::HasherTrait;
use crate::*;

/// 目前支持的所有算法
pub enum CipherAlgorithm {
    ChaCha20,
    Sm4,
}

/// 密码算法的类型
#[derive(Clone)]
pub enum CipherAlgorithmType {
    Stream,
    Block(usize),
}

/// 原始的密码算法trait
pub trait CipherAlgorithmBaseTrait {
    const IV_LENGTH: usize;
    const KEY_LENGTH: usize;
    const CIPHER_ALGORITHM_TYPE: CipherAlgorithmType;

    /// 返回IV的长度
    fn iv_length() -> usize {
        Self::IV_LENGTH
    }

    /// Key的长度
    fn key_length() -> usize {
        Self::KEY_LENGTH
    }

    /// 返回当前加密算法的类型（流密码还是分组密码）
    fn cipher_algorithm_type() -> CipherAlgorithmType {
        Self::CIPHER_ALGORITHM_TYPE
    }
}

/// 密码算法trait
pub trait CipherAlgorithmTrait: CipherAlgorithmBaseTrait {
    /// 加密算法原始的加密处理，对一串长度为分组长度倍数的数组进行加密
    /// 所有加密算法应强制保证完整的加密了一个分组，不应有漏加密或者剩余的情况，
    /// 也应当保证src_data和dst_data之间长度相等
    fn crypt(&mut self, src_data: &[u8], dst_data: &mut [u8]) -> Result<()>;
}

/// 通过IV和Key生成一个实例
pub trait IVKeyNewTrait {
    /// 创建一个加密算法器
    fn new(iv: &[u8], key: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// 密码流生成器的trait
pub trait StreamGeneratorTrait {
    /// 生成密码流
    fn generate(&mut self, len: usize) -> Result<ByteVector>;
}

/// 字符串加密器trait
pub trait StringCrypterTrait {
    fn encrypt(&self, data: &str, password: &str) -> Result<String>;
    fn decrypt(&self, data: &str, password: &str) -> Result<String>;
}

//------------------------------------------------具体实现------------------------------------------------//
/// 密码流生成器模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamGeneratorMode {
    Short = 1,
    Medium = 32,
    Large = 1024,
}
/// 获取不同模式下的缓存区的分组块数量
#[inline]
const fn stream_temp_block_count(m: StreamGeneratorMode) -> usize {
    return m as usize * 64;
}

/// 获取不同模式下的缓存区的长度
#[inline]
const fn stream_temp_buffer_size(m: StreamGeneratorMode) -> usize {
    return m as usize * 1024;
}

/// StreamGenerator是angulu自己实现的一个流生成器，具体逻辑是传入一个实现了CipherAlgorithmTrait和
/// IVKeyNewTrait的密码算法结构体，然后通过调用密码算法的加密函数实现自定义的字符串加密器
pub struct StreamGenerator<CA: CipherAlgorithmTrait + IVKeyNewTrait> {
    /// 加密算法器实例
    m_cipher_algorithm: CA,
    /// 密码流生成器模式
    m_mode: StreamGeneratorMode,
    /// 缓冲区的最大容量
    m_max_buffer_size: usize,
    /// 当前的索引
    m_current_index: usize,
    /// 当前的缓冲区
    m_current_buffer: ByteVector,
    /// 初始的明文内容
    m_plaintext_buffer: ByteVector,
}

impl<CA: CipherAlgorithmTrait + IVKeyNewTrait> StreamGenerator<CA> {
    /// 新建一个密码流生成器
    fn new(iv: &[u8], key: &[u8], mode: StreamGeneratorMode) -> Result<Self> {
        let calc_stream_temp_buffer_size = |mode: StreamGeneratorMode| -> usize {
            if let CipherAlgorithmType::Block(n) = CA::cipher_algorithm_type() {
                return stream_temp_block_count(mode) * n;
            }
            stream_temp_buffer_size(mode)
        };
        let buffer_size = calc_stream_temp_buffer_size(mode.clone());
        Ok(StreamGenerator::<CA> {
            m_cipher_algorithm: CA::new(iv, key)?,
            m_mode: mode.clone(),
            // 当前的下标应该在缓冲区的最后，因为最开始并没有初始化
            m_current_index: buffer_size,
            m_max_buffer_size: buffer_size,
            m_current_buffer: vec![0x00; buffer_size],
            m_plaintext_buffer: vec![0x00; buffer_size],
        })
    }

    /// 刷新缓冲区
    fn flush(&mut self) -> Result<()> {
        if self.m_current_index != self.m_max_buffer_size {
            return Err(CrypterError::BufferFlushFailed.into());
        }
        self.m_cipher_algorithm
            .crypt(&self.m_plaintext_buffer, &mut self.m_current_buffer)?;
        self.m_current_index = 0;
        Ok(())
    }
}

impl<CA: CipherAlgorithmTrait + IVKeyNewTrait> IVKeyNewTrait for StreamGenerator<CA> {
    /// 新建一个密码流生成器
    fn new(iv: &[u8], key: &[u8]) -> Result<Self> {
        Self::new(iv, key, StreamGeneratorMode::Medium)
    }
}

impl<CA: CipherAlgorithmTrait + IVKeyNewTrait> StreamGeneratorTrait for StreamGenerator<CA> {
    fn generate(&mut self, len: usize) -> Result<ByteVector> {
        if len == 0 {
            return Ok(ByteVector::new());
        }
        // 如果当前缓冲区中无更多内容则刷新
        if self.m_current_index >= self.m_max_buffer_size {
            self.flush()?;
        }
        // 生成的结果
        let mut dst_data = vec![0x00 as u8; len];
        // 当前生成到的字节索引
        let mut index: usize = 0;
        // 记录缓冲区还能生成的字节的最大数量
        let mut once_gen: usize = self.m_max_buffer_size - self.m_current_index;
        // 如果要产生新的buffer，则不断的循环这一步骤
        while index + once_gen < len {
            memcpy(
                &mut dst_data[index..index + once_gen],
                &self.m_current_buffer[self.m_current_index..self.m_current_index + once_gen],
            )?;
            index += once_gen;
            self.m_current_index += once_gen;
            self.flush()?;
            once_gen = self.m_max_buffer_size - self.m_current_index;
        }
        // 将剩余部份拷贝
        let last_gen = len - index;
        memcpy(
            &mut dst_data[index..index + last_gen],
            &self.m_current_buffer[self.m_current_index..self.m_current_index + last_gen],
        )?;
        index += last_gen;
        self.m_current_index += last_gen;
        Ok(dst_data)
    }
}

/// 随机生成IV
#[inline]
fn rand_iv(n: usize) -> ByteVector {
    let mut res = vec![0x00; n];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut res);
    res
}

/// 该函数用于从密码生成密钥流，其原理是将密码进行sha256哈希，将哈希值拷贝到给定长度为N的ByteArray中
/// 如果一次sha256的长度不足N，则将上一次的哈希值与原文拼接继续进行一次哈希，并将值继续拷贝到ByteArray中，重复该步骤直到长度大于N为止
#[inline]
fn generate_key_from_password<HR: HasherTrait + Default>(password: &str, n: usize) -> ByteVector {
    // 生成加密所需的密钥
    let mut hasher = HR::default();
    hasher.update_message(password);
    let mut buffer = hasher.finalize();
    let mut cnt: usize = 0;
    let mut res = vec![0x00; n];
    while cnt < n {
        // 计算下次填充的长度
        let once_gen = min(n - cnt, buffer.len());
        // 拷贝
        for i in 0..once_gen {
            res[cnt + i] = buffer[i];
        }
        cnt += once_gen;
        if cnt >= n {
            break;
        }
        // 长度不足对结果进行二次哈希
        hasher.update_bytes(&buffer);
        buffer = hasher.finalize();
    }
    res
}

/// StringCrypter是angulu自己实现的一个文本加密器
pub struct StringCrypter<
    CA: CipherAlgorithmTrait + IVKeyNewTrait,
    HR: HasherTrait + Default = Crc32cHasher,
> {
    _ca: marker::PhantomData<CA>,
    _hr: marker::PhantomData<HR>,
}

impl<CA: CipherAlgorithmTrait + IVKeyNewTrait, HR: HasherTrait + Default> StringCrypter<CA, HR> {
    pub fn rand_iv(n: usize) -> ByteVector {
        crate::crypter::rand_iv(n)
    }

    pub fn generate_key_from_password(password: &str, n: usize) -> ByteVector {
        generate_key_from_password::<Sha256Hasher>(password, n)
    }
}

impl<CA: CipherAlgorithmTrait + IVKeyNewTrait, HR: HasherTrait + Default> Default
    for StringCrypter<CA, HR>
{
    fn default() -> Self {
        StringCrypter::<CA, HR> {
            _ca: marker::PhantomData::<CA>,
            _hr: marker::PhantomData::<HR>,
        }
    }
}

impl<CA: CipherAlgorithmTrait + IVKeyNewTrait, HR: HasherTrait + Default> StringCrypterTrait
    for StringCrypter<CA, HR>
{
    fn encrypt(&self, data: &str, password: &str) -> Result<String> {
        if data.is_empty() {
            return Err(CrypterError::EmptyStringNotAllowed.into());
        }
        if password.is_empty() {
            return Err(CrypterError::EmptyPasswordNotAllowed.into());
        }

        // 创建一个密码流生成器
        let iv = rand_iv(CA::IV_LENGTH);
        let key = Self::generate_key_from_password(password, CA::KEY_LENGTH);
        let mut stream_generator =
            StreamGenerator::<CA>::new(&iv, &key, StreamGeneratorMode::Short)?;
        // 获取明文的字节流
        let plain_data_bytes = data.as_bytes();
        // 获取明文的校验值
        let plain_data_checksum = {
            let mut c = HR::default();
            c.update_bytes(&plain_data_bytes);
            c.finalize()
        };
        // 生成密码流进行加密
        let cipher_data_bytes = {
            let cipher_stream = stream_generator.generate(plain_data_bytes.len())?;
            xor(&cipher_stream, plain_data_bytes)?
        };
        // 继续加密校验值
        let cipher_data_checksum = {
            let cipher_stream = stream_generator.generate(plain_data_checksum.len())?;
            xor(&cipher_stream, &plain_data_checksum)?
        };
        let res = [&iv[..], &cipher_data_checksum[..], &cipher_data_bytes[..]].concat();
        // 对结果进行编码
        Ok(Base64Encoding::default().encode(&res))
    }

    fn decrypt(&self, data: &str, password: &str) -> Result<String> {
        if data.is_empty() {
            return Err(CrypterError::EmptyStringNotAllowed.into());
        }
        if password.is_empty() {
            return Err(CrypterError::EmptyPasswordNotAllowed.into());
        }

        // 对密文进行解码
        let b64 = Base64Encoding::default();
        let data = b64.decode(data)?;
        // 从原文中获取数据
        let mut iv = vec![0u8; CA::IV_LENGTH];
        let mut cipher_data_checksum = vec![0u8; HR::OUTPUT_LENGTH];
        let mut mt = MemoryTaker::new(&data);
        let cipher_data_bytes = mt
            .take(&mut iv)?
            .take(&mut cipher_data_checksum)?
            .take_all()?;
        // 创建一个密码流生成器
        let key = Self::generate_key_from_password(password, CA::KEY_LENGTH);
        let mut stream_generator =
            StreamGenerator::<CA>::new(&iv, &key, StreamGeneratorMode::Short)?;
        // 生成密码流进行解密
        let plain_data_bytes = {
            let cipher_stream = stream_generator.generate(cipher_data_bytes.len())?;
            xor(&cipher_data_bytes, &cipher_stream)?
        };
        // 解密原文的校验值
        let plain_data_checksum = {
            let cipher_stream = stream_generator.generate(cipher_data_checksum.len())?;
            xor(&cipher_data_checksum, &cipher_stream)?
        };
        // 计算解密后的内容的校验值
        let calced_plain_data_checksum = {
            let mut c = HR::default();
            c.update_bytes(&plain_data_bytes);
            c.finalize()
        };
        if plain_data_checksum != calced_plain_data_checksum {
            return Err(CrypterError::ChecksumValidationFailed.into());
        }
        Ok(String::from_utf8(plain_data_bytes)
            .map_err(|_| Into::<Error>::into(CrypterError::StringDecodingFailed))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex::HexEncoding;
    use crate::encoding::EncodingTrait;

    #[test]
    fn test_generate_key_from_password() {
        let hexe = HexEncoding::default();
        // 123456 32bytes
        let res = generate_key_from_password::<Sha256Hasher>("123456", 32);
        assert_eq!(
            "8D969EEF6ECAD3C29A3A629280E686CF0C3F5D5A86AFF3CA12020C923ADC6C92".to_string(),
            hexe.encode(&res)
        );
        // 123456 48bytes
        let res = generate_key_from_password::<Sha256Hasher>("123456", 48);
        assert_eq!("8D969EEF6ECAD3C29A3A629280E686CF0C3F5D5A86AFF3CA12020C923ADC6C9213619CFEA04EEB088EA04D789731EFED".to_string(), hexe.encode(&res));
    }
}
