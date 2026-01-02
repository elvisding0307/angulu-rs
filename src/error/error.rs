use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnguluError {
    #[error("编码错误: {0}")]
    Encoding(#[from] EncodingError),

    #[error("加密错误: {0}")]
    Crypter(#[from] CrypterError),

    #[error("通用错误: {0}")]
    Etc(#[from] EtcError),
}

#[derive(Error, Debug)]
pub enum EncodingError {
    #[error("非法的16进制字符串")]
    InvalidHex,

    #[error("非法的Base64字符串")]
    InvalidBase64,

    #[error("二进制编码错误")]
    BinaryEncoding,
}

#[derive(Error, Debug)]
pub enum CrypterError {
    #[error("不满足要求的IV长度")]
    InvalidIVLength,

    #[error("不满足要求的Key长度")]
    InvalidKeyLength,

    #[error("执行密码操作时失败")]
    CryptionFailed,

    #[error("完成密码操作时失败")]
    FinalizationFailed,

    #[error("刷新缓冲区时失败")]
    BufferFlushFailed,

    #[error("解密后内容无法通过校验")]
    ChecksumValidationFailed,

    #[error("字符串编码时失败")]
    StringEncodingFailed,

    #[error("字符串解码时失败")]
    StringDecodingFailed,

    #[error("不能对空串进行密码操作")]
    EmptyStringNotAllowed,

    #[error("密码不能为空")]
    EmptyPasswordNotAllowed,
}

#[derive(Error, Debug)]
pub enum EtcError {
    #[error("拷贝原始内存和目的内存长度不一致")]
    MemoryLengthMismatch,

    #[error("进行异或操作的两段内存长度不一致")]
    XorMemoryLengthMismatch,

    #[error("内存获取器中的内容长度不足")]
    InsufficientMemoryContent,
}

pub type AnguluResult<T> = Result<T, AnguluError>;
