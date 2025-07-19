use ::base64::{engine::general_purpose, Engine as _};

use crate::encoding::EncodingTrait;
use crate::*;

pub struct Base64Encoding();

impl Default for Base64Encoding {
    fn default() -> Base64Encoding {
        Base64Encoding()
    }
}

impl EncodingTrait for Base64Encoding {
    fn encode(&self, data: &[u8]) -> String {
        let mut res: String = String::new();
        general_purpose::STANDARD.encode_string(&data, &mut res);
        res
    }
    fn decode(&self, data: &str) -> Result<ByteVector> {
        let mut buffer: Vec<u8> = ByteVector::new();
        general_purpose::STANDARD
            .decode_vec(data, &mut buffer)
            .or::<Error>(Err(EncodingError::InvalidBase64.into()))?;
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64() {
        let b64 = Base64Encoding::default();
        let res = b64.encode("Hello, angulu! 你好！".as_bytes());
        assert_eq!("SGVsbG8sIGFuZ3VsdSEg5L2g5aW977yB".to_string(), res);
        let res = b64.decode(&res).unwrap();
        assert_eq!("Hello, angulu! 你好！".as_bytes(), &res[..]);
        let res = b64.decode("SGVsbG8sIGNpZnRsISDkvaDlpb3vvIEA=");
        assert!(res.is_err());
        println!("错误：{}", res.unwrap_err());
    }
}
