pub mod base64;
pub mod hex;

use crate::*;

pub trait EncodingTrait {
    fn encode(&self, data: &[u8]) -> String;
    fn decode(&self, data: &str) -> Result<ByteVector>;
}
