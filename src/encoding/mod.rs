pub mod hex;
pub mod base64;

use crate::*;

pub trait EncodingTrait
{
    fn encode(&self, data : &[u8]) -> String;
    fn decode(&self, data : &str) -> Result<ByteVector>;
}

