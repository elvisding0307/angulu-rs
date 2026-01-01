pub mod memory;

// 重导出所有组件
pub use memory::{memcpy, xor, ByteArray, ByteVector, MemoryTaker};
