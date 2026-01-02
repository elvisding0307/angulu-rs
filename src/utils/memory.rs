use std::convert::AsRef;
use std::fmt;
use std::ops;
use std::ops::Deref;
use std::ops::DerefMut;

use crate::*;

/// 字节向量类型别名，用于表示动态长度的字节数组
pub type ByteVector = Vec<u8>;

/// ByteArray是一个定长的字节容器，使用泛型常量参数N来指定数组大小
///
/// 这个结构体提供了一个类型安全的方式来处理固定长度的字节数组，
/// 相比于原生数组，它提供了更多的便利方法和trait实现
#[derive(Debug, Clone)]
pub struct ByteArray<const N: usize>([u8; N]);

impl<const N: usize> ByteArray<N> {
    /// 创建一个新的ByteArray实例，所有字节初始化为0
    pub fn new() -> ByteArray<N> {
        ByteArray::<N>([0; N])
    }
}

/// 为ByteArray实现Default trait，提供默认值构造
impl<const N: usize> Default for ByteArray<N> {
    /// 创建默认的ByteArray实例，所有字节初始化为0x00
    fn default() -> Self {
        ByteArray::<N>([0x00; N])
    }
}

/// 实现AsRef trait，允许ByteArray被当作&[u8]使用
impl<const N: usize> AsRef<[u8]> for ByteArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// 实现Deref trait，允许ByteArray自动解引用为&[u8]
impl<const N: usize> Deref for ByteArray<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// 实现DerefMut trait，允许ByteArray自动解引用为&mut [u8]
impl<const N: usize> DerefMut for ByteArray<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// 实现PartialEq trait，允许ByteArray之间进行相等性比较
impl<const N: usize> PartialEq for ByteArray<N> {
    /// 比较两个ByteArray是否相等
    ///
    /// # 参数
    /// * `other` - 要比较的另一个ByteArray
    ///
    /// # 返回值
    /// 如果两个数组的所有元素都相等则返回true，否则返回false
    fn eq(&self, other: &Self) -> bool {
        return self.0 == other.0;
    }
}

/// 实现从&[u8; N]到ByteArray的转换
impl<const N: usize> From<&[u8; N]> for ByteArray<N> {
    /// 从字节数组引用创建ByteArray
    ///
    /// # 参数
    /// * `value` - 长度为N的字节数组引用
    fn from(value: &[u8; N]) -> Self {
        ByteArray::<N>(*value)
    }
}

/// 实现从[u8; N]到ByteArray的转换
impl<const N: usize> From<[u8; N]> for ByteArray<N> {
    /// 从字节数组创建ByteArray
    ///
    /// # 参数
    /// * `value` - 长度为N的字节数组
    fn from(value: [u8; N]) -> Self {
        ByteArray::<N>(value)
    }
}

/// 实现Display trait，允许ByteArray被格式化输出
impl<const N: usize> fmt::Display for ByteArray<N> {
    /// 格式化ByteArray为字符串
    ///
    /// # 参数
    /// * `f` - 格式化器
    ///
    /// # 返回值
    /// 格式化结果
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// 实现BitXor trait，允许ByteArray之间进行异或操作
impl<const N: usize> ops::BitXor for ByteArray<N> {
    type Output = Self;

    /// 对两个ByteArray执行按位异或操作
    ///
    /// # 参数
    /// * `rhs` - 右操作数ByteArray
    ///
    /// # 返回值
    /// 异或结果的新ByteArray
    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut res = self;
        for i in 0..N {
            res.0[i] = res.0[i] ^ rhs.0[i];
        }
        res
    }
}

/// 实现Index trait，允许通过索引访问ByteArray中的元素
impl<const N: usize> ops::Index<usize> for ByteArray<N> {
    type Output = u8;

    /// 通过索引获取ByteArray中指定位置的字节
    ///
    /// # 参数
    /// * `index` - 要访问的索引位置
    ///
    /// # 返回值
    /// 指定位置的字节引用
    fn index(&self, index: usize) -> &Self::Output {
        &self.0.as_slice()[index]
    }
}

/// 实现IndexMut trait，允许通过索引修改ByteArray中的元素
impl<const N: usize> ops::IndexMut<usize> for ByteArray<N> {
    /// 通过索引获取ByteArray中指定位置的可变字节引用
    ///
    /// # 参数
    /// * `index` - 要访问的索引位置
    ///
    /// # 返回值
    /// 指定位置的可变字节引用
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0.as_mut_slice()[index]
    }
}

/// 内存获取器，用于从一块内存中顺序获取数据直到结束
///
/// MemoryTaker提供了一种安全的方式来从字节切片中顺序读取数据，
/// 它会跟踪当前读取位置，确保不会越界访问
pub struct MemoryTaker<'a> {
    /// 源内存的引用
    mem: &'a [u8],
    /// 当前读取位置的索引
    idx: usize,
    /// 内存总长度
    length: usize,
}

impl<'a> MemoryTaker<'a> {
    /// 创建一个新的MemoryTaker实例
    ///
    /// # 参数
    /// * `src` - 源字节切片
    ///
    /// # 返回值
    /// 新的MemoryTaker实例
    pub fn new(src: &'a [u8]) -> MemoryTaker<'a> {
        MemoryTaker {
            mem: src,
            idx: 0,
            length: src.len(),
        }
    }

    /// 从内存中取出指定长度的数据到目标缓冲区
    ///
    /// # 参数
    /// * `dst` - 目标缓冲区，其长度决定了要读取的字节数
    ///
    /// # 返回值
    /// 成功时返回自身的可变引用，失败时返回错误
    ///
    /// # 错误
    /// 当剩余内存不足时返回InsufficientMemoryContent错误
    pub fn take(&mut self, dst: &mut [u8]) -> Result<&mut Self> {
        let need_length = dst.len();
        if self.idx + need_length > self.length {
            return Err(EtcError::InsufficientMemoryContent.into());
        }
        memcpy(dst, &self.mem[self.idx..self.idx + need_length])?;
        self.idx += need_length;
        Ok(self)
    }

    /// 取出所有剩余的内存数据
    ///
    /// # 返回值
    /// 成功时返回包含所有剩余数据的ByteVector，失败时返回错误
    ///
    /// # 错误
    /// 当没有剩余数据时返回InsufficientMemoryContent错误
    pub fn take_all(&mut self) -> Result<ByteVector> {
        if self.idx >= self.length {
            return Err(EtcError::InsufficientMemoryContent.into());
        }
        let res = self.mem[self.idx..].to_vec();
        self.idx = self.length;
        Ok(res)
    }
}

/// 内存拷贝函数，将源切片的数据复制到目标切片
///
/// # 参数
/// * `dst` - 目标字节切片
/// * `src` - 源字节切片
///
/// # 返回值
/// 成功时返回Ok(())，失败时返回错误
///
/// # 错误
/// 当源和目标切片长度不匹配时返回MemoryLengthMismatch错误
pub fn memcpy(dst: &mut [u8], src: &[u8]) -> Result<()> {
    if dst.len() != src.len() {
        return Err(EtcError::MemoryLengthMismatch.into());
    }
    dst.copy_from_slice(src);
    Ok(())
}

/// 内存异或函数，对两个字节切片执行按位异或操作
///
/// # 参数
/// * `src1` - 第一个源字节切片
/// * `src2` - 第二个源字节切片
///
/// # 返回值
/// 成功时返回异或结果的ByteVector，失败时返回错误
///
/// # 错误
/// 当两个源切片长度不匹配时返回XorMemoryLengthMismatch错误
pub fn xor(src1: &[u8], src2: &[u8]) -> Result<ByteVector> {
    if src1.len() != src2.len() {
        return Err(EtcError::XorMemoryLengthMismatch.into());
    }
    let target_len = src1.len();
    let mut res = vec![0x00; target_len];
    for i in 0..target_len {
        res[i] = src1[i] ^ src2[i];
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let a = ByteArray::<4>::from(&[0x42, 0x63, 0x76, 0x77]);
        let b = ByteArray::<4>::from(&[0x75, 0x4A, 0xB1, 0xC9]);
        let res = a ^ b;
        assert_eq!(res.as_ref(), &[0x37, 0x29, 0xC7, 0xBE]);
        println!("Res: {}", res);
    }

    #[test]
    fn test_memory_taker() {
        let v = b"123456789".to_vec();
        let mut mt = MemoryTaker::new(&v);
        let mut v1: Vec<u8> = vec![0u8; 2];
        let mut v2 = vec![0u8; 3];
        let v3 = mt
            .take(&mut v1)
            .unwrap()
            .take(&mut v2)
            .unwrap()
            .take_all()
            .unwrap();
        assert_eq!(v1, b"12".to_vec());
        assert_eq!(v2, b"345".to_vec());
        assert_eq!(v3, b"6789".to_vec());
        let mut v1: Vec<u8> = vec![0u8; 2];
        assert!(mt.take(&mut v1).is_err());
    }
}
