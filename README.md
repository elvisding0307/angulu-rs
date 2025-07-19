# README

angulu-rs是一个密码学工具库。

## 模块介绍

### crypter（加密工具）

| 密码算法 | IV长度（Byte） | Key长度（Byte） | Block长度（Byte） | 算法类型 |
| -------- | -------------- | --------------- | ----------------- | -------- |
| ChaCha20 | 12             | 32              | 1                 | Stream   |

### encoding（编码工具）

| 编码类型 | 参数                                     |
| -------- | ---------------------------------------- |
| hex      | **HexEncodingCase:** UpperCase/LowerCase |
| base64   | 无                                       |

### hash（哈希工具）

| 哈希算法 | 输出长度（Byte） |
| -------- | ---------------- |
| CRC32    | 4                |
| CRC32C   | 4                |
| Sha1     | 20               |
| Sha256   | 32               |
| Sha512   | 64               |

## 编译

### 编译angulu库。

```
cargo build
```
