# README

angulu是一个密码学工具库。

## 模块介绍

### crypter（加密工具）

| 密码算法 | IV长度（Byte） | Key长度（Byte） | Block长度（Byte） | 算法类型 |
| -------- | -------------- | --------------- | ----------------- | -------- |
| ChaCha20 | 12             | 32              | 1                 | Stream   |
| SM4      | 16             | 16              | 16                | Block    |

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

### 基本编译

编译angulu库（开发模式）：
```bash
cargo build
```

编译优化版本（发布模式）：
```bash
cargo build --release
```

### 测试

运行所有测试：
```bash
cargo test
```

运行测试并显示输出：
```bash
cargo test -- --nocapture
```

### 文档生成

生成并打开文档：
```bash
cargo doc --open
```

### 代码检查

运行代码格式检查：
```bash
cargo fmt --check
```

运行代码质量检查：
```bash
cargo clippy
```

### 清理构建产物

清理编译生成的文件：
```bash
cargo clean
```
