package main

// 分片加密/解密
//
// 设计要点:
//   - 算法:AES-256-GCM(AEAD,加密 + 完整性认证一体)
//   - 密钥派生:scrypt(带随机盐的慢哈希,抵御暴力破解)
//   - 大文件处理:按固定大小分块(1 MiB)流式加解密,内存占用恒定
//   - 每块独立随机12字节 nonce,随密文一同写入分片文件
//   - 分片文件头部写入4字节魔数,用于快速识别加密分片
//   - 清单只记录加密元数据(算法/盐/KDF参数)
//
// 加密分片文件格式:
//   魔数(4字节) | [nonce(12字节) + 密文块(明文块 + 认证标签16字节)] × N

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"

    "golang.org/x/crypto/scrypt"
)

const (
    // 加密块大小(明文分块,1 MiB),内存占用 = 块大小 + 认证标签,恒定可控
    encryptChunkSize = 1024 * 1024
    // GCM 随机数长度(12 字节,NIST 推荐)
    gcmNonceSize = 12
    // GCM 认证标签长度(16 字节)
    gcmTagSize = 16
    // 盐值长度(32 字节),每个文件独立随机
    saltSize = 32
    // scrypt 参数(工业常见配置,单次派生约 100ms 量级,兼顾安全与速度)
    // 32768
    scryptN = 1 << 15
    scryptR = 8
    scryptP = 1
    // 派生密钥长度(AES-256 -> 32 字节)
    derivedKeySize = 32
)

// 加密算法与KDF的标识字符串
const (
    cipherName = "AES-256-GCM"
    kdfName    = "scrypt"
)

// encryptedFileMagic:加密分片文件的魔数(4 字节)
// 写在每个加密分片文件的最开头合并解密时先读前4字节跟它比对,一致才继续按加密格式解析
// 不是安全机制,不提供任何保密或防篡改能力,只是格式标识
// BSE1:binsplit encrypted format v1
// 将来如果加密格式整体升级,可以用BSE2来区分新旧
var encryptedFileMagic = []byte{'B', 'S', 'E', '1'}

// generateSalt:生成随机盐值
func generateSalt() ([]byte, error) {
    salt := make([]byte, saltSize)
    if _, err := rand.Read(salt); err != nil {
        return nil, fmt.Errorf("生成加密盐值失败: %w", err)
    }
    return salt, nil
}

// deriveKey:使用scrypt从密码与盐派生AES-256密钥
// 密码以UTF-8字节处理,因此中文,中文标点等任意字符均可作为密码,长度不限
func deriveKey(password, salt []byte) ([]byte, error) {
    key, err := scrypt.Key(password, salt, scryptN, scryptR, scryptP, derivedKeySize)
    if err != nil {
        return nil, fmt.Errorf("密钥派生失败: %w", err)
    }
    return key, nil
}

// newGCM:创建AES-256-GCM AEAD实例
func newGCM(key []byte) (cipher.AEAD, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("创建 AES 加密器失败: %w", err)
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("创建 GCM 模式失败: %w", err)
    }
    return gcm, nil
}

// encryptStream:从reader读取明文,分块AES-256-GCM加密后写入writer
// 写入格式:魔数(4) + [nonce(12) + 密文块(明文块+认证标签16)] × N
// 返回写入的明文总字节数
func encryptStream(reader io.Reader, writer io.Writer, key []byte) (int64, error) {
    // 写入魔数,标记这是加密分片
    if _, err := writer.Write(encryptedFileMagic); err != nil {
        return 0, fmt.Errorf("写入加密分片头部失败: %w", err)
    }
    gcm, err := newGCM(key)
    if err != nil {
        return 0, err
    }
    buf := make([]byte, encryptChunkSize)
    out := make([]byte, gcmNonceSize+encryptChunkSize+gcmTagSize)
    var total int64
    for {
        n, err := io.ReadFull(reader, buf)
        if n > 0 {
            // 每块使用独立随机 nonce(放在输出缓冲头部)
            nonce := out[:gcmNonceSize]
            if _, rerr := rand.Read(nonce); rerr != nil {
                return total, fmt.Errorf("生成随机数失败: %w", rerr)
            }
            // 加密:sealed = 密文 + 认证标签,追加到 nonce 之后
            sealed := gcm.Seal(out[gcmNonceSize:gcmNonceSize], nonce, buf[:n], nil)
            if _, werr := writer.Write(out[:gcmNonceSize+len(sealed)]); werr != nil {
                return total, fmt.Errorf("写入加密数据失败: %w", werr)
            }
            total += int64(n)
        }
        if err == nil {
            continue
        }
        if err == io.EOF {
            return total, nil
        }
        if err == io.ErrUnexpectedEOF {
            continue
        }
        return total, fmt.Errorf("读取明文失败: %w", err)
    }
}

// decryptStream:从reader读取加密分片,解密为明文后写入writer
// 返回解出的明文总字节数
func decryptStream(reader io.Reader, writer io.Writer, key []byte) (int64, error) {
    gcm, err := newGCM(key)
    if err != nil {
        return 0, err
    }
    // 校验魔数,快速识别"未加密/已损坏"的分片
    magic := make([]byte, len(encryptedFileMagic))
    if _, err := io.ReadFull(reader, magic); err != nil {
        return 0, fmt.Errorf("无法读取加密分片头部(文件可能已损坏或被截断): %w", err)
    }
    if string(magic) != string(encryptedFileMagic) {
        return 0, fmt.Errorf("分片文件不是有效的加密分片(缺少加密标识),可能是未加密的分片或文件已损坏")
    }
    nonce := make([]byte, gcmNonceSize)
    ctBuf := make([]byte, encryptChunkSize+gcmTagSize)
    var total int64
    for {
        // 读取每块的nonce
        if _, err := io.ReadFull(reader, nonce); err != nil {
            if err == io.EOF {
                // 正常结束
                return total, nil
            }
            return total, fmt.Errorf("读取加密块随机数失败(文件可能被截断): %w", err)
        }
        n, err := io.ReadFull(reader, ctBuf)
        if n == 0 {
            return total, fmt.Errorf("加密分片数据损坏:读取到空的密文块")
        }
        if err != nil && err != io.ErrUnexpectedEOF {
            return total, fmt.Errorf("读取密文块失败: %w", err)
        }
        if n <= gcmTagSize {
            return total, fmt.Errorf("加密分片数据损坏:密文块过短")
        }
        pt, oerr := gcm.Open(nil, nonce, ctBuf[:n], nil)
        if oerr != nil {
            // GCM 认证失败:密码错误或密文被篡改/损坏,均在此暴露
            return total, fmt.Errorf("解密失败(密码错误或分片数据损坏): %w", oerr)
        }
        if _, werr := writer.Write(pt); werr != nil {
            return total, fmt.Errorf("写入解密数据失败: %w", werr)
        }
        total += int64(len(pt))
    }
}

// encryptPartWithSHA:从reader读取明文:边加密写入writer,边计算明文SHA256
// 返回明文长度与明文SHA256(清单记录的是明文SHA,合并后据此校验)
func encryptPartWithSHA(reader io.Reader, writer io.Writer, key []byte) (int64, string, error) {
    hasher := sha256.New()
    // encryptStream:返回的不是写入密文的字节数,而是读入的明文字节数
    plainLen, err := encryptStream(io.TeeReader(reader, hasher), writer, key)
    if err != nil {
        return plainLen, "", err
    }

    return plainLen, hex.EncodeToString(hasher.Sum(nil)), nil
}

// decryptPartWithSHA:从reader读取密文,解密为明文后写入writer并计算明文SHA256
// 返回明文长度与明文SHA256
func decryptPartWithSHA(reader io.Reader, writer io.Writer, key []byte) (int64, string, error) {
    hasher := sha256.New()
    plainLen, err := decryptStream(reader, io.MultiWriter(writer, hasher), key)
    if err != nil {
        return plainLen, "", err
    }
    return plainLen, hex.EncodeToString(hasher.Sum(nil)), nil
}

// zeroBytes:清零字节切片(用于及时擦除内存中的密码/密钥,降低被读取的风险)
func zeroBytes(b []byte) {
    for i := range b {
        b[i] = 0
    }
}
