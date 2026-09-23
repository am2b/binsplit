package main

// 本文件定义清单文件(manifest)的数据结构与读写逻辑
//
// 清单文件的作用:
// 1,记录原始文件的名称,大小,SHA256(合并时用于恢复文件名和校验完整性)
// 2,记录每个分片的文件名,大小,SHA256 和顺序(合并时按序拼接)
// 3,记录创建时间等元信息
//
// 清单文件本身的命名格式:原始文件名-清单文件SHA256-分片数量.txt

import (
    "bufio"
    "encoding/hex"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "time"
)

// manifestNameRegex:匹配合法的清单文件名
// 格式:任意字符-64位十六进制-数字.txt
var manifestNameRegex = regexp.MustCompile(`^(.+)-([0-9a-f]{64})-(\d+)\.txt$`)

// error:表示一个分割目录中存在多个清单文件
var ErrMultipleManifests = errors.New("目录中存在多个清单文件,无法确定使用哪一个")

// 描述单个分片的信息
type PartInfo struct {
    Index    int    // 分片序号(从 1 开始,决定合并时的拼接顺序)
    FileName string // 分片的随机文件名(64 字符)
    Size     int64  // 分片大小(字节)
    SHA256   string // 分片的 SHA256 哈希值
}

// 描述整个分割任务的清单信息
type Manifest struct {
    ToolName       string     // 创建本清单的工具名称(binsplit)
    Version        string     // 创建本清单的软件版本号(合并出错时可据此选择正确的软件版本)
    Encrypted      bool       // 分片是否加密
    Cipher         string     // 加密算法(如AES-256-GCM)
    KDF            string     // 密钥派生算法(如scrypt)
    Salt           []byte     // 加密盐值(随机生成)
    ScryptN        int        // scrypt 参数 N
    ScryptR        int        // scrypt 参数 r
    ScryptP        int        // scrypt 参数 p
    OriginalName   string     // 原始文件名(含后缀)
    OriginalSize   int64      // 原始文件大小(字节)
    OriginalSHA256 string     // 原始文件的SHA256
    PartCount      int        // 分片总数
    CreatedAt      time.Time  // 清单创建时间
    Parts          []PartInfo // 分片信息列表(按顺序排列)
}

const (
    // 区块名
    sectionSoftwareInfo = "软件信息"
    sectionOriginalInfo = "原始文件信息"
    sectionPartList     = "分片列表"

    // 键名
    keyTool          = "工具"
    keyVersion       = "版本"
    keyFileName      = "文件名"
    keyFileSize      = "文件大小"
    keySHA256        = "SHA256"
    keyPartCount     = "分片数量"
    keyCreatedAt     = "创建时间"
    keyEncrypted     = "加密"
    keyCipher        = "加密算法"
    keyKDF           = "密钥派生"
    keySalt          = "盐值"
    keyScryptParams  = "scrypt参数"

    valueEncryptedYes = "是"
    valueEncryptedNo  = "否"

    kvSeparator   = " = "
    partSeparator = " | "
)

// generateManifestName:根据清单信息与清单文件自身 SHA256 生成清单文件名
// 格式:原始文件名-清单文件SHA256-分片数量.txt
//
// 参数:
//   - manifest: 清单信息
//   - manifestSHA256: 清单文件自身的SHA256
//
// 返回:
//   - 清单文件名
func generateManifestName(manifest *Manifest, manifestSHA256 string) string {
    return fmt.Sprintf("%s-%s-%d.txt", manifest.OriginalName, manifestSHA256, manifest.PartCount)
}

// findManifestFile:在指定目录中查找符合命名规范的清单文件
//
// 参数:
//   - dir: 目录路径
//
// 返回:
//   - 清单文件的完整路径
//   - 错误信息
func findManifestFile(dir string) (string, error) {
    entries, err := os.ReadDir(dir)
    if err != nil {
        return "", fmt.Errorf("无法读取目录 %s: %w", dir, err)
    }

    var found []string
    for _, entry := range entries {
        if entry.IsDir() {
            continue
        }
        name := entry.Name()
        if manifestNameRegex.MatchString(name) {
            found = append(found, filepath.Join(dir, name))
        }
    }

    if len(found) == 0 {
        return "", fmt.Errorf("目录 %s 中未找到符合命名规范的清单文件", dir)
    }
    if len(found) > 1 {
        return "", fmt.Errorf("%w(共 %d 个):%s", ErrMultipleManifests, len(found), strings.Join(found, "、"))
    }

    return found[0], nil
}

// writeManifest:将清单信息写入指定目录下的清单文件
//
//  1,先将内容写入同目录下的临时文件
//  2,计算临时文件的SHA256(即清单文件自身的指纹)
//  3,将临时文件重命名为"原始文件名-清单SHA256-分片数量.txt"
//
// 这样清单文件名中携带的SHA256就是清单文件本身的指纹,合并时重新计算并比对,即可检测清单是否被意外修改(文本编辑器改动,复制损坏,磁盘位翻转等)
// 临时文件若在重命名前失败,会被 split 的失败回滚逻辑一并清理
//
// 文件格式说明:
//   - 以 # 开头的行为注释
//   - [区块名] 标记一个区块的开始
//   - 键值对使用 "键 = 值" 格式
//   - 分片列表使用 "序号 | 文件名 | 大小 | SHA256" 格式
//
// 参数:
//   - dir: 分割目录路径
//   - manifest: 清单信息
//
// 返回:
//   - 错误信息
func writeManifest(dir string, manifest *Manifest) error {
    tmpName, err := generateUniqueRandomName(dir)
    if err != nil {
        return fmt.Errorf("生成临时文件名失败: %w", err)
    }
    tmpName = ".binsplit-manifest-tmp-" + tmpName
    tmpPath := filepath.Join(dir, tmpName)
    // 创建临时文件
    f, err := os.Create(tmpPath)
    if err != nil {
        return fmt.Errorf("无法创建清单文件 %s: %w", tmpPath, err)
    }
    defer f.Close()

    // 使用 bufio.Writer 提高写入性能
    writer := bufio.NewWriter(f)

    // 写入文件头注释
    fmt.Fprintln(writer, "# ============================================================")
    fmt.Fprintln(writer, "# binsplit 清单文件 (manifest)")
    fmt.Fprintln(writer, "# 本文件由 binsplit 工具自动生成,请勿手动修改")
    fmt.Fprintln(writer, "# 合并时需要读取本文件以恢复原始文件名和校验完整性")
    fmt.Fprintln(writer, "# ============================================================")
    fmt.Fprintln(writer)

    // 写入软件信息区块(记录创建工具与版本,便于合并出错时选择正确的软件版本)
    fmt.Fprintln(writer, "["+sectionSoftwareInfo+"]")
    fmt.Fprintf(writer, "%s%s%s\n", keyTool, kvSeparator, manifest.ToolName)
    fmt.Fprintf(writer, "%s%s%s\n", keyVersion, kvSeparator, manifest.Version)
    fmt.Fprintln(writer)

    // 写入原始文件信息区块
    fmt.Fprintln(writer, "["+sectionOriginalInfo+"]")
    fmt.Fprintf(writer, "%s%s%s\n", keyFileName, kvSeparator, manifest.OriginalName)
    fmt.Fprintf(writer, "%s%s%d\n", keyFileSize, kvSeparator, manifest.OriginalSize)
    fmt.Fprintf(writer, "%s%s%s\n", keySHA256, kvSeparator, manifest.OriginalSHA256)
    fmt.Fprintf(writer, "%s%s%d\n", keyPartCount, kvSeparator, manifest.PartCount)
    fmt.Fprintf(writer, "%s%s%s\n", keyCreatedAt, kvSeparator, manifest.CreatedAt.Format(time.RFC3339))

    if manifest.Encrypted {
        fmt.Fprintf(writer, "%s%s%s\n", keyEncrypted, kvSeparator, valueEncryptedYes)
        fmt.Fprintf(writer, "%s%s%s\n", keyCipher, kvSeparator, manifest.Cipher)
        fmt.Fprintf(writer, "%s%s%s\n", keyKDF, kvSeparator, manifest.KDF)
        fmt.Fprintf(writer, "%s%s%s\n", keySalt, kvSeparator, hex.EncodeToString(manifest.Salt))
        fmt.Fprintf(writer, "%s%s%d,%d,%d\n", keyScryptParams, kvSeparator, manifest.ScryptN, manifest.ScryptR, manifest.ScryptP)
    } else {
        fmt.Fprintf(writer, "%s%s%s\n", keyEncrypted, kvSeparator, valueEncryptedNo)
    }
    fmt.Fprintln(writer)

    // 写入分片列表区块
    fmt.Fprintln(writer, "["+sectionPartList+"]")
    fmt.Fprintf(writer, "# 格式: 序号%s分片文件名%s分片大小(字节)%s分片SHA256\n", partSeparator, partSeparator, partSeparator)
    for _, part := range manifest.Parts {
        fmt.Fprintf(writer, "%d%s%s%s%d%s%s\n",
            part.Index, partSeparator, part.FileName, partSeparator, part.Size, partSeparator, part.SHA256)
    }

    // 显式刷新并落盘,确保在计算哈希与重命名前数据已完整写入
    if err := writer.Flush(); err != nil {
        f.Close()
        return fmt.Errorf("写入清单文件 %s 失败: %w", tmpPath, err)
    }
    if err := f.Close(); err != nil {
        return fmt.Errorf("关闭清单文件 %s 失败: %w", tmpPath, err)
    }

    // 计算清单文件自身的SHA256
    manifestSHA256, err := computeFileSHA256(tmpPath)
    if err != nil {
        return fmt.Errorf("计算清单文件 SHA256 失败: %w", err)
    }

    // 重命名为最终清单文件名
    finalName := generateManifestName(manifest, manifestSHA256)
    if err := os.Rename(tmpPath, filepath.Join(dir, finalName)); err != nil {
        return fmt.Errorf("重命名清单文件失败: %w", err)
    }

    return nil
}

// readManifest:从指定目录查找并解析清单文件
//
// 解析逻辑:
//  1. 逐行读取文件
//  2. 跳过空行和注释行(以 # 开头)
//  3. 识别 [区块名] 切换当前区块
//  4. 在"原始文件信息"区块解析键值对
//  5. 在"分片列表"区块解析竖线分隔的分片信息
//
// 参数:
//   - dir: 分割目录路径
//
// 返回:
//   - 解析后的清单信息
//   - 错误信息
func readManifest(dir string) (*Manifest, error) {
    // 查找清单文件
    manifestPath, err := findManifestFile(dir)
    if err != nil {
        return nil, err
    }

    f, err := os.Open(manifestPath)
    if err != nil {
        return nil, fmt.Errorf("无法打开清单文件 %s: %w", manifestPath, err)
    }
    defer f.Close()

    manifest := &Manifest{Parts: make([]PartInfo, 0)}

    // 当前所在的区块名称
    currentSection := ""

    scanner := bufio.NewScanner(f)
    // 增加缓冲区大小,防止某些行过长导致读取失败
    scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

    for scanner.Scan() {
        line := scanner.Text()
        trimmed := strings.TrimSpace(line)

        // 跳过空行
        if trimmed == "" {
            continue
        }

        // 跳过注释行
        if strings.HasPrefix(trimmed, "#") {
            continue
        }

        // 检测区块标记,例如 [原始文件信息]
        if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
            currentSection = trimmed[1 : len(trimmed)-1]
            continue
        }

        // 根据当前区块解析内容
        switch currentSection {
        case sectionSoftwareInfo:
            // 解析软件信息键值对（工具/版本/格式版本）
            if idx := strings.Index(trimmed, "="); idx >= 0 {
                key := strings.TrimSpace(trimmed[:idx])
                value := strings.TrimSpace(trimmed[idx+1:])
                switch key {
                case keyTool:
                    manifest.ToolName = value
                case keyVersion:
                    manifest.Version = value
                }
            }
        case sectionOriginalInfo:
            // 解析键值对："键 = 值"
            if idx := strings.Index(trimmed, "="); idx >= 0 {
                key := strings.TrimSpace(trimmed[:idx])
                value := strings.TrimSpace(trimmed[idx+1:])

                switch key {
                case keyFileName:
                    manifest.OriginalName = value
                case keyFileSize:
                    size, err := strconv.ParseInt(value, 10, 64)
                    if err != nil {
                        return nil, fmt.Errorf("清单文件中文件大小格式无效: %s", value)
                    }
                    manifest.OriginalSize = size
                case keySHA256:
                    manifest.OriginalSHA256 = value
                case keyPartCount:
                    count, err := strconv.Atoi(value)
                    if err != nil {
                        return nil, fmt.Errorf("清单文件中分片数量格式无效: %s", value)
                    }
                    manifest.PartCount = count
                case keyCreatedAt:
                    t, err := time.Parse(time.RFC3339, value)
                    if err == nil {
                        manifest.CreatedAt = t
                    }
                    // 创建时间解析失败不影响主流程，忽略错误
                case keyEncrypted:
                    manifest.Encrypted = (value == valueEncryptedYes)
                case keyCipher:
                    manifest.Cipher = value
                case keyKDF:
                    manifest.KDF = value
                case keySalt:
                    salt, err := hex.DecodeString(value)
                    if err != nil {
                        return nil, fmt.Errorf("清单文件中加密盐值格式无效: %s", value)
                    }
                    manifest.Salt = salt
                case keyScryptParams:
                    parts := strings.Split(value, ",")
                    if len(parts) != 3 {
                        return nil, fmt.Errorf("清单文件中 scrypt 参数格式无效: %s", value)
                    }
                    n, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
                    r, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
                    p, e3 := strconv.Atoi(strings.TrimSpace(parts[2]))
                    if e1 != nil || e2 != nil || e3 != nil {
                        return nil, fmt.Errorf("清单文件中 scrypt 参数格式无效: %s", value)
                    }
                    manifest.ScryptN, manifest.ScryptR, manifest.ScryptP = n, r, p
                }
            }

        case sectionPartList:
            // 解析分片信息："序号 | 文件名 | 大小 | SHA256"
            fields := strings.Split(trimmed, "|")
            if len(fields) != 4 {
                // 格式不对的行跳过（可能是注释残留）
                continue
            }

            index, err := strconv.Atoi(strings.TrimSpace(fields[0]))
            if err != nil {
                return nil, fmt.Errorf("分片序号格式无效: %s", fields[0])
            }

            size, err := strconv.ParseInt(strings.TrimSpace(fields[2]), 10, 64)
            if err != nil {
                return nil, fmt.Errorf("分片大小格式无效: %s", fields[2])
            }

            part := PartInfo{
                Index:    index,
                FileName: strings.TrimSpace(fields[1]),
                Size:     size,
                SHA256:   strings.TrimSpace(fields[3]),
            }
            manifest.Parts = append(manifest.Parts, part)
        }
    }

    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("读取清单文件时出错: %w", err)
    }

    // 基本校验
    if manifest.OriginalName == "" {
        return nil, fmt.Errorf("清单文件中缺少原始文件名")
    }
    if manifest.OriginalSHA256 == "" {
        return nil, fmt.Errorf("清单文件中缺少原始文件 SHA256")
    }
    if len(manifest.Parts) == 0 {
        return nil, fmt.Errorf("清单文件中没有分片信息")
    }

    // 校验原始文件 SHA256 格式(64 位十六进制)
    if len(manifest.OriginalSHA256) != 64 || !isHexString(manifest.OriginalSHA256) {
        return nil, fmt.Errorf("清单文件中原始文件 SHA256 格式无效: %s", manifest.OriginalSHA256)
    }
    if manifest.OriginalSize < 0 {
        return nil, fmt.Errorf("清单文件中原始文件大小非法: %d", manifest.OriginalSize)
    }
    // 校验加密元数据(防止损坏/被篡改的清单在解密时给出误导性错误)
    if manifest.Encrypted {
        if manifest.Cipher != cipherName {
            return nil, fmt.Errorf("清单文件中加密算法 %q 不受支持(当前支持 %s),该清单可能由更新版本创建", manifest.Cipher, cipherName)
        }
        if manifest.KDF != kdfName {
            return nil, fmt.Errorf("清单文件中密钥派生算法 %q 不受支持(当前支持 %s),该清单可能由更新版本创建", manifest.KDF, kdfName)
        }
        if len(manifest.Salt) != saltSize {
            return nil, fmt.Errorf("清单文件中加密盐值长度非法(应为 %d 字节,实际 %d 字节),清单可能已损坏", saltSize, len(manifest.Salt))
        }
        if manifest.ScryptN <= 0 || manifest.ScryptR <= 0 || manifest.ScryptP <= 0 {
            return nil, fmt.Errorf("清单文件中 scrypt 参数非法(N=%d,r=%d,p=%d)", manifest.ScryptN, manifest.ScryptR, manifest.ScryptP)
        }
    }
    // 校验清单声明的分片数量与实际记录一致
    if manifest.PartCount > 0 && manifest.PartCount != len(manifest.Parts) {
        return nil, fmt.Errorf("清单文件中分片数量(%d)与实际分片记录数(%d)不一致,清单可能已损坏", manifest.PartCount, len(manifest.Parts))
    }
    // 按序号排序,并校验序号连续(兼容 0-based 与 1-based 两种历史格式)
    sort.Slice(manifest.Parts, func(i, j int) bool {
        return manifest.Parts[i].Index < manifest.Parts[j].Index
    })
    base := manifest.Parts[0].Index
    for i, p := range manifest.Parts {
        if p.Index != base+i {
            return nil, fmt.Errorf("清单文件中分片序号不连续: 第 %d 条记录序号为 %d,期望 %d", i+1, p.Index, base+i)
        }
    }
    // 校验每个分片字段的合法性
    for _, p := range manifest.Parts {
        if p.FileName == "" {
            return nil, fmt.Errorf("清单文件中分片 %d 文件名为空", p.Index)
        }
        if strings.ContainsAny(p.FileName, `/\`) {
            return nil, fmt.Errorf("清单文件中分片 %d 文件名包含路径分隔符,疑似异常: %s", p.Index, p.FileName)
        }
        //这里应该检查其准确的等于比如64
        if len(p.FileName) > 1024 {
            return nil, fmt.Errorf("清单文件中分片 %d 文件名长度异常: %s", p.Index, p.FileName)
        }
        if p.Size < 1 {
            return nil, fmt.Errorf("清单文件中分片 %d 大小非法: %d 字节", p.Index, p.Size)
        }
        if len(p.SHA256) != 64 || !isHexString(p.SHA256) {
            return nil, fmt.Errorf("清单文件中分片 %d 的 SHA256 格式无效", p.Index)
        }
    }

    // 清单文件自身完整性校验
    manifestSHA256, err := computeFileSHA256(manifestPath)
    if err != nil {
        return nil, fmt.Errorf("无法计算清单文件 SHA256: %w", err)
    }

    matches := manifestNameRegex.FindStringSubmatch(filepath.Base(manifestPath))
    var nameSHA256 string
    if len(matches) == 4 {
        nameSHA256 = matches[2]
    }

    if nameSHA256 == "" {
        return nil, fmt.Errorf("清单文件名格式异常: %s", filepath.Base(manifestPath))
    }

    if manifestSHA256 != nameSHA256 {
        return nil, fmt.Errorf("清单文件已被修改或损坏:文件内容指纹(%s)与文件名中的校验值(%s)不一致", manifestSHA256, nameSHA256)
    }

    return manifest, nil
}

// isSplitDirectory:判断指定目录是否为一个有效的分割目录
// 判断依据:目录中是否存在符合命名规范的清单文件
//
// 这个函数用于 merge 命令中自动识别输入是单个分割目录还是包含多个分割目录的父目录
//
// 参数:
//   - dir: 目录路径
//
// 返回:
//   - true 表示是分割目录,false 表示不是
func isSplitDirectory(dir string) bool {
    _, err := findManifestFile(dir)
    return err == nil
}

// isPartsDirectory:判断目录名是否符合分割目录的命名规范(以 .parts 结尾)
//
// 分割目录的命名规范是:<原始文件名>.parts
// 例如:video.mp4.parts、document.pdf.parts
//
// 这个函数用于批量合并时筛选子目录,只处理符合命名规范的分割目录,忽略用户目录中可能存在的其他不相关子目录
//
// 参数:
//   - dirName: 目录名(不含路径)
//
// 返回:
//   - true 表示符合命名规范,false 表示不符合
func isPartsDirectory(dirName string) bool {
    return strings.HasSuffix(dirName, splitDirSuffix)
}
