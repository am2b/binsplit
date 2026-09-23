package main

// 本文件实现文件合并逻辑,包括:
// - 单个分割目录的合并
// - 包含多个分割目录的父目录批量合并
// - 合并前并行校验各分片完整性
// - 合并后计算总 SHA256 并与清单中的值比对
//
// 合并流程:
// 1,读取清单文件,获取原始文件名,总 SHA256,分片列表
// 2,并行校验每个分片的 SHA256(与清单中记录的值比对)
// 3,按顺序将所有分片拼接写入输出文件,同时计算总 SHA256
// 4,比对计算出的总 SHA256 与清单中的值
// 5,打印比对结果

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "sync"
    "time"
)

// mergeDirectory:合并单个分割目录中的所有分片,恢复为原始文件
//
// 参数:
//   - splitDir: 分割目录路径(包含清单文件和分片文件)
//   - outputDir: 输出目录(合并后的文件放在这里)
//   - workers: 并行校验分片时的 worker 数
//   - password: 解密密码(清单标记已加密但未传密码时直接报错)
//   - progressEnabled: 是否显示进度条
//
// 返回:
//   - 错误信息
func mergeDirectory(splitDir string, outputDir string, workers int, password []byte, progressEnabled bool) error {
    // 读取清单文件
    manifest, err := readManifest(splitDir)
    if err != nil {
        return fmt.Errorf("读取清单文件失败: %w", err)
    }

    fmt.Printf("正在合并: %s\n", splitDir)

    fmt.Println("---")

    // 打印清单文件中的软件版本信息(合并出错时,用户可据此选择正确的软件版本重试)
    creator := manifest.ToolName
    if creator == "" {
        return errors.New("从清单文件中读取软件名称失败")
    }
    fmt.Printf("分割时的软件: %s %s\n", creator, manifest.Version)

    if manifest.Version != "" && manifest.Version != Version {
        fmt.Printf("当前软件: binsplit %s(与创建版本不同)\n", Version)
        if compareVersions(manifest.Version, Version) > 0 {
            fmt.Printf("  ⚠️ 警告: 清单由更新版本的 %s 创建。若本次合并失败,请改用 binsplit %s 重试,以免数据无法恢复。\n",
                creator, manifest.Version)
        } else {
            fmt.Printf("  提示: 清单由旧版本创建,当前版本兼容合并。\n")
        }
    } else if manifest.Version != "" {
        fmt.Printf("当前软件: binsplit %s\n", Version)
        fmt.Println("---")
    }

    fmt.Printf("原始文件名: %s\n", manifest.OriginalName)
    fmt.Printf("原始文件大小: %s (%d 字节)\n", formatFileSize(manifest.OriginalSize), manifest.OriginalSize)
    fmt.Printf("分片数量: %d\n", manifest.PartCount)
    fmt.Printf("原始文件 SHA256: %s\n", manifest.OriginalSHA256)

    // 加密状态处理
    var decKey []byte
    if manifest.Encrypted {
        fmt.Printf("加密: 是(%s,密钥派生 %s)\n", manifest.Cipher, manifest.KDF)
        if len(password) == 0 {
            return fmt.Errorf("该分割目录的分片已加密,必须使用 -password 提供密码才能合并,若不知道密码,将无法恢复数据")
        }

        if manifest.Salt == nil {
            return fmt.Errorf("清单缺少加密盐值,无法解密(清单可能已损坏)")
        }

        key, err := deriveKey(password, manifest.Salt)
        if err != nil {
            return err
        }
        decKey = key
        defer zeroBytes(decKey)
        fmt.Println("  正在使用提供的密码派生解密密钥...")
    } else {
        fmt.Printf("加密: 否\n")
        if len(password) > 0 {
            fmt.Println("  提示: 清单未加密,忽略传入的 -password。")
        }
    }

    fmt.Println("---")

    // 输出目录
    if outputDir == "" {
        outputDir = "."
    }
    if err := ensureDir(outputDir); err != nil {
        return err
    }

    // 输出文件路径:使用清单中记录的原始文件名(恢复文件名和后缀)
    outputPath := filepath.Join(outputDir, manifest.OriginalName)

    // 检查输出文件是否已存在,避免误覆盖
    if _, err := os.Stat(outputPath); err == nil {
        // 文件已存在,自动添加序号后缀(如 video_1.mp4, video_2.mp4)
        outputPath, err = generateUniqueOutputPath(outputDir, manifest.OriginalName)
        if err != nil {
            // 极端情况:找不到任何不冲突的文件名(单文件合并时直接退出,批量合并时由 mergeParentDirectory 捕获后跳过该目录继续)
            return err
        }
        fmt.Printf("提示: 输出文件已存在,将保存为: %s\n", filepath.Base(outputPath))
    }

    // 阶段1:并行校验所有分片的完整性
    fmt.Println("正在校验分片完整性...")

    if err := verifyAllParts(splitDir, manifest.Parts, workers, decKey); err != nil {
        return fmt.Errorf("分片完整性校验失败: %w", err)
    }

    fmt.Println("所有分片校验通过!")
    fmt.Println("---")

    // 阶段2:按顺序合并分片,同时计算总 SHA256
    fmt.Println("正在合并分片...")

    // 创建进度条(仅 progressEnabled 时启动)
    var totalPartBytes int64
    for _, p := range manifest.Parts {
        totalPartBytes += p.Size
    }
    prog := newProgress(progressEnabled, totalPartBytes, filepath.Base(outputPath))
    prog.start()
    startTime := time.Now()

    mergedSHA256, err := mergePartsToFile(splitDir, manifest.Parts, outputPath, decKey, prog)

    prog.stop()

    if err != nil {
        // 合并失败时删除不完整的输出文件
        os.Remove(outputPath)
        return fmt.Errorf("合并分片失败: %w", err)
    }

    elapsed := time.Since(startTime)

    // 获取输出文件大小,用于校验
    outputInfo, err := os.Stat(outputPath)
    if err != nil {
        return fmt.Errorf("无法获取输出文件信息: %w", err)
    }

    fmt.Printf("合并完成!耗时: %v\n", elapsed)
    fmt.Printf("输出文件: %s\n", outputPath)
    fmt.Printf("输出文件大小: %s (%d 字节)\n", formatFileSize(outputInfo.Size()), outputInfo.Size())

    fmt.Println("---")

    // 阶段3:比对总 SHA256
    fmt.Println("正在比对 SHA256...")
    fmt.Printf("  清单记录值: %s\n", manifest.OriginalSHA256)
    fmt.Printf("  合并计算值: %s\n", mergedSHA256)

    if mergedSHA256 == manifest.OriginalSHA256 {
        fmt.Println("  ✅ SHA256 比对一致!文件完整性验证通过。")
    } else {
        fmt.Println("  ❌ SHA256 比对不一致!文件可能已损坏。")
        // 比对失败时不删除文件,让用户可以自行排查
        return fmt.Errorf("SHA256 比对失败: 期望值 %s, 实际值 %s",
            manifest.OriginalSHA256, mergedSHA256)
    }

    // 校验文件大小
    if outputInfo.Size() != manifest.OriginalSize {
        fmt.Printf("  ⚠️  文件大小不一致: 预期 %d 字节, 实际 %d 字节\n",
            manifest.OriginalSize, outputInfo.Size())
    } else {
        fmt.Println("  ✅ 文件大小一致。")
    }

    fmt.Println()

    return nil
}

// verifyAllParts:并行校验所有分片的 SHA256 是否与清单中记录的值一致
//
// 使用 worker 池控制并发数,每个 worker 独立读取一个分片文件并计算 SHA256
//
// 参数:
//   - splitDir: 分割目录路径
//   - parts: 分片信息列表
//   - workers: 并行 worker 数
//   - key: 解密密钥(非 nil 表示分片已加密,需先解密再校验明文 SHA)
//
// 返回:
//   - 错误信息(任意分片校验失败则返回错误)
func verifyAllParts(splitDir string, parts []PartInfo, workers int, key []byte) error {
    if workers <= 0 {
        workers = 1
    }

    // 任务通道:将待校验的分片分发给 worker
    taskCh := make(chan PartInfo, len(parts))

    // 错误通道:收集校验失败的结果
    errCh := make(chan error, len(parts))

    var wg sync.WaitGroup

    // 启动 worker 池
    for w := 0; w < workers; w++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for part := range taskCh {
                partPath := filepath.Join(splitDir, part.FileName)
                // 打开分片文件
                f, err := os.Open(partPath)
                if err != nil {
                    errCh <- fmt.Errorf("分片 %d 文件无法打开: %w", part.Index, err)
                    continue
                }
                if key != nil {
                    // 加密分片:解密后计算明文 SHA256 并与清单比对
                    hasher := sha256.New()
                    plainLen, derr := decryptStream(f, hasher, key)
                    f.Close()
                    if derr != nil {
                        errCh <- fmt.Errorf("分片 %d 解密失败: %w", part.Index, derr)
                        continue
                    }
                    if plainLen != part.Size {
                        errCh <- fmt.Errorf("分片 %d 解密后大小不匹配: 预期 %d 字节, 实际 %d 字节",
                            part.Index, part.Size, plainLen)
                        continue
                    }
                    actualSHA256 := hex.EncodeToString(hasher.Sum(nil))
                    if actualSHA256 != part.SHA256 {
                        errCh <- fmt.Errorf("分片 %d 明文 SHA256 不匹配: 预期 %s, 实际 %s",
                            part.Index, part.SHA256, actualSHA256)
                    }
                } else {
                    // 未加密分片:直接计算文件 SHA256
                    f.Close()
                    actualSHA256, err := computeFileSHA256(partPath)
                    if err != nil {
                        errCh <- fmt.Errorf("分片 %d SHA256 计算失败: %w", part.Index, err)
                        continue
                    }
                    if actualSHA256 != part.SHA256 {
                        errCh <- fmt.Errorf("分片 %d SHA256 不匹配: 预期 %s, 实际 %s",
                            part.Index, part.SHA256, actualSHA256)
                    }
                }
            }
        }()
    }

    // 将所有分片任务送入通道
    for _, part := range parts {
        taskCh <- part
    }
    close(taskCh)

    // 等待所有 worker 完成
    wg.Wait()
    close(errCh)

    // 收集所有错误
    var errors []error
    for err := range errCh {
        errors = append(errors, err)
    }

    if len(errors) > 0 {
        // 打印所有校验失败的信息
        for _, e := range errors {
            fmt.Printf("  ❌ %v\n", e)
        }
        return fmt.Errorf("共有 %d 个分片校验失败", len(errors))
    }

    return nil
}

// mergePartsToFile:按顺序将所有分片拼接写入输出文件,同时计算总 SHA256
//
// 实现要点:
//   - 必须按分片序号顺序写入,否则合并后的文件会错乱
//   - 使用 io.MultiWriter 同时写入输出文件和 SHA256 哈希器,一次读取完成两个操作
//
// 参数:
//   - splitDir: 分割目录路径
//   - parts: 分片信息列表(已按序号排序)
//   - outputPath: 输出文件路径
//   - key: 解密密钥(非 nil 表示分片已加密,需解密后写入)
//   - prog: 进度条(nil 表示不显示)
//
// 返回:
//   - 合并后文件的 SHA256
//   - 错误信息
func mergePartsToFile(splitDir string, parts []PartInfo, outputPath string, key []byte, prog *progress) (string, error) {
    // 无论清单文件中分片记录的顺序如何,都严格按序号拼接
    sortedParts := make([]PartInfo, len(parts))
    copy(sortedParts, parts)
    sort.Slice(sortedParts, func(i, j int) bool {
        return sortedParts[i].Index < sortedParts[j].Index
    })

    // 创建输出文件
    outputFile, err := os.Create(outputPath)
    if err != nil {
        return "", fmt.Errorf("无法创建输出文件 %s: %w", outputPath, err)
    }
    defer outputFile.Close()

    // 创建 SHA256 哈希器,用于计算合并后文件的总哈希
    // sha256.New() 返回的 hash.Hash 已经实现了 io.Writer 接口
    hasher := sha256.New()

    // 创建多路写入器:数据同时写入输出文件和哈希器
    multiWriter := io.MultiWriter(outputFile, hasher)

    // 包装写入目标以汇报进度(未启用进度时零开销)
    dest := io.Writer(multiWriter)
    if prog != nil {
        dest = &countingWriter{w: multiWriter, p: prog}
    }

    // 缓冲区,用于分块拷贝
    buf := make([]byte, sha256BufferSize)

    // 按顺序处理每个分片
    for i, part := range parts {
        partPath := filepath.Join(splitDir, part.FileName)

        // 打开分片文件
        partFile, err := os.Open(partPath)
        if err != nil {
            return "", fmt.Errorf("无法打开分片 %d (%s): %w", part.Index, part.FileName, err)
        }

        var written int64
        if key != nil {
            // 加密分片:解密为明文后写入多路写入器
            written, err = decryptStream(partFile, dest, key)
            partFile.Close()
            if err != nil {
                return "", fmt.Errorf("解密分片 %d 时出错: %w", part.Index, err)
            }
        } else {
            // 未加密分片:直接拷贝到多路写入器
            written, err = io.CopyBuffer(dest, partFile, buf)
            partFile.Close() // 立即关闭,不 defer(因为在循环中)
            if err != nil {
                return "", fmt.Errorf("写入分片 %d 时出错: %w", part.Index, err)
            }
        }

        // 校验写入字节数
        if written != part.Size {
            return "", fmt.Errorf("分片 %d 大小不匹配: 预期 %d 字节, 实际写入 %d 字节",
                part.Index, part.Size, written)
        }

        // 分片拷贝完成:主动渲染精确进度帧(done 已包含本分片),
        // 再用换行定格本行,避免显示后台刷新协程的过期帧(如 99.7%)
        if prog != nil {
            prog.render()
        }

        // 打印进度
        fmt.Printf("  已合并分片 %d/%d (%s)\n", i+1, len(parts), part.FileName)
        // 最后一个分片完成后立即停止后台刷新协程,防止后续Sync/SHA计算期间再画出多余帧
        if i == len(parts)-1 && prog != nil {
            prog.stop()
        }
    }

    // 刷新输出文件到磁盘
    fmt.Println("正在将合并结果同步到磁盘...")
    if err := outputFile.Sync(); err != nil {
        return "", fmt.Errorf("输出文件同步到磁盘失败: %w", err)
    }

    // 获取最终的SHA256(哈希结果转为十六进制字符串)
    return hex.EncodeToString(hasher.Sum(nil)), nil
}

// generateUniqueOutputPath:在输出目录中生成一个不与现有文件冲突的输出路径
// 如果原文件名已存在,则在文件名(不含后缀)后添加 _1, _2 等序号
//
// 例如:
//   - video.mp4 已存在 → video_1.mp4
//   - video_1.mp4 也存在 → video_2.mp4
//
// 参数:
//   - outputDir: 输出目录
//   - originalName: 原始文件名
//
// 返回:
//   - 唯一的输出文件路径
func generateUniqueOutputPath(outputDir string, originalName string) (string, error) {
    // 添加序号的最大尝试次数(_1 到 _9999)
    const maxUniqueSuffixTries = 10000

    // 分离文件名和扩展名
    ext := filepath.Ext(originalName)
    baseName := originalName[:len(originalName)-len(ext)]

    // 尝试添加序号,直到找到不冲突的文件名
    for i := 1; i < maxUniqueSuffixTries; i++ {
        candidate := fmt.Sprintf("%s_%d%s", baseName, i, ext)
        candidatePath := filepath.Join(outputDir, candidate)
        if _, err := os.Stat(candidatePath); os.IsNotExist(err) {
            return candidatePath, nil
        }
    }

    // 极端情况:_1 到 _9999 全部冲突
    return "", fmt.Errorf("无法为 %s 生成不冲突的输出文件名(%s_1 到 %s_%d 均已被占用),请清理输出目录 %s 后重试",
        originalName, baseName, baseName, maxUniqueSuffixTries-1, outputDir)
}

// mergeParentDirectory:批量合并指定目录下的所有分割子目录
//
// 遍历父目录下的每个子目录,只有同时满足以下两个条件的子目录才会被处理:
// 1,目录名以 ".parts" 结尾(符合分割目录命名规范)
// 2,目录中存在符合命名规范的清单文件
//
// 这样可以忽略用户目录中可能存在的其他不相关子目录和文件
//
// 参数:
//   - parentDir: 父目录路径(包含多个分割子目录)
//   - outputDir: 输出目录
//   - workers: 每个合并任务的并行 worker 数
//   - password: 解密密码(nil/空表示不提供)
//   - progressEnabled: 是否显示进度条
//
// 返回:
//   - 错误信息
func mergeParentDirectory(parentDir string, outputDir string, workers int, password []byte, progressEnabled bool) error {
    // 列出所有子目录
    subDirs, err := listSubDirs(parentDir)
    if err != nil {
        return err
    }

    if len(subDirs) == 0 {
        return fmt.Errorf("目录 %s 中没有子目录", parentDir)
    }

    // 筛选出符合命名规范且包含清单文件的分割目录
    // 第一步:检查目录名是否以 ".parts" 结尾
    // 第二步:检查目录中是否存在清单文件
    var splitDirs []string
    var ambiguousDirs []string
    for _, dirName := range subDirs {
        // 只处理符合 ".parts" 命名规范的子目录,忽略其他不相关目录
        if !isPartsDirectory(dirName) {
            continue
        }
        fullPath := filepath.Join(parentDir, dirName)
        if isSplitDirectory(fullPath) {
            splitDirs = append(splitDirs, fullPath)
        } else if _, mErr := findManifestFile(fullPath); errors.Is(mErr, ErrMultipleManifests) {
            // 该目录存在多个清单文件,属于歧义目录,记录并整体报错,避免静默跳过
            ambiguousDirs = append(ambiguousDirs, dirName)
        }
    }

    if len(ambiguousDirs) > 0 {
        return fmt.Errorf("以下分割目录存在多个清单文件,无法确定使用哪一个,请先清理: %s", strings.Join(ambiguousDirs, "、"))
    }
    if len(splitDirs) == 0 {
        return fmt.Errorf("目录 %s 中没有找到有效的分割目录(名称以 .parts 结尾且包含清单文件的子目录)", parentDir)
    }

    fmt.Printf("找到 %d 个分割目录待合并\n", len(splitDirs))
    fmt.Println("========================================")

    // 统计成功和失败数量
    successCount := 0
    failCount := 0

    for i, splitDir := range splitDirs {
        fmt.Printf("\n[%d/%d] 合并目录: %s\n", i+1, len(splitDirs), filepath.Base(splitDir))
        fmt.Println("----------------------------------------")

        if err := mergeDirectory(splitDir, outputDir, workers, password, progressEnabled); err != nil {
            fmt.Printf("错误: 合并目录 %s 失败: %v\n", filepath.Base(splitDir), err)
            failCount++
            continue
        }
        successCount++
    }

    fmt.Println("\n========================================")
    fmt.Printf("批量合并完成: 成功 %d 个, 失败 %d 个\n", successCount, failCount)

    if failCount > 0 {
        return fmt.Errorf("有 %d 个目录合并失败", failCount)
    }

    return nil
}
