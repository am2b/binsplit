package main

// 本文件实现文件分割逻辑,包括:
// - 单文件分割(按百分比,按数量等分,按目标分片大小)
// - 目录批量分割
// - 并行处理(利用多核 CPU 加速)
//
// 分割后的目录结构:
//  <输出目录>/
//    <原始文件名>.parts/
//      <原始文件名>-清单<SHA256>-<分片数量>.txt    ← 清单文件(动态命名,记录原始文件信息和分片列表)
//      <64字符随机名>                              ← 分片1
//      <64字符随机名>                              ← 分片2
//      ...

import (
    "fmt"
    "io"
    "os"
    "path/filepath"
    "sort"
    "strconv"
    "sync"
    "time"
)

// 分割目录的后缀名
const splitDirSuffix = ".parts"

// 单次分割允许的最大分片数量(1千)
// 防止用户误传极小目标大小(如 -s 1B)导致产生天文数字级分片,保护文件系统
const maxParts = 1000

// 分片处理任务,用于传递给 worker goroutine
type splitTask struct {
    index   int       // 分片序号(0-based)
    offset  int64     // 在原文件中的起始偏移(字节)
    size    int64     // 分片大小(字节)
    srcPath string    // 原文件路径
    destDir string    // 输出目录
    key     []byte    // 加密密钥(nil 表示不加密)
    prog    *progress // 进度条(nil 表示不显示进度)
}

// 分片处理结果,由 worker goroutine 返回
type splitResult struct {
    taskIndex int      // 分片序号(0-based),无论成功失败都填充,用于准确的错误定位
    partInfo  PartInfo // 分片信息(成功时有效)
    err       error    // 处理过程中的错误(失败时有效)
}

// splitFile 分割单个文件
// 处理流程:
//  1,获取原文件大小
//  2,计算每个分片的偏移量和大小(按百分比 / 按数量等分 / 按目标大小)
//  3,创建分割目录(<原文件名>.parts)
//  4,并行处理:
//     - 一个 goroutine 顺序读取原文件计算其 SHA256
//     - 多个 worker goroutine 并行读取原文件的不同区段,写入分片并计算分片的 SHA256
//  5,收集所有分片结果,按序号排序
//  6,写入清单文件(清单文件的文件名格式:原始文件名-清单SHA256-分片数量.txt)

// 健壮性保证:
//   - 分割目录已存在且非空时拒绝执行,避免混入旧分片/旧清单
//   - 任一环节失败时回滚本次已创建的全部文件,不留半成品目录
//   - 清单文件名长度超过文件系统的限制时提前报错

// 参数:
//   - srcPath: 原文件路径
//   - outputRoot: 输出目录(为空则使用当前目录)
//   - ratios: 百分比列表(如 [20, 50, 30]),为 nil 表示使用 targetSize 分割
//   - targetSize: 目标分片大小(字节),为 0 表示使用 ratios 分割
//   - workers: 并行 worker 数量
//   - password: 加密密码(非空则启用 AES-256-GCM 分片加密,为空则不加密)
//   - progressEnabled: 是否显示进度条(默认为 false 关闭)
//
// 返回:
//   - 错误信息
func splitFile(srcPath string, outputRoot string, ratios []float64, targetSize int64, workers int, password []byte, progressEnabled bool) error {
    // 获取原文件的绝对路径和基本信息
    srcAbs, err := filepath.Abs(srcPath)
    if err != nil {
        return fmt.Errorf("无法获取文件绝对路径: %w", err)
    }

    // 获取原文件大小
    fileInfo, err := os.Stat(srcAbs)
    if err != nil {
        return fmt.Errorf("无法获取文件信息: %w", err)
    }

    // 如果是目录的话,报错
    if fileInfo.IsDir() {
        return fmt.Errorf("%s 是目录,不是文件", srcPath)
    }

    totalSize := fileInfo.Size()
    if totalSize == 0 {
        return fmt.Errorf("文件 %s 大小为 0,无法分割", srcPath)
    }

    // 原文件名(不含路径)
    originalName := filepath.Base(srcAbs)

    // 确定输出目录
    if outputRoot == "" {
        outputRoot = "."
    }
    if err := ensureDir(outputRoot); err != nil {
        return err
    }

    // 加密密钥派生(传入密码才加密,每个文件使用独立的随机 salt 值)
    encrypted := len(password) > 0
    var encKey []byte
    var salt []byte
    if encrypted {
        // 每个文件生成独立 salt 值,避免不同文件共用同一密钥材料
        salt, err = generateSalt()
        if err != nil {
            return err
        }

        encKey, err = deriveKey(password, salt)
        if err != nil {
            return err
        }

        // 用完后擦除派生密钥(明文密码由调用方统一擦除)
        defer zeroBytes(encKey)
    }

    // 计算分片计划(按百分比或按目标大小)
    var offsets, sizes []int64
    if targetSize > 0 {
        // 按目标分片大小分割
        offsets, sizes, err = calculatePartOffsetsBySize(totalSize, targetSize)
    } else {
        // 按百分比分割(含按数量等分,二者都归一化为 ratios)
        offsets, sizes, err = calculatePartOffsets(totalSize, ratios)
    }
    if err != nil {
        return err
    }

    partCount := len(offsets)

    // 分割目录:<输出目录>/<原文件名>.parts
    splitDir := filepath.Join(outputRoot, originalName+splitDirSuffix)

    // 预检清单文件名长度,避免写入时才发现超长而留下半成品目录
    // 格式:原始文件名-清单SHA256(64)-分片数量.txt
    manifestNameLen := len(originalName) + 1 + 64 + 1 + len(strconv.Itoa(partCount)) + len(".txt")
    if manifestNameLen > 255 {
        return fmt.Errorf("生成的清单文件名将超过文件系统 255 字节限制(约 %d 字节),请缩短原始文件名或减少分片数量", manifestNameLen)
    }

    // 创建/检查分割目录
    dirExisted := false
    if info, statErr := os.Stat(splitDir); statErr == nil {
        if !info.IsDir() {
            return fmt.Errorf("输出路径 %s 已存在且不是目录,无法创建分割目录", splitDir)
        }
        entries, readErr := os.ReadDir(splitDir)
        if readErr != nil {
            return fmt.Errorf("无法读取分割目录 %s: %w", splitDir, readErr)
        }
        if len(entries) > 0 {
            return fmt.Errorf("分割目录 %s 已存在且非空,为避免混入旧分片或旧清单,请先删除或改名后再分割", splitDir)
        }
        dirExisted = true
    } else if !os.IsNotExist(statErr) {
        return fmt.Errorf("无法检查分割目录 %s: %w", splitDir, statErr)
    } else {
        if err := ensureDir(splitDir); err != nil {
            return err
        }
    }

    // 失败回滚函数:删除本次分割创建的所有文件
    // 因为目录在开始时保证为空,所以目录内所有文件都是本次创建的,可安全删除
    cleanup := func(err error) error {
        if entries, rerr := os.ReadDir(splitDir); rerr == nil {
            for _, en := range entries {
                _ = os.Remove(filepath.Join(splitDir, en.Name()))
            }
        }
        if !dirExisted {
            // 仅删除本次创建的目录本身
            _ = os.Remove(splitDir)
        }
        return err
    }

    fmt.Printf("正在分割文件: %s\n", srcPath)
    fmt.Printf("文件大小: %s (%d 字节)\n", formatFileSize(totalSize), totalSize)
    fmt.Printf("分片数量: %d\n", partCount)
    if targetSize > 0 {
        fmt.Printf("目标分片大小: %s(末片可能小于目标值)\n", formatFileSize(targetSize))
    }
    fmt.Printf("输出目录: %s\n", splitDir)
    if encrypted {
        fmt.Printf("加密: 是(%s,密钥派生 %s,盐值已记录在清单中)\n", cipherName, kdfName)
    } else {
        fmt.Printf("加密: 否\n")
    }
    fmt.Println("---")
    // 打印分片计划
    if targetSize > 0 {
        for i := range offsets {
            fmt.Printf("  分片 %d: 偏移=%d, 大小=%s\n", i+1, offsets[i], formatFileSize(sizes[i]))
        }
    } else {
        for i := range offsets {
            fmt.Printf("  分片 %d: 偏移=%d, 大小=%s (%.2f%%)\n", i+1, offsets[i], formatFileSize(sizes[i]), ratios[i])
        }
    }
    fmt.Println("---")

    // 并行处理阶段
    // 使用 WaitGroup 等待所有 goroutine 完成
    var wg sync.WaitGroup
    // 用于收集分片结果的通道(带缓冲,避免 worker 阻塞)
    resultCh := make(chan splitResult, partCount)
    // 限制并发数的信号量通道
    semaphore := make(chan struct{}, workers)

    // 并行任务1:计算原文件的SHA256
    var originalSHA256 string
    var sha256Err error
    wg.Add(1)
    go func() {
        defer wg.Done()
        originalSHA256, sha256Err = computeFileSHA256(srcAbs)
    }()

    // 创建进度条(仅 progressEnabled 时启动后台刷新协程,否则零开销)
    prog := newProgress(progressEnabled, totalSize, filepath.Base(srcAbs))
    prog.start()
    defer prog.finish()

    // 并行任务2:并行处理各分片
    startTime := time.Now()
    for i := range offsets {
        wg.Add(1)
        task := splitTask{
            index:   i,
            offset:  offsets[i],
            size:    sizes[i],
            srcPath: srcAbs,
            destDir: splitDir,
            key:     encKey,
            prog:    prog,
        }
        go func(t splitTask) {
            defer wg.Done()
            // 获取信号量(控制并发数)
            semaphore <- struct{}{}
            // 释放信号量
            defer func() { <-semaphore }()
            // 处理单个分片
            resultCh <- processSinglePart(t)
        }(task)
    }

    // 等待所有 goroutine 完成
    wg.Wait()
    close(resultCh)
    elapsed := time.Since(startTime)

    // 检查总 SHA256 计算是否出错
    if sha256Err != nil {
        return cleanup(fmt.Errorf("计算原文件 SHA256 失败: %w", sha256Err))
    }

    // 收集所有分片结果
    parts := make([]PartInfo, 0, partCount)
    for result := range resultCh {
        if result.err != nil {
            return cleanup(fmt.Errorf("分片 %d 处理失败: %w", result.taskIndex+1, result.err))
        }
        parts = append(parts, result.partInfo)
    }

    // 按分片序号排序(确保顺序正确)
    sort.Slice(parts, func(i, j int) bool {
        return parts[i].Index < parts[j].Index
    })

    // 写入清单文件
    // 构建清单信息(记录创建工具与版本,便于合并出错时选择正确的软件版本)
    manifest := &Manifest{
        ToolName:       "binsplit",
        Version:        Version,
        Encrypted:      encrypted,
        Cipher:         cipherName,
        KDF:            kdfName,
        Salt:           salt,
        ScryptN:        scryptN,
        ScryptR:        scryptR,
        ScryptP:        scryptP,
        OriginalName:   originalName,
        OriginalSize:   totalSize,
        OriginalSHA256: originalSHA256,
        PartCount:      len(parts),
        CreatedAt:      time.Now(),
        Parts:          parts,
    }

    // 写入清单文件
    if err := writeManifest(splitDir, manifest); err != nil {
        return cleanup(fmt.Errorf("写入清单文件失败: %w", err))
    }

    // 打印完成信息
    fmt.Printf("分割完成!耗时: %v\n", elapsed)
    fmt.Printf("原始文件 SHA256: %s\n", originalSHA256)
    fmt.Printf("分片已保存至: %s\n", splitDir)
    fmt.Println()

    return nil
}

// processSinglePart 处理单个分片:从原文件指定偏移读取指定字节数,写入分片文件,同时计算分片的 SHA256
// 每个 worker 独立打开原文件(拥有独立的文件描述符和读取位置),这样多个 worker 可以并行读取文件的不同区段,不会互相干扰
//
// 参数:
//   - task: 分片任务信息
//
// 返回:
//   - 分片处理结果(无论成功失败都携带准确的 taskIndex,便于错误定位)
func processSinglePart(task splitTask) splitResult {
    // 生成唯一的 64 字符随机文件名
    partName, err := generateUniqueRandomName(task.destDir)
    if err != nil {
        return splitResult{taskIndex: task.index, err: err}
    }

    // 分片文件的完整路径
    partPath := filepath.Join(task.destDir, partName)

    // 以只读模式打开原文件(每个 worker 独立打开,避免共享文件偏移)
    srcFile, err := os.Open(task.srcPath)
    if err != nil {
        return splitResult{taskIndex: task.index, err: fmt.Errorf("无法打开原文件: %w", err)}
    }
    defer srcFile.Close()

    // 将文件读取位置移动到该分片的起始偏移
    if _, err := srcFile.Seek(task.offset, io.SeekStart); err != nil {
        return splitResult{taskIndex: task.index, err: fmt.Errorf("无法定位文件偏移 %d: %w", task.offset, err)}
    }

    // 创建分片文件
    destFile, err := os.Create(partPath)
    if err != nil {
        return splitResult{taskIndex: task.index, err: fmt.Errorf("无法创建分片文件 %s: %w", partPath, err)}
    }
    defer destFile.Close()

    // 使用 io.LimitReader 限制只读取该分片大小的字节数
    // 这样即使原文件后面还有数据,也不会多读
    limitedReader := io.LimitReader(srcFile, task.size)

    // 包装写入目标以汇报进度(未启用进度时零开销)
    dest := io.Writer(destFile)
    if task.prog != nil {
        dest = &countingWriter{w: destFile, p: task.prog}
    }

    var written int64
    var partSHA256 string
    if task.key != nil {
        // 加密模式:明文流入 SHA256 计算,密文写入分片文件,清单记录明文 SHA256
        // 注意:written 是明文长度,不是密文长度
        written, partSHA256, err = encryptPartWithSHA(limitedReader, dest, task.key)
    } else {
        // 普通模式:边读边写边算 SHA256(一次读取完成三个操作)
        written, partSHA256, err = computeReaderSHA256(limitedReader, dest)
    }
    if err != nil {
        return splitResult{taskIndex: task.index, err: fmt.Errorf("处理分片数据时出错: %w", err)}
    }

    // 校验写入的字节数是否符合预期
    if written != task.size {
        return splitResult{
            taskIndex: task.index,
            err:       fmt.Errorf("分片大小不匹配: 预期 %d 字节, 实际写入 %d 字节", task.size, written),
        }
    }

    // 刷新文件缓冲区,确保数据全部写入磁盘
    if err := destFile.Sync(); err != nil {
        // Sync 失败不影响数据正确性(操作系统最终会刷盘),仅打印警告
        fmt.Printf("警告: 分片文件 %s 同步到磁盘失败: %v\n", partPath, err)
    }

    return splitResult{
        taskIndex: task.index,
        partInfo: PartInfo{
            // 序号从 1 开始(与清单展示一致)
            Index:    task.index + 1,
            FileName: partName,
            Size:     written,
            SHA256:   partSHA256,
        },
    }
}

// calculatePartOffsets:根据百分比计算每个分片的偏移量和大小
//
// 关键设计:最后一个分片取"剩余所有字节",避免浮点误差导致字节丢失
// 例如:100 字节按 33%, 33%, 34% 分割:
//   - 分片1: 100 * 0.33 = 33 字节
//   - 分片2: 100 * 0.33 = 33 字节
//   - 分片3: 100 - 33 - 33 = 34 字节(取剩余,而非 100*0.34=34)
//
// 健壮性保证:
//   - 分片数量不能超过文件字节数(每个分片至少 1 字节),否则报错
//   - 分片数量不能超过 maxParts 上限,防止资源耗尽
//   - 最终校验所有分片大小之和必须精确等于原文件大小
//
// 参数:
//   - totalSize: 原文件总大小(字节)
//   - ratios: 百分比列表
//
// 返回:
//   - offsets: 每个分片的起始偏移量
//   - sizes: 每个分片的大小
//   - 错误信息
func calculatePartOffsets(totalSize int64, ratios []float64) ([]int64, []int64, error) {
    n := len(ratios)
    if n == 0 {
        return nil, nil, fmt.Errorf("没有提供任何分片比例")
    }
    if n > maxParts {
        return nil, nil, fmt.Errorf("分片数量(%d)超过上限 %d,请增大分片大小或减少分片数量", n, maxParts)
    }
    if int64(n) > totalSize {
        return nil, nil, fmt.Errorf("分片数量(%d)大于文件大小(%d 字节),每个分片至少需要 1 字节", n, totalSize)
    }

    offsets := make([]int64, n)
    sizes := make([]int64, n)
    var offset int64 = 0
    for i := 0; i < n; i++ {
        offsets[i] = offset
        if i == n-1 {
            // 最后一个分片取剩余所有字节,确保总和精确等于原文件大小
            sizes[i] = totalSize - offset
        } else {
            // 按百分比计算大小,使用 float64 转换后截断为整数
            sizes[i] = int64(float64(totalSize) * ratios[i] / 100.0)
            // 确保至少 1 字节(避免百分比极小导致 0 字节分片)
            if sizes[i] <= 0 {
                sizes[i] = 1
            }
        }
        offset += sizes[i]
    }

    // 防御性校验:所有分片大小必须为正,且总和等于原文件大小
    var sum int64
    for i, s := range sizes {
        if s < 1 {
            return nil, nil, fmt.Errorf("分片 %d 大小非法: %d 字节", i+1, s)
        }
        sum += s
    }
    if sum != totalSize {
        return nil, nil, fmt.Errorf("分片大小总和(%d)与原文件大小(%d)不一致", sum, totalSize)
    }

    return offsets, sizes, nil
}

// calculatePartOffsetsBySize:按目标分片大小计算每个分片的偏移量和大小
//
// 语义:前 N-1 个分片均为目标大小,最后一个分片取剩余字节(可能小于目标大小)
// 分片数量 N = ceil(总大小 / 目标大小)
//
// 例如:总大小 1000 字节,目标 300 字节 → 分片大小为 [300, 300, 300, 100]
//
// 参数:
//   - totalSize: 原文件总大小(字节)
//   - targetSize: 目标分片大小(字节)
//
// 返回:
//   - offsets: 每个分片的起始偏移量
//   - sizes: 每个分片的大小
//   - 错误信息
func calculatePartOffsetsBySize(totalSize int64, targetSize int64) ([]int64, []int64, error) {
    if targetSize < 1 {
        return nil, nil, fmt.Errorf("目标分片大小必须大于 0")
    }

    // 计算分片数量:向上取整(避免 totalSize+targetSize-1 溢出 int64)
    partCount := totalSize / targetSize
    if totalSize%targetSize != 0 {
        partCount++
    }
    if partCount < 2 {
        return nil, nil, fmt.Errorf("目标分片大小 %s 过大,文件只能分成 1 片(需至少 2 片才有意义)", formatFileSize(targetSize))
    }
    if partCount > maxParts {
        return nil, nil, fmt.Errorf("按目标大小 %s 分割将产生 %d 个分片,超过上限 %d,请增大目标分片大小", formatFileSize(targetSize), partCount, maxParts)
    }

    offsets := make([]int64, partCount)
    sizes := make([]int64, partCount)
    var offset int64 = 0
    for i := int64(0); i < partCount; i++ {
        offsets[i] = offset
        if i == partCount-1 {
            // 最后一个分片取剩余字节
            sizes[i] = totalSize - offset
        } else {
            sizes[i] = targetSize
        }
        offset += sizes[i]
    }

    return offsets, sizes, nil
}

// splitDirectory:批量分割指定目录下的所有普通文件
//
// 遍历目录下的每个文件,对每个文件调用 splitFile 进行分割
// 目前是顺序处理每个文件(文件内部是并行的)
//
// 参数:
//   - inputDir: 输入目录路径
//   - outputRoot: 输出根目录
//   - ratios: 百分比列表
//   - targetSize: 目标分片大小(0 表示使用 ratios)
//   - workers: 每个文件的并行 worker 数
//   - password: 加密密码(非空则加密,nil/空则不加密)
//   - progressEnabled: 是否显示进度条
//
// 返回:
//   - 错误信息
//
// 注意:
//   - -s批量分割时,如果某个文件小于目标分片大小,那么会报错并且跳过该文件,而不是整体退出
func splitDirectory(inputDir string, outputRoot string, ratios []float64, targetSize int64, workers int, password []byte, progressEnabled bool) error {
    // 列出目录下所有普通文件
    files, err := listFilesInDir(inputDir)
    if err != nil {
        return err
    }

    if len(files) == 0 {
        return fmt.Errorf("目录 %s 中没有可分割的文件", inputDir)
    }

    fmt.Printf("找到 %d 个文件待分割\n", len(files))
    fmt.Println("========================================")

    // 统计成功和失败数量
    successCount := 0
    failCount := 0
    for i, fileName := range files {
        fmt.Printf("\n[%d/%d] 处理文件: %s\n", i+1, len(files), fileName)
        fmt.Println("----------------------------------------")
        srcPath := filepath.Join(inputDir, fileName)
        if err := splitFile(srcPath, outputRoot, ratios, targetSize, workers, password, progressEnabled); err != nil {
            fmt.Printf("错误: 分割文件 %s 失败: %v\n", fileName, err)
            failCount++
            continue
        }
        successCount++
    }

    fmt.Println("\n========================================")
    fmt.Printf("批量分割完成: 成功 %d 个, 失败 %d 个\n", successCount, failCount)
    if failCount > 0 {
        return fmt.Errorf("有 %d 个文件分割失败", failCount)
    }

    return nil
}
