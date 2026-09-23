package main

// 本文件提供工具函数:SHA256 计算,随机文件名生成,百分比解析,文件大小格式化等

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "math"
    "os"
    "strconv"
    "strings"
    "unicode"
)

// 计算 SHA256 时使用的缓冲区大小(1MB),平衡内存占用与系统调用次数
const sha256BufferSize = 1024 * 1024

// computeFileSHA256:流式计算指定文件的 SHA256 哈希值
// 使用流式读取而非一次性读入内存,因此可以处理超大文件(几十 GB 也没问题)
//
// 参数:
//   - filePath: 要计算哈希的文件路径
//
// 返回:
//   - 十六进制字符串形式的SHA256(64个字符)
//   - 错误信息(如果文件无法打开或读取)
func computeFileSHA256(filePath string) (string, error) {
    // 以只读模式打开文件
    f, err := os.Open(filePath)
    if err != nil {
        return "", fmt.Errorf("无法打开文件 %s: %w", filePath, err)
    }
    defer f.Close()

    // 创建 SHA256 哈希器
    hasher := sha256.New()

    // 创建缓冲区,用于分块读取文件
    buf := make([]byte, sha256BufferSize)

    // 循环读取文件内容并写入哈希器
    // io.CopyBuffer 会一直读到 EOF,每次最多读 buf 大小的数据
    if _, err := io.CopyBuffer(hasher, f, buf); err != nil {
        return "", fmt.Errorf("读取文件 %s 时出错: %w", filePath, err)
    }

    // 将哈希结果转为十六进制字符串
    return hex.EncodeToString(hasher.Sum(nil)), nil
}

// computeReaderSHA256:从一个 io.Reader 流式计算 SHA256,同时将数据透传给 writer
// 这个函数在分割时非常有用:边读边写分片,同时计算该分片的 SHA256,
// 避免了写完后再重新读一遍来算哈希,大幅提升大文件处理速度
//
// 参数:
//   - reader: 数据源(通常是原始文件的某个区段读取器)
//   - writer: 数据写入目标(通常是分片文件)
//
// 返回:
//   - 写入的字节数
//   - 十六进制字符串形式的SHA256
//   - 错误信息
func computeReaderSHA256(reader io.Reader, writer io.Writer) (int64, string, error) {
    hasher := sha256.New()

    // io.MultiWriter 创建一个多路写入器:写入它的数据会同时写入 hasher 和 writer
    // 这样一次读取就能同时完成"写文件"和"算哈希"两个操作
    multiWriter := io.MultiWriter(hasher, writer)

    buf := make([]byte, sha256BufferSize)
    n, err := io.CopyBuffer(multiWriter, reader, buf)
    if err != nil {
        return n, "", fmt.Errorf("数据拷贝时出错: %w", err)
    }

    return n, hex.EncodeToString(hasher.Sum(nil)), nil
}

const (
    charset = "0123456789abcdefghijklmnopqrstuvwxyz"

    minRandomNameLength = 1
    maxRandomNameLength = 1024

    randomBufferSize = 4096
)

// 随机文件名生成
func GenerateSecureRandomName(length int) (string, error) {
    if length < minRandomNameLength || length > maxRandomNameLength {
        return "", fmt.Errorf(
            "length must be between %d and %d",
            minRandomNameLength,
            maxRandomNameLength,
        )
    }

    const charsetLen = len(charset)
    const limit = 256 - (256 % charsetLen)

    result := make([]byte, length)

    buf := make([]byte, randomBufferSize)

    pos := 0

    for pos < length {
        n, err := rand.Read(buf)
        if err != nil {
            return "", fmt.Errorf("generate random bytes: %w", err)
        }

        for i := 0; i < n && pos < length; i++ {
            b := buf[i]

            if int(b) >= limit {
                continue
            }

            result[pos] = charset[int(b)%charsetLen]
            pos++
        }
    }

    return string(result), nil
}

// generateUniqueRandomName:在指定目录下生成一个不与现有文件冲突的随机文件名
// 虽然 64 位随机数碰撞概率极低,但为了绝对安全,仍然检查目标目录下是否已存在同名文件
//
// 参数:
//   - dir: 目标目录路径
//
// 返回:
//   - 唯一的 64 字符随机文件名
func generateUniqueRandomName(dir string) (string, error) {
    for attempts := 0; attempts < 100; attempts++ {
        name, err := GenerateSecureRandomName(64)
        if err != nil {
            return "", err
        }

        // 检查该文件名在目标目录下是否已存在
        fullPath := dir + string(os.PathSeparator) + name
        if _, err := os.Stat(fullPath); os.IsNotExist(err) {
            // 文件不存在,说明这个名字可用
            return name, nil
        }
    }

    return "", fmt.Errorf("经过 100 次尝试仍无法生成唯一的随机文件名,请检查目录是否异常")
}

// isHexString:判断字符串是否为合法的十六进制字符串
// 用于校验清单文件中的 SHA256 字段,防止损坏/被篡改的清单导致异常
func isHexString(s string) bool {
    if len(s) == 0 || len(s)%2 != 0 {
        return false
    }

    _, err := hex.DecodeString(s)

    return err == nil
}

// sizeUnitBytes:将单位名称映射为字节数(二进制单位:1K=1024)
// 键统一为大写,解析时对输入做大小写归一化,因此 500M/500MB/500Mb/500mB/500mb 都能正确解析为相同的值
var sizeUnitBytes = map[string]int64{
    "B":  1,
    "KB": 1 << 10, "K": 1 << 10, "KIB": 1 << 10,
    "MB": 1 << 20, "M": 1 << 20, "MIB": 1 << 20,
    "GB": 1 << 30, "G": 1 << 30, "GIB": 1 << 30,
    "TB": 1 << 40, "T": 1 << 40, "TIB": 1 << 40,
    "PB": 1 << 50, "P": 1 << 50, "PIB": 1 << 50,
}

// parseSizeBytes:将人类可读的大小字符串解析为字节数
//
// 支持的格式(单位大小写不敏感,可带空格):
//   - "500M","500MB","500Mb","500mB","500mb"  → 500 * 1024^2
//   - "5G","5GB","5g"                         → 5 * 1024^3
//   - "100K","100KB","100k"                   → 100 * 1024
//   - "60B","60b"                             → 60
//   - "1.5G"                                  → 小数也支持
//   - "500"(不带单位)                         → 500 字节(默认按字节计)
//   - " 500 MB "(含空格)                      → 自动去除空格
//
// 返回值:
//   - 字节数(int64)
//   - 错误信息(空值,非法数字,未知单位,溢出,小于 1 字节时返回错误)
func parseSizeBytes(input string) (int64, error) {
    if input == "" {
        return 0, fmt.Errorf("大小为空")
    }

    // 去除空白字符
    s := strings.Map(func(r rune) rune {
        if unicode.IsSpace(r) {
            return -1
        }
        return r
    }, input)
    if s == "" {
        return 0, fmt.Errorf("大小为空")
    }

    // 分离数字部分和单位部分
    i := 0
    if s[0] == '+' || s[0] == '-' {
        if s[0] == '-' {
            return 0, fmt.Errorf("大小不能为负数: %s", input)
        }
        // 允许显式正号 "+"
        i++
    }

    // 读取数字(整数或小数,允许一个小数点)
    digits := ""
    hasDot := false
    for ; i < len(s); i++ {
        c := s[i]
        if c >= '0' && c <= '9' {
            digits += string(c)
        } else if c == '.' && !hasDot {
            digits += string(c)
            hasDot = true
        } else {
            break
        }
    }
    if digits == "" || digits == "." || digits == "-" || digits == "+" {
        return 0, fmt.Errorf("\"%s\" 不是有效的数字", input)
    }
    unit := strings.ToUpper(s[i:]) // 单位统一大写,实现大小写不敏感
    if unit == "" {
        // 不带单位时默认按字节
        unit = "B"
    }
    multiplier, ok := sizeUnitBytes[unit]
    if !ok {
        return 0, fmt.Errorf("\"%s\" 的单位 \"%s\" 无法识别,支持的单位: B、KB/K/KIB、MB/M/MIB、GB/G/GIB、TB/T/TIB、PB/P/PIB", input, unit)
    }
    number, err := strconv.ParseFloat(digits, 64)
    if err != nil {
        return 0, fmt.Errorf("\"%s\" 不是有效的数字: %w", input, err)
    }
    if number < 0 {
        return 0, fmt.Errorf("大小不能为负数: %s", input)
    }
    // 溢出保护:number * multiplier 不得超过 int64 最大值
    // 用 >= 而非 >:float64无法精确表示MaxInt64,边界输入(如2^63)会解析成恰好等于阈值,若放行会在int64转换时回绕为负数,被后续检查误报为"至少1字节"
    if float64(number) >= float64(math.MaxInt64)/float64(multiplier) {
        return 0, fmt.Errorf("大小超出可表示范围: %s", input)
    }
    size := int64(number * float64(multiplier))
    if size < 1 {
        return 0, fmt.Errorf("大小必须至少为 1 字节: %s", input)
    }
    // float64只有53位有效精度,超过2^53字节(约9PB)无法精确表示,明确拒绝
    if float64(number) >= float64(1<<53) {
        return 0, fmt.Errorf("大小超出浮点精度可精确表示的范围: %s", input)
    }

    return size, nil
}

// parsePercentages:将百分比字符串解析为浮点数切片
//
// 支持的格式:
//   - "40"          → [40, 60]        (单值自动补全,剩余部分为 100 - 该值)
//   - "40%"         → [40, 60]        (单值带百分号)
//   - "30,70"       → [30, 70]        (多值逗号分隔)
//   - "20,40,40"    → [20, 40, 40]    (三个及以上)
//   - "30%,70%"     → [30, 70]        (百分号会被自动去除)
//   - "30% , 70%"   → [30, 70]        (任意位置的空格都会被自动去除)
//   - " 30 , 70 "   → [30, 70]        (首尾空格也会被自动去除)
//
// 校验规则:
//   - 单值输入时,值必须在 (0, 100) 之间(不包含端点),否则剩余部分为0或负数
//   - 多值输入时,每个值必须大于 0
//   - 多值输入总和不足 100 时,按差值分两种处理:
//   - 差值 ≤ tolerancePercent:视为"用户给出的值本意就是 100,只是存在取整/舍入误差"
//     (如 33.3,33.3,33.3 总和 99.9,差 0.1),自动微调最后一个值补足,不增加分片数；
//   - 差值 > tolerancePercent:视为"用户只给出了部分分片比例"
//     (如 20,50 总和 70,差 30),自动追加一个剩余分片 100 - sum,增加分片数
//
// 参数:
//   - input: 百分比字符串
//
// 返回:
//   - 浮点数切片,每个元素代表一个分片的百分比
//   - 错误信息(格式不合法或校验失败时)
//
// tolerancePercent 多值百分比总和的自动补全容差(百分点)
const tolerancePercent = 1.0

func parsePercentages(input string) ([]float64, error) {
    // 第一步:去除所有空格
    // 这样 "40%, 60%"," 30 , 70 ","40 %" 等各种带空格的格式都能正确解析
    input = strings.ReplaceAll(input, " ", "")

    // 按逗号分割字符串
    parts := strings.Split(input, ",")

    // 单值输入:自动补全剩余部分
    // 用户只输入一个百分比(如 "40" 或 "40%"),自动将剩余部分计算为 100 - 该值
    if len(parts) == 1 {
        val, err := parseSinglePercentage(parts[0])
        if err != nil {
            return nil, fmt.Errorf("百分比值解析失败: %w", err)
        }
        // 单值必须严格在 0 和 100 之间,否则剩余部分为 0 或负数,无法分割
        if val <= 0 || val >= 100 {
            return nil, fmt.Errorf("单个百分比值必须在 0 和 100 之间（不包含端点），当前为 %.2f", val)
        }

        return []float64{val, 100 - val}, nil
    }

    // 多值输入:正常解析每个值
    // 预留一个追加位(总和不足 100 时可能追加)
    ratios := make([]float64, 0, len(parts)+1)
    var sum float64

    for i, part := range parts {
        val, err := parseSinglePercentage(part)
        if err != nil {
            return nil, fmt.Errorf("第 %d 个百分比值: %w", i+1, err)
        }

        if val <= 0 || val >= 100 {
            return nil, fmt.Errorf("第 %d 个百分比值必须在 0 和 100 之间(不包含端点),当前为 %.2f", i+1, val)
        }

        ratios = append(ratios, val)
        sum += val
    }

    // 总和超过100,报错
    if sum > 100.01 {
        return nil, fmt.Errorf("所有百分比之和不能超过 100，当前总和为 %.2f", sum)
    }

    // 总和不足100,自动补全
    if sum < 99.99 {
        remainder := 100.0 - sum
        if remainder <= tolerancePercent {
            // 容差内:视为舍入/取整误差,微调最后一个值补足,不增加分片数
            // 例:33.3,33.3,33.3(总和 99.9,差 0.1)→ [33.3, 33.3, 33.4],仍为 3 片
            ratios[len(ratios)-1] += remainder
        } else {
            // 明显不足:追加一个"剩余"分片
            // 例:20,50(总和 70,差 30)→ [20, 50, 30],变为 3 片
            ratios = append(ratios, remainder)
        }
    }

    // 逻辑走到最后sum只有两种可能:
    // 来源                                 sum值                                是否>100
    // 放行窗口[99.99,100.01](如50,50.005)  可能100.005                          可能略>100
    // 补全路径(sum < 99.99进入)            ≈ 100.0(实测精确100.00000000000000)  否

    // 总和在[99.99,100.01]内:无需调整(分割时末片取剩余字节,自动吸收浮点误差)

    return ratios, nil
}

// parseSinglePercentage 解析单个百分比字符串(辅助函数)
// 支持带百分号("40%")和不带百分号("40")两种格式
//
// 参数:
//   - s: 单个百分比字符串
//
// 返回:
//   - 解析后的浮点数值
//   - 错误信息
func parseSinglePercentage(s string) (float64, error) {
    // 去除首尾空格(虽然 parsePercentages 已经全局去空格,但保留这步更健壮)
    s = strings.TrimSpace(s)
    // 去除末尾的百分号(如果有)
    s = strings.TrimSuffix(s, "%")
    // 再次去除首尾空格(处理 "40 %" → 去%后变成 "40 " 的情况)
    s = strings.TrimSpace(s)

    if s == "" {
        return 0, fmt.Errorf("值为空")
    }

    val, err := strconv.ParseFloat(s, 64)
    if err != nil {
        return 0, fmt.Errorf("\"%s\" 不是有效数字: %w", s, err)
    }

    return val, nil
}

// formatFileSize:将字节数格式化为人类可读的字符串
// 例如:1536 → "1.50 KB",1048576 → "1.00 MB"
//
// 参数:
//   - bytes: 文件大小(字节数)
//
// 返回:
//   - 格式化后的字符串
func formatFileSize(bytes int64) string {
    const unit = 1024
    if bytes < unit {
        return fmt.Sprintf("%d B", bytes)
    }
    div, exp := int64(unit), 0
    for n := bytes / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
    // 双保险：理论上 int64 最大 2^63 时 exp 只会到 5，但绝不越界
    if exp >= len(units) {
        exp = len(units) - 1
    }
    return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div), units[exp])
}

// 密码文件大小上限(64 KB),防止用户误传一个大文件(如日志,备份等)当作密码文件
const maxPasswordFileSize = 64 * 1024

// readPasswordFromFile:从文本文件读取密码
//
// 换行符处理:
//   - 文本文件最常见的形态是"一行密码 + 末尾换行"(echo 重定向,文本编辑器保存都会产生),如果原样读取,密码会多出一个换行字节,必然导致加密/解密不一致
//   - 因此读取后剥离文件末尾的一个换行序列:CRLF(\r\n)、LF(\n)、CR(\r)三种都支持
//   - 文件中间的换行符原样保留(支持故意使用多行密码)
//   - 唯一极端场景:密码确实要以换行结尾,此时末尾换行会被剥离,这是行业通用取舍
//
// 健壮性保证:
//   - 文件不存在 / 是目录 / 读取失败 → 明确报错
//   - 文件超过 64KB → 报错(防止误传大文件)
//   - 文件为空 → 报错(空密码无意义,避免"看似加密实则未加密"的坑)
//
// 密码文件内容 读取后的密码 说明
// abc\n        abc          末尾换行被剥离(最常见情况)
// a\nb         a\nb         无末尾换行,原样
// a\nb\n       a\nb         中间换行保留,末尾剥离
// a\nb\n\n     a\nb\n       只剥离一个末尾换行,密码本身可以以换行结尾
//
//所以"支持多行密码"的意思就是:
//a\nb和ab是两个完全不同的密码,如果要使用多行密码,那么用printf或编辑器写两行即可,-password-file是唯一能表达含换行密码的途径
//命令行-password在shell里几乎无法输入换行
//注意:如果非要使用多行密码的话,必须固定平台-加密和合并都在同一台机器/同一种行尾风格下操作,且别用会自动改行尾的编辑器(推荐printf或vi,禁用Windows记事本)
func readPasswordFromFile(path string) ([]byte, error) {
    info, err := os.Stat(path)
    if err != nil {
        return nil, fmt.Errorf("无法访问密码文件 %s: %w", path, err)
    }
    if info.IsDir() {
        return nil, fmt.Errorf("密码文件 %s 是目录,不是文件", path)
    }
    if info.Size() > maxPasswordFileSize {
        return nil, fmt.Errorf("密码文件 %s 过大(%d 字节,上限 %d 字节),请确认不是误传的普通文件", path, info.Size(), maxPasswordFileSize)
    }
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("读取密码文件 %s 失败: %w", path, err)
    }

    // 剥离文件末尾的一个换行序列(CRLF/LF/CR)
    data = trimTrailingNewline(data)

    if len(data) == 0 {
        return nil, fmt.Errorf("密码文件 %s 内容为空,无法作为密码", path)
    }

    return data, nil
}

// trimTrailingNewline:剥离字节切片末尾的一个换行序列:\r\n,\n或\r
func trimTrailingNewline(b []byte) []byte {
    n := len(b)
    if n == 0 {
        return b
    }
    if n >= 2 && b[n-2] == '\r' && b[n-1] == '\n' {
        return b[:n-2]
    }
    if b[n-1] == '\n' || b[n-1] == '\r' {
        return b[:n-1]
    }
    return b
}

// compareVersions:比较两个点分数字版本号(如 "1.3.0" 与 "1.10.0")
// 返回:
//  a<b 返回 -1
//  a==b 返回 0
//  a>b 返回 1
// 非数字段按0处理,长度不足的补0,因此"1.10" > "1.9" 判断正确
func compareVersions(a, b string) int {
    pa := strings.Split(a, ".")
    pb := strings.Split(b, ".")
    n := len(pa)
    if len(pb) > n {
        n = len(pb)
    }
    for i := 0; i < n; i++ {
        var x, y int
        if i < len(pa) {
            x, _ = strconv.Atoi(pa[i])
        }
        if i < len(pb) {
            y, _ = strconv.Atoi(pb[i])
        }
        if x < y {
            return -1
        }
        if x > y {
            return 1
        }
    }
    return 0
}

// ensureDir:确保指定目录存在,不存在则创建(包括所有父目录)
//
// 参数:
//   - dir: 目录路径
//
// 返回:
//   - 错误信息
func ensureDir(dir string) error {
    // os.MkdirAll 会创建目录及其所有父目录,权限设为 0755
    // 如果目录已存在,不会报错
    if err := os.MkdirAll(dir, 0755); err != nil {
        return fmt.Errorf("无法创建目录 %s: %w", dir, err)
    }
    return nil
}

// listFilesInDir:列出指定目录下的所有普通文件(不包括子目录,符号链接,隐藏文件等)
// 用于目录批量分割时遍历所有待分割文件
//
// 隐藏文件判断:文件名以 "." 开头的文件视为隐藏文件(Unix/macOS 约定),会被忽略
// 例如 .DS_Store,.gitignore,.hidden 等文件不会被分割
//
// 参数:
//   - dir: 目录路径
//
// 返回:
//   - 文件名切片(仅文件名,不含目录路径)
//   - 错误信息
func listFilesInDir(dir string) ([]string, error) {
    entries, err := os.ReadDir(dir)
    if err != nil {
        return nil, fmt.Errorf("无法读取目录 %s: %w", dir, err)
    }

    var files []string
    for _, entry := range entries {
        // 只处理普通文件,跳过子目录和其他类型
        if !entry.Type().IsRegular() {
            continue
        }
        // 忽略隐藏文件(文件名以 "." 开头)
        if strings.HasPrefix(entry.Name(), ".") {
            continue
        }
        files = append(files, entry.Name())
    }

    return files, nil
}

// listSubDirs:列出指定目录下的所有子目录(不包括普通文件)
// 用于批量合并时遍历所有分割目录
//
// 参数:
//   - dir: 目录路径
//
// 返回:
//   - 子目录名切片
//   - 错误信息
func listSubDirs(dir string) ([]string, error) {
    entries, err := os.ReadDir(dir)
    if err != nil {
        return nil, fmt.Errorf("无法读取目录 %s: %w", dir, err)
    }

    var dirs []string
    for _, entry := range entries {
        if entry.IsDir() {
            dirs = append(dirs, entry.Name())
        }
    }

    return dirs, nil
}
