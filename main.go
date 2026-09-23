package main

// 本文件是程序的主入口,负责:
// -解析命令行参数
// -根据子命令(split/merge)分发到对应的处理函数
// -统一的错误处理和退出码管理

// 命令行设计采用"子命令"模式(类似git,docker等工具):
// binsplit split [选项]
// binsplit merge [选项]
// binsplit version
// binsplit help

import (
    "errors"
    "flag"
    "fmt"
    "os"
    "runtime"
)

// 版本号
const Version = "1.0.0"

func main() {
    // 如果没有提供任何参数,打印用法并退出
    if len(os.Args) < 2 {
        printUsage()
        os.Exit(1)
    }

    // 根据第一个参数(子命令)分发处理
    switch os.Args[1] {
    case "split":
        // 分割命令:将剩余参数传给runSplit
        runSplit(os.Args[2:])
    case "merge":
        // 合并命令:将剩余参数传给runMerge
        runMerge(os.Args[2:])
    case "version", "-v", "--version":
        // 显示版本号
        fmt.Printf("binsplit v%s\n", Version)
        fmt.Printf("Go 版本: %s\n", runtime.Version())
        fmt.Printf("操作系统: %s/%s\n", runtime.GOOS, runtime.GOARCH)
    case "help", "-h", "--help":
        // 显示帮助信息
        printUsage()
    default:
        // 未知命令
        fmt.Fprintf(os.Stderr, "错误: 未知命令 \"%s\"\n\n", os.Args[1])
        printUsage()
        os.Exit(1)
    }
}

// printUsage:打印程序的整体使用说明
func printUsage() {
    fmt.Printf(`binsplit v%s - 二进制文件分割与合并工具

用法:
  binsplit <命令> [选项]

命令:
  split   分割文件(支持单文件或目录批量分割)
  merge   合并文件(支持单个分割目录或批量合并)
  version 显示版本信息
  help    显示此帮助信息

示例:
  # 按百分比分割单个文件(只输一个值,剩余自动补全,如 40%% → 40%%+60%%)
  binsplit split -i video.mp4 -p 40

  # 按百分比分割单个文件(显式指定两份,如 30%% 和 70%%)
  binsplit split -i video.mp4 -p 30,70

  # 按数量等分单个文件(分为 10 份)
  binsplit split -i video.mp4 -n 10

  # 按目标分片大小分割(每个分片约 500MB,大小写不敏感,如 500M/500MB/500mb)
  binsplit split -i video.mp4 -s 500M

  # 批量分割目录下所有文件,每个分片约 500MB,输出到指定目录(-s批量分割时,如果某个文件小于目标分片大小,那么会报错并且跳过该文件,而不是整体退出)
  binsplit split -i ./files -s 500M -o ./output

  # 加密分割(AES-256-GCM)
  binsplit split -i secret.mp4 -s 500M -password "我的密码"

  # 加密分割,从密码文件读取密码(自动剥离文件末尾换行符)
  binsplit split -i secret.mp4 -s 500M -password-file ./pass.txt

  # 加密分片合并(必须提供密码,否则报错退出)
  binsplit merge -i secret.mp4.parts -password "我的密码"
  binsplit merge -i secret.mp4.parts -password-file ./pass.txt

  # 显示进度条(split/merge 均可加 -progress,默认关闭,关闭时不计算任何进度开销)
  binsplit split -i ./files -s 500M -progress

使用 "binsplit <命令> -h" 查看该命令的详细选项
`, Version)
}

// split 子命令
// runSplit 处理 split 子命令的参数解析和执行
// 参数设计说明:
// -i input   输入文件或目录(必填),程序自动判断是文件还是目录
// -p percent 按百分比分割,单值自动补全,多值逗号分隔,与 -n/-s 三选一
// -n count   按数量等分,与 -p/-s 三选一
// -s size    按目标分片的大小分割,与 -p/-n 三选一
// -o output  输出目录(可选,默认为当前目录)
// -j workers 并行线程数(可选,默认为 CPU 核心数)
func runSplit(args []string) {
    // 创建独立的 flag 集,避免与全局 flag 冲突
    fs := flag.NewFlagSet("split", flag.ExitOnError)
    // 定义选项
    input := fs.String("i", "", "输入文件路径或目录路径(必填)")
    percent := fs.String("p", "", "按百分比分割,单值自动补全(如 \"40\"),多值逗号分隔(如 \"30,70\"、\"20,40,40\")")
    count := fs.Int("n", 0, "按数量等分,如 10 表示等分为 10 份")
    sizeStr := fs.String("s", "", "按目标分片的大小分割,支持单位(如 \"500M\"、\"500MB\"、\"5G\"、\"100K\"、\"60B\"),大小写不敏感")
    output := fs.String("o", "", "输出目录(可选,默认为当前目录)")
    workers := fs.Int("j", 0, "并行工作线程数(可选,默认为 CPU 核心数)")
    password := fs.String("password", "", "分片加密密码(传入则启用 AES-256-GCM 加密,密码支持中文等任意字符,长度不限)")
    passwordFile := fs.String("password-file", "", "从文本文件中读取密码(与 -password 二选一;会自动剥离文件末尾的换行符)")
    progressFlag := fs.Bool("progress", false, "显示进度条(默认关闭)")
    // 自定义帮助信息
    fs.Usage = func() {
        fmt.Fprintf(os.Stderr, `用法: binsplit split -i <输入> [-p 百分比 | -n 数量 | -s 目标大小] [-o 输出目录] [-j 线程数]
选项:
  -i string  输入文件或目录(必填)
  -p string  按百分比分割,单值自动补全(如 "40" → 40%%+60%%),多值逗号分隔(如 "20,50,30"),(与 -n/-s 三选一)
  -n int     按数量等分,如 10(与 -p/-s 三选一)
  -s string  按目标分片大小分割(与 -p/-n 三选一),支持单位且大小写不敏感:
             如 "500M"/"500MB"/"500Mb"/"500mB"/"500mb" → 500MB;"5G"→5GB;"100K"→100KB;"60B"→60字节
             不带单位时按字节计,末片可能小于目标大小
  -o string  输出目录(默认当前目录)
  -j int     并行线程数(默认 CPU 核心数)
  -password string
             分片加密密码(传入则启用 AES-256-GCM 加密),密码支持中文,中文标点等任意字符,长度不限
  -password-file string
             从文本文件中读取密码(与 -password 二选一),自动剥离文件末尾的换行符(CRLF/LF/CR 均支持)
             文件中间的换行符会保留,文件不能为空,文件大小不能超过 64KB
  -progress  显示进度条(默认关闭,关闭时不做任何进度计算,零额外开销)
示例:
  binsplit split -i video.mp4 -p 40
  binsplit split -i video.mp4 -p 30,70
  binsplit split -i video.mp4 -n 10
  binsplit split -i video.mp4 -s 500M
  binsplit split -i ./files -s 500M -o ./output
  binsplit split -i secret.mp4 -s 500M -password "我的密码" -progress
`)
    }

    // 解析参数
    fs.Parse(args)

    // 参数校验
    // 必须指定输入
    if *input == "" {
        fmt.Fprintln(os.Stderr, "错误: 必须使用 -i 指定输入文件或目录")
        fs.Usage()
        os.Exit(1)
    }
    // -p,-n,-s 必须且只能三选一
    modeCount := 0
    if *percent != "" {
        modeCount++
    }
    if *count != 0 {
        modeCount++
    }
    if *sizeStr != "" {
        modeCount++
    }
    if modeCount == 0 {
        fmt.Fprintln(os.Stderr, "错误: 必须使用 -p(百分比)、-n(数量)或 -s(目标大小)之一指定分割方式")
        os.Exit(1)
    }
    if modeCount > 1 {
        fmt.Fprintln(os.Stderr, "错误: -p(百分比)、-n(数量)、-s(目标大小)只能指定其一")
        os.Exit(1)
    }

    // 解析分割方式
    var ratios []float64
    var targetSize int64
    var err error
    if *percent != "" {
        // 按百分比分割:解析用户提供的百分比字符串
        ratios, err = parsePercentages(*percent)
        if err != nil {
            fmt.Fprintf(os.Stderr, "错误: 百分比格式无效: %v\n", err)
            os.Exit(1)
        }
    } else if *count != 0 {
        // 按数量等分:生成 N 个相等的百分比
        if *count <= 0 {
            fmt.Fprintln(os.Stderr, "错误: 分割数量必须大于 0")
            os.Exit(1)
        }
        if *count == 1 {
            fmt.Fprintln(os.Stderr, "错误: 分割数量为 1 没有意义(文件不会被分割)")
            os.Exit(1)
        }
        if *count > maxParts {
            fmt.Fprintf(os.Stderr, "错误: 分割数量 %d 超过上限 %d\n", *count, maxParts)
            os.Exit(1)
        }
        ratios = make([]float64, *count)
        for i := range ratios {
            ratios[i] = 100.0 / float64(*count)
        }
    } else {
        // 按目标分片大小分割:解析用户提供的大小字符串
        targetSize, err = parseSizeBytes(*sizeStr)
        if err != nil {
            fmt.Fprintf(os.Stderr, "错误: 目标分片大小无效: %v\n", err)
            os.Exit(1)
        }
    }

    // 设置并行数
    if *workers <= 0 {
        // 默认使用 CPU 核心数,充分利用多核性能
        *workers = runtime.NumCPU()
    }
    // 限制最大并发数,避免过多 goroutine 导致资源耗尽
    if *workers > 64 {
        *workers = 64
    }

    // 判断输入是文件还是目录,执行对应操作
    // 使用 os.Stat 获取文件信息,判断是文件还是目录
    fileInfo, err := os.Stat(*input)
    if err != nil {
        fmt.Fprintf(os.Stderr, "错误: 无法访问输入路径 %s: %v\n", *input, err)
        os.Exit(1)
    }

    // 密码处理(-password 与 -password-file 二选一)
    var passBytes []byte
    if *password != "" && *passwordFile != "" {
        fmt.Fprintln(os.Stderr, "错误: -password 与 -password-file 只能二选一")
        os.Exit(1)
    }
    if *passwordFile != "" {
        p, err := readPasswordFromFile(*passwordFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "错误: %v\n", err)
            os.Exit(1)
        }
        passBytes = p
    } else if *password != "" {
        passBytes = []byte(*password)
    }
    if len(passBytes) > 0 {
        // 用完后擦除内存中的密码字节
        defer zeroBytes(passBytes)
    }

    // 判断输入是文件还是目录,执行对应操作
    if fileInfo.IsDir() {
        // 输入是目录:批量分割目录下所有文件
        err = splitDirectory(*input, *output, ratios, targetSize, *workers, passBytes, *progressFlag)
    } else {
        // 输入是文件:分割单个文件
        err = splitFile(*input, *output, ratios, targetSize, *workers, passBytes, *progressFlag)
    }

    // 处理结果
    if err != nil {
        fmt.Fprintf(os.Stderr, "\n错误: %v\n", err)
        os.Exit(1)
    }
    fmt.Println("所有操作已完成。")
}

// merge 子命令
// runMerge 处理 merge 子命令的参数解析和执行
// 参数设计说明:
// -i input   输入目录(必填),可以是单个分割目录,也可以是包含多个分割目录的父目录
//            程序自动判断:
//            如果目录中存在清单文件(清单文件名的格式:原始文件名-SHA256-分片数量.txt),视为单个分割目录
//            否则遍历子目录,只对名称以 .parts 结尾且包含清单文件的子目录进行批量合并
// -o output  输出目录(可选,默认为当前目录)
// -j workers 并行线程数(可选,默认为 CPU 核心数),用于分片校验阶段
func runMerge(args []string) {
    fs := flag.NewFlagSet("merge", flag.ExitOnError)

    input := fs.String("i", "", "输入分割目录或包含多个分割目录的父目录(必填)")
    output := fs.String("o", "", "输出目录(可选,默认为当前目录)")
    workers := fs.Int("j", 0, "并行工作线程数(可选,默认为 CPU 核心数)")
    password := fs.String("password", "", "解密密码(分割目录已加密时必须提供,否则报错退出,未加密时该参数被忽略)")
    passwordFile := fs.String("password-file", "", "从文本文件读取密码(与 -password 二选一,会自动剥离文件末尾的换行符)")
    progressFlag := fs.Bool("progress", false, "显示进度条(默认关闭)")

    fs.Usage = func() {
        fmt.Fprintf(os.Stderr, `用法: binsplit merge -i <输入目录> [-o 输出目录] [-j 线程数]

选项:
  -i string  输入:单个分割目录,或包含多个分割目录的父目录(必填)
  -o string  输出目录(默认当前目录)
  -j int     并行线程数(默认 CPU 核心数)
  -password string
             解密密码,分割目录已加密时必须提供,否则报错退出,未加密时该参数被忽略,密码支持中文等任意字符,长度不限
  -password-file string
             从文本文件读取密码(与 -password 二选一,会自动剥离文件末尾的换行符)
             分割目录已加密时必须提供其一,否则报错退出
  -progress  显示进度条(默认关闭)

说明:
  如果 -i 指定的目录包含清单文件,则视为单个分割目录直接合并
  否则遍历其下所有子目录,只对名称以 .parts 结尾且包含清单文件的子目录进行批量合并

示例:
  binsplit merge -i video.mp4.parts
  binsplit merge -i ./all_parts -o ./restored
  binsplit merge -i secret.mp4.parts -password "我的密码" -progress
`)
    }

    fs.Parse(args)

    // 参数校验
    if *input == "" {
        fmt.Fprintln(os.Stderr, "错误: 必须使用 -i 指定输入目录")
        fs.Usage()
        os.Exit(1)
    }

    // 设置并行数
    if *workers <= 0 {
        *workers = runtime.NumCPU()
    }
    if *workers > 64 {
        *workers = 64
    }

    // 检查输入路径
    fileInfo, err := os.Stat(*input)
    if err != nil {
        fmt.Fprintf(os.Stderr, "错误: 无法访问输入路径 %s: %v\n", *input, err)
        os.Exit(1)
    }

    if !fileInfo.IsDir() {
        fmt.Fprintln(os.Stderr, "错误: merge 命令的 -i 必须是目录")
        os.Exit(1)
    }

    // 密码处理(-password 与 -password-file 二选一)
    var passBytes []byte
    if *password != "" && *passwordFile != "" {
        fmt.Fprintln(os.Stderr, "错误: -password 与 -password-file 只能二选一")
        os.Exit(1)
    }
    if *passwordFile != "" {
        p, err := readPasswordFromFile(*passwordFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "错误: %v\n", err)
            os.Exit(1)
        }
        passBytes = p
    } else if *password != "" {
        passBytes = []byte(*password)
    }
    if len(passBytes) > 0 {
        defer zeroBytes(passBytes)
    }

    // 自动判断是单个分割目录还是批量合并
    var mergeErr error

    // 优先尝试读取清单文件来判断目录类型
    _, findErr := findManifestFile(*input)
    if findErr == nil {
        // 目录中包含清单文件,视为单个分割目录
        mergeErr = mergeDirectory(*input, *output, *workers, passBytes, *progressFlag)
    } else if errors.Is(findErr, ErrMultipleManifests) {
        // 目录中存在多个清单文件:直接显式报错,避免静默选择错误版本导致数据错乱
        mergeErr = findErr
    } else {
        // 目录中没有清单文件,视为包含多个分割目录的父目录,批量合并
        mergeErr = mergeParentDirectory(*input, *output, *workers, passBytes, *progressFlag)
    }

    if mergeErr != nil {
        fmt.Fprintf(os.Stderr, "\n错误: %v\n", mergeErr)
        os.Exit(1)
    }

    fmt.Println("所有操作已完成")
}
