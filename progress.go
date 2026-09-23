package main

// 进度条(可选功能,通过 -progress 启用,split 与 merge 通用)
//
// 设计要点:
//   - 默认关闭:progressEnabled为false,没有CPU开销
//   - 输出到stderr(而非stdout),避免污染程序的结构化输出
//   - 使用 \r 刷新单行,避免终端刷屏

import (
    "fmt"
    "io"
    "os"
    "sync"
    "sync/atomic"
    "time"
)

// 单行进度条
type progress struct {
    enabled bool
    label   string
    total   int64
    // 并发安全:split 的多个worker会同时累加
    done     atomic.Int64
    startAt  time.Time
    stopCh   chan struct{}
    stopOnce sync.Once
    writer   io.Writer
}

// newProgress:创建进度条,enabled=false时创建一个"空"进度条,所有操作零开销
func newProgress(enabled bool, total int64, label string) *progress {
    return &progress{
        enabled: enabled,
        label:   label,
        total:   total,
        startAt: time.Now(),
        stopCh:  make(chan struct{}),
        writer:  os.Stderr,
    }
}

// add:累加已处理字节数,未启用时直接返回
func (p *progress) add(n int64) {
    if !p.enabled {
        return
    }
    p.done.Add(n)
}

// start:启动后台刷新协程(每100ms重绘一次)
func (p *progress) start() {
    if !p.enabled {
        return
    }
    go func() {
        ticker := time.NewTicker(100 * time.Millisecond)
        defer ticker.Stop()
        for {
            select {
            case <-p.stopCh:
                return
            case <-ticker.C:
                p.render()
            }
        }
    }()
}

// finish:停止刷新并输出最终状态与换行
// 修改后（progress.go）
func (p *progress) finish() {
    if !p.enabled {
        return
    }
    p.stopOnce.Do(func() {
        close(p.stopCh)
        // 全部收进 Do:第一次执行,以后任何调用都是空操作
        p.render()
        fmt.Fprintln(p.writer)
    })
}

// render:重绘当前进度条
func (p *progress) render() {
    done := p.done.Load()
    if p.total <= 0 {
        return
    }
    pct := float64(done) / float64(p.total)
    if pct > 1 {
        // 加密分片统计的是密文字节,可能略超总量,封顶显示
        pct = 1
    }
    const barWidth = 30
    filled := int(pct * barWidth)
    if filled > barWidth {
        filled = barWidth
    }
    bar := ""
    for i := 0; i < barWidth; i++ {
        if i < filled {
            bar += "#"
        } else {
            bar += "-"
        }
    }
    elapsed := time.Since(p.startAt).Seconds()
    var speed string
    if elapsed > 0 {
        speed = fmt.Sprintf("%s/s", formatFileSize(int64(float64(done)/elapsed)))
    } else {
        speed = "--"
    }
    fmt.Fprintf(p.writer, "\r[%s] %5.1f%%  %s  %s", bar, pct*100, speed, p.label)
}

// countingWriter:包装一个writer,在写入时累计字节数并汇报给进度条
type countingWriter struct {
    w io.Writer
    p *progress
}

// Write:实现io.Writer接口
func (c *countingWriter) Write(b []byte) (int, error) {
    n, err := c.w.Write(b)
    if n > 0 {
        c.p.add(int64(n))
    }
    return n, err
}

// stop:停止后台刷新协程,但不渲染最终帧,不输出换行
// 用于"每个分片完成时已主动渲染精确帧"的场景(merge 路径),避免finish()再渲染一次导致冗余的进度条行
// 与finish共用stopOnce:先stop后finish或反之,都不会重复渲染
func (p *progress) stop() {
    if !p.enabled {
        return
    }
    p.stopOnce.Do(func() { close(p.stopCh) })
}
