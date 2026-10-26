// ddosguard — NetFlow DDoS 检测与交换机联动处置。
//
// 流程：
//  1. UDP 接收 NetFlow v5/v9/IPFIX；
//  2. 解析后按 目标IP+端口 做滑动窗口（默认 5s）聚合（连接数/包数/字节数）；
//  3. 目标 IP 命中配置的交换机-网段规则且超过阈值（连接数/流量）时触发；
//  4. 通过 SSH 在对应交换机执行命令模板（{ip}/{port} 占位符已填入），
//     并带冷却时间避免重复下发。
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"ddosguard/internal/config"
	"ddosguard/internal/detect"
	"ddosguard/internal/netflow"
	"ddosguard/internal/switchctl"
)

// task 待解析的报文（含导出设备 IP，用于默认采样率匹配）
type task struct {
	data       []byte
	exporterIP string
}

// stats 运行指标
type stats struct {
	packets   uint64
	records   uint64
	matched   uint64
	hits      uint64
	parseErrs uint64
}

// actionRouter 按交换机名分发处置
type actionRouter struct {
	execs  map[string]*switchctl.Executor
	logger *zap.Logger
}

func (a *actionRouter) RunBatch(switchName string, hits []detect.Hit) error {
	ex, ok := a.execs[switchName]
	if !ok {
		return fmt.Errorf("no ssh executor for switch %q", switchName)
	}
	return ex.RunBatch(switchName, hits)
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	httpFlag := flag.String("http", "", "override metrics/health listen address (empty=use config; e.g. :9090)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger := newLogger()
	defer logger.Sync()

	logger.Info("starting ddosguard",
		zap.String("config", *configPath),
		zap.Duration("window", cfg.Detection.Window),
		zap.Duration("cooldown", cfg.Detection.Cooldown),
		zap.Int("switches", len(cfg.Switches)),
	)

	// 构建规则与 SSH 执行器
	rules := make([]detect.Rule, 0, len(cfg.Switches))
	execs := make(map[string]*switchctl.Executor, len(cfg.Switches))
	for _, sw := range cfg.Switches {
		flows, bytes, packets := cfg.Thresholds(&sw)
		rules = append(rules, detect.Rule{
			Switch:  sw.Name,
			Targets: sw.Nets,
			Thresholds: detect.Thresholds{
				MinFlows:   flows,
				MinBytes:   bytes,
				MinPackets: packets,
			},
		})
		execs[sw.Name] = switchctl.NewExecutor(sw, logger)
		logger.Info("switch rule loaded",
			zap.String("switch", sw.Name),
			zap.String("host", sw.Host),
			zap.Int("targets", len(sw.Nets)),
			zap.Uint64("min_flows", flows),
			zap.Uint64("min_bytes", bytes),
			zap.Uint64("min_packets", packets),
		)
	}

	agg := detect.NewAggregator(cfg.Detection.Window)
	router := &actionRouter{execs: execs, logger: logger}
	detector := detect.NewDetector(agg, rules, cfg.Detection.Cooldown, cfg.Detection.DedupTTL, router, logger)

	// 所有目标网段（用于接收侧快速过滤）
	var allTargets []*net.IPNet
	for _, sw := range cfg.Switches {
		allTargets = append(allTargets, sw.Nets...)
	}

	var st stats

	// UDP 接收 + 解析工作池
	addr, err := net.ResolveUDPAddr("udp", cfg.Collector.Listen)
	if err != nil {
		logger.Fatal("resolve listen address", zap.Error(err))
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		logger.Fatal("listen udp", zap.Error(err))
	}
	bufSize := cfg.Collector.BufferSize
	if bufSize < 1<<20 {
		bufSize = 1 << 20
	}
	conn.SetReadBuffer(bufSize)

	cache := netflow.NewTemplateCache(30 * time.Minute)
	taskCh := make(chan task, 1024)
	var wg sync.WaitGroup

	stopCh := make(chan struct{})

	// workers
	for i := 0; i < cfg.Collector.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskCh {
				records, err := netflow.Parse(t.data, cache)
				if err != nil {
					atomic.AddUint64(&st.parseErrs, 1)
					continue
				}
				now := time.Now()
				for i := range records {
					r := &records[i]
					atomic.AddUint64(&st.records, 1)
					if r.DstIP == "" || !inTargets(allTargets, r.DstIP) {
						continue
					}
					// 采样处理与 netstream-collector 一致：设备未提供采样率时
					// 使用按导出设备 IP 的默认采样率，再按采样间隔放大计数
					r.ApplyDefaultSampling(t.exporterIP, cfg.Sampling.Defaults)
					r.ScaleSampledCounters()
					atomic.AddUint64(&st.matched, 1)
					agg.Add(detect.Key{IP: r.DstIP, Port: r.DstPort}, r.Proto, r.Packets, r.Bytes, now)
				}
			}
		}()
	}

	// reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				select {
				case <-stopCh:
					return
				default:
					logger.Error("udp read", zap.Error(err))
					continue
				}
			}
			atomic.AddUint64(&st.packets, 1)
			t := task{data: make([]byte, n)}
			copy(t.data, buf[:n])
			if src != nil && src.IP != nil {
				t.exporterIP = src.IP.String()
			}
			select {
			case taskCh <- t:
			default:
				logger.Warn("worker queue full, packet dropped")
			}
		}
	}()

	// 检测循环
	go func() {
		ticker := time.NewTicker(cfg.Detection.CheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case now := <-ticker.C:
				hits := detector.Check(now)
				if n := len(hits); n > 0 {
					atomic.AddUint64(&st.hits, uint64(n))
				}
				agg.Evict(now)
			}
		}
	}()

	// metrics / health（配置 http.listen；-http 可覆盖；空=禁用）
	httpAddr := cfg.HTTP.Listen
	if *httpFlag != "" {
		httpAddr = *httpFlag
	}
	if httpAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "ddosguard_packets_received %d\n", atomic.LoadUint64(&st.packets))
			fmt.Fprintf(w, "ddosguard_records_parsed %d\n", atomic.LoadUint64(&st.records))
			fmt.Fprintf(w, "ddosguard_records_matched %d\n", atomic.LoadUint64(&st.matched))
			fmt.Fprintf(w, "ddosguard_hits_total %d\n", atomic.LoadUint64(&st.hits))
			fmt.Fprintf(w, "ddosguard_parse_errors %d\n", atomic.LoadUint64(&st.parseErrs))
		})
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok"}`))
		})
		server := &http.Server{Addr: httpAddr, Handler: mux}
		go func() {
			logger.Info("http server started", zap.String("addr", httpAddr))
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("http server", zap.Error(err))
			}
		}()
	}

	// 等待退出
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("shutting down", zap.String("signal", sig.String()))
	close(stopCh)
	conn.Close()
	close(taskCh)
	wg.Wait()
	logger.Info("stopped",
		zap.Uint64("packets", atomic.LoadUint64(&st.packets)),
		zap.Uint64("records", atomic.LoadUint64(&st.records)),
		zap.Uint64("hits", atomic.LoadUint64(&st.hits)),
	)
}

// inTargets 判断目标 IP 是否在网段列表内
func inTargets(nets []*net.IPNet, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, nw := range nets {
		if nw.Contains(ip) {
			return true
		}
	}
	return false
}

// newLogger 结构化日志（高频告警限速）
func newLogger() *zap.Logger {
	atom := zap.NewAtomicLevelAt(zap.InfoLevel)
	cfg := zap.Config{
		Level:            atom,
		Encoding:         "json",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}
	base, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	return zap.New(zapcore.NewSampler(base.Core(), 10*time.Second, 1, 100))
}
