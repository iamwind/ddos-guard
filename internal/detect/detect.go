// Package detect 实现按 目标IP+端口 的滑动窗口聚合与 DDoS 阈值检测。
package detect

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Key 聚合键：目标 IP + 端口
type Key struct {
	IP   string
	Port uint16
}

// Stats 窗口内累计统计
type Stats struct {
	Flows   uint64
	Packets uint64
	Bytes   uint64
	// Protos 协议号 -> flow 数（用于确定主导协议，填充命令模板 {proto}）
	Protos map[uint8]uint64
}

func (s *Stats) add(o Stats) {
	s.Flows += o.Flows
	s.Packets += o.Packets
	s.Bytes += o.Bytes
	for p, c := range o.Protos {
		if s.Protos == nil {
			s.Protos = make(map[uint8]uint64)
		}
		s.Protos[p] += c
	}
}

// DominantProto 返回 flow 数最多的协议号（无则 0）
func (s *Stats) DominantProto() uint8 {
	var best uint8
	var bestCount uint64
	for p, c := range s.Protos {
		if c > bestCount {
			best, bestCount = p, c
		}
	}
	return best
}

// Aggregator 按秒分桶的滑动窗口聚合器（按 Key）
type Aggregator struct {
	mu      sync.Mutex
	window  time.Duration
	buckets map[int64]map[Key]*Stats // unix 秒 -> Key -> 统计
}

// NewAggregator 创建聚合器
func NewAggregator(window time.Duration) *Aggregator {
	if window <= 0 {
		window = 5 * time.Second
	}
	return &Aggregator{
		window:  window,
		buckets: make(map[int64]map[Key]*Stats),
	}
}

// Add 记录一条流（flows 计 1 次连接）
func (a *Aggregator) Add(k Key, proto uint8, packets, bytes uint64, t time.Time) {
	sec := t.Unix()
	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.buckets[sec]
	if b == nil {
		b = make(map[Key]*Stats)
		a.buckets[sec] = b
	}
	st := b[k]
	if st == nil {
		st = &Stats{}
		b[k] = st
	}
	st.Flows++
	st.Packets += packets
	st.Bytes += bytes
	if st.Protos == nil {
		st.Protos = make(map[uint8]uint64)
	}
	st.Protos[proto]++
}

// Snapshot 返回窗口内（含当前秒）的聚合快照
func (a *Aggregator) Snapshot(now time.Time) map[Key]Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[Key]Stats)
	oldest := now.Add(-a.window + time.Second).Unix()
	for sec, b := range a.buckets {
		if sec < oldest {
			continue
		}
		for k, st := range b {
			cur := out[k]
			cur.add(*st)
			out[k] = cur
		}
	}
	return out
}

// Evict 清理窗口外的秒桶
func (a *Aggregator) Evict(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	oldest := now.Add(-a.window + time.Second).Unix()
	for sec := range a.buckets {
		if sec < oldest {
			delete(a.buckets, sec)
		}
	}
}

// Len 当前桶数（用于测试/指标）
func (a *Aggregator) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.buckets)
}

// Thresholds 检测阈值（0 表示不启用该条件）
type Thresholds struct {
	MinFlows   uint64
	MinBytes   uint64
	MinPackets uint64
}

// Exceeded 判断统计是否同时满足所有已启用的阈值（**且**关系）：
// 连接数、流量（字节）、包数量三个条件均需达到各自阈值（0 = 不启用该条件）。
func (t Thresholds) Exceeded(s Stats) (bool, string) {
	var parts []string
	if t.MinFlows > 0 {
		if s.Flows < t.MinFlows {
			return false, ""
		}
		parts = append(parts, fmt.Sprintf("flows %d >= %d", s.Flows, t.MinFlows))
	}
	if t.MinBytes > 0 {
		if s.Bytes < t.MinBytes {
			return false, ""
		}
		parts = append(parts, fmt.Sprintf("bytes %d >= %d", s.Bytes, t.MinBytes))
	}
	if t.MinPackets > 0 {
		if s.Packets < t.MinPackets {
			return false, ""
		}
		parts = append(parts, fmt.Sprintf("packets %d >= %d", s.Packets, t.MinPackets))
	}
	if len(parts) == 0 {
		return false, ""
	}
	return true, strings.Join(parts, " && ")
}

// Rule 一个交换机 + 目标网段 + 阈值 + 命令
type Rule struct {
	Switch  string
	Targets []*net.IPNet
	Thresholds
}

// Hit 命中事件
type Hit struct {
	Switch string
	Key    Key
	Stats  Stats
	Proto  uint8 // 窗口内主导协议（用于命令模板 {proto}）
	Reason string
}

// Action 命中后的处置（由 switchctl 实现）。
// 一次检测批次内的多个命中作为一组下发：规则编号从起始编号（默认 800）
// 连续分配，每次批次都重新从起始编号开始（覆盖上一次的规则）。
type Action interface {
	RunBatch(switchName string, hits []Hit) error
}

// Detector 检测器：窗口快照 -> 规则匹配 -> 冷却抑制 -> 异步处置
type Detector struct {
	agg      *Aggregator
	rules    []Rule
	cooldown time.Duration
	dedupTTL time.Duration
	action   Action
	logger   *zap.Logger

	mu      sync.Mutex
	lastHit map[string]time.Time // switch|ip|port -> 上次命中时间
}

// NewDetector 创建检测器。
// cooldown 为最小重发间隔；dedupTTL 为处置后去重时间（已下发 ACL 的目标在
// 该时间内不再重复下发，避免持续攻击导致 ACL 膨胀）。实际跳过窗口取两者较大值。
func NewDetector(agg *Aggregator, rules []Rule, cooldown, dedupTTL time.Duration, action Action, logger *zap.Logger) *Detector {
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}
	if dedupTTL <= 0 {
		dedupTTL = 24 * time.Hour
	}
	return &Detector{
		agg:      agg,
		rules:    rules,
		cooldown: cooldown,
		dedupTTL: dedupTTL,
		action:   action,
		logger:   logger,
		lastHit:  make(map[string]time.Time),
	}
}

// Check 执行一次检测，返回本次命中（已通过冷却过滤）的事件列表
func (d *Detector) Check(now time.Time) []Hit {
	snap := d.agg.Snapshot(now)
	if len(snap) == 0 {
		return nil
	}

	var hits []Hit
	// 按交换机聚合本批次命中，批次内规则编号从起始编号连续分配
	batches := make(map[string][]Hit)
	for _, rule := range d.rules {
		for k, st := range snap {
			if !matchAny(rule.Targets, k.IP) {
				continue
			}
			ok, reason := rule.Thresholds.Exceeded(st)
			if !ok {
				continue
			}
			hk := hitKey(rule.Switch, k)
			skip := d.cooldown
			if d.dedupTTL > skip {
				skip = d.dedupTTL
			}
			d.mu.Lock()
			last, seen := d.lastHit[hk]
			if seen && now.Sub(last) < skip {
				d.mu.Unlock()
				continue
			}
			d.lastHit[hk] = now
			d.mu.Unlock()

			proto := st.DominantProto()
			hit := Hit{Switch: rule.Switch, Key: k, Stats: st, Proto: proto, Reason: reason}
			hits = append(hits, hit)
			batches[rule.Switch] = append(batches[rule.Switch], hit)
			d.logger.Warn("ddos attack detected",
				zap.String("switch", rule.Switch),
				zap.String("target_ip", k.IP),
				zap.Uint16("target_port", k.Port),
				zap.Uint8("proto", proto),
				zap.Uint64("flows", st.Flows),
				zap.Uint64("packets", st.Packets),
				zap.Uint64("bytes", st.Bytes),
				zap.String("reason", reason),
			)
		}
	}

	// 每批次异步处置一次（规则编号由处置器从起始编号重新开始分配）
	for switchName, batch := range batches {
		go func(sw string, hs []Hit) {
			if err := d.action.RunBatch(sw, hs); err != nil {
				d.logger.Error("switch action failed",
					zap.String("switch", sw),
					zap.Int("rules", len(hs)),
					zap.Error(err),
				)
			}
		}(switchName, batch)
	}
	return hits
}

// hitKey 冷却键
func hitKey(switchName string, k Key) string {
	return fmt.Sprintf("%s|%s|%d", switchName, k.IP, k.Port)
}

// matchAny 目标 IP 是否落入任一网段
func matchAny(nets []*net.IPNet, ipStr string) bool {
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
