package detect

import (
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func mustNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, nw, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return nw
}

// TestAggregatorWindow 滑动窗口：窗口内累计、窗口外滚出
func TestAggregatorWindow(t *testing.T) {
	agg := NewAggregator(5 * time.Second)
	base := time.Unix(1700000000, 0)
	k := Key{IP: "203.0.113.5", Port: 443}

	// 每秒加 1 条流，共 5 秒
	for i := 0; i < 5; i++ {
		agg.Add(k, 17, 100, 1000, base.Add(time.Duration(i)*time.Second))
	}
	snap := agg.Snapshot(base.Add(4 * time.Second))
	st := snap[k]
	if st.Flows != 5 || st.Packets != 500 || st.Bytes != 5000 {
		t.Fatalf("window stats: %+v", st)
	}

	// 时间前进 6 秒：旧桶滚出，新事件进入
	agg.Evict(base.Add(10 * time.Second))
	snap = agg.Snapshot(base.Add(10 * time.Second))
	if st := snap[k]; st.Flows != 0 {
		t.Fatalf("expired stats: %+v", st)
	}
	if agg.Len() != 0 {
		t.Fatalf("buckets not evicted: %d", agg.Len())
	}
}

// TestAggregatorPerSecondBuckets 同一秒内多次添加
func TestAggregatorPerSecondBuckets(t *testing.T) {
	agg := NewAggregator(5 * time.Second)
	now := time.Unix(1700000000, 0)
	k := Key{IP: "10.0.0.1", Port: 80}
	for i := 0; i < 100; i++ {
		agg.Add(k, 17, 1, 100, now)
	}
	st := agg.Snapshot(now)[k]
	if st.Flows != 100 || st.Bytes != 10000 {
		t.Fatalf("stats: %+v", st)
	}
}

// fakeAction 记录执行
type fakeAction struct {
	mu    sync.Mutex
	calls []Key
}

func (f *fakeAction) RunBatch(switchName string, hits []Hit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range hits {
		f.calls = append(f.calls, h.Key)
	}
	return nil
}

func (f *fakeAction) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// TestDetectorHitAndCooldown 命中 + 冷却抑制 + 目标网段过滤
func TestDetectorHitAndCooldown(t *testing.T) {
	agg := NewAggregator(5 * time.Second)
	act := &fakeAction{}
	rules := []Rule{{
		Switch:     "sw1",
		Targets:    []*net.IPNet{mustNet(t, "203.0.113.0/24")},
		Thresholds: Thresholds{MinFlows: 10},
	}}
	det := NewDetector(agg, rules, time.Second, time.Hour, act, zap.NewNop())

	now := time.Unix(1700000000, 0)
	// 目标网段内：命中
	for i := 0; i < 10; i++ {
		agg.Add(Key{IP: "203.0.113.9", Port: 443}, 17, 1, 100, now)
	}
	// 网段外：不应命中
	for i := 0; i < 100; i++ {
		agg.Add(Key{IP: "198.51.100.9", Port: 443}, 17, 1, 100, now)
	}
	// 低于阈值：不应命中
	agg.Add(Key{IP: "203.0.113.10", Port: 80}, 6, 1, 100, now)

	hits := det.Check(now)
	if len(hits) != 1 {
		t.Fatalf("hits=%d, want 1 (%+v)", len(hits), hits)
	}
	if hits[0].Key.IP != "203.0.113.9" || hits[0].Key.Port != 443 {
		t.Errorf("hit key: %+v", hits[0].Key)
	}
	time.Sleep(50 * time.Millisecond) // 等待异步 action
	if act.count() != 1 {
		t.Fatalf("action calls=%d", act.count())
	}

	// 冷却期内重复检测：不再触发
	hits = det.Check(now.Add(10 * time.Second))
	if len(hits) != 0 {
		t.Fatalf("cooldown violated: %+v", hits)
	}

	// dedup 期内（1 小时）重新出现攻击流量：不重复下发（避免 ACL 膨胀）
	later := now.Add(61 * time.Second)
	for i := 0; i < 10; i++ {
		agg.Add(Key{IP: "203.0.113.9", Port: 443}, 17, 1, 100, later)
	}
	if hits = det.Check(later); len(hits) != 0 {
		t.Fatalf("dedup violated: %+v", hits)
	}

	// dedup 期过后再次触发（新检测器以验证 cooldown 之外的路径）
	act2 := &fakeAction{}
	det2 := NewDetector(agg, rules, time.Second, time.Minute, act2, zap.NewNop())
	after := now.Add(2 * time.Minute)
	for i := 0; i < 10; i++ {
		agg.Add(Key{IP: "203.0.113.9", Port: 443}, 17, 1, 100, after)
	}
	if hits = det2.Check(after); len(hits) != 1 {
		t.Fatalf("after dedup hits=%d", len(hits))
	}
}

// TestThresholds 阈值判定（**且**关系：所有已启用条件需同时满足）
func TestThresholds(t *testing.T) {
	th := Thresholds{MinFlows: 100, MinBytes: 1000, MinPackets: 50}

	// 全部满足 → 触发
	if ok, reason := th.Exceeded(Stats{Flows: 100, Bytes: 1000, Packets: 50}); !ok {
		t.Errorf("all conditions satisfied should trigger: %s", reason)
	}
	// 只满足连接数 → 不触发
	if ok, _ := th.Exceeded(Stats{Flows: 100, Bytes: 999, Packets: 50}); ok {
		t.Error("flows only must not trigger (AND)")
	}
	// 只满足流量 → 不触发
	if ok, _ := th.Exceeded(Stats{Flows: 99, Bytes: 1000, Packets: 50}); ok {
		t.Error("bytes only must not trigger (AND)")
	}
	// 只满足包数 → 不触发
	if ok, _ := th.Exceeded(Stats{Flows: 100, Bytes: 1000, Packets: 49}); ok {
		t.Error("packets only must not trigger (AND)")
	}
	// 两项满足、缺一项 → 不触发
	if ok, _ := th.Exceeded(Stats{Flows: 100, Bytes: 1000}); ok {
		t.Error("missing packets must not trigger (AND)")
	}
	// 未启用的条件（0）忽略：仅 flows 启用
	th2 := Thresholds{MinFlows: 10}
	if ok, _ := th2.Exceeded(Stats{Flows: 10}); !ok {
		t.Error("single enabled condition should trigger")
	}
}
