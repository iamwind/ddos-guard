package detect

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"ddosguard/internal/netflow"
)

// recordingAction 记录处置调用
type recordingAction struct {
	mu    sync.Mutex
	calls []Key
}

func (r *recordingAction) RunBatch(switchName string, hits []Hit) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range hits {
		r.calls = append(r.calls, h.Key)
	}
	return nil
}

func (r *recordingAction) snapshot() []Key {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Key, len(r.calls))
	copy(out, r.calls)
	return out
}

// buildAttackV5 构造 v5 包：n 条流，dst=203.0.113.9:443
func buildAttackV5(n int) []byte {
	pkt := make([]byte, 24+n*48)
	binary.BigEndian.PutUint16(pkt[0:2], 5)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(n))
	binary.BigEndian.PutUint32(pkt[4:8], 70000)
	binary.BigEndian.PutUint32(pkt[8:12], uint32(time.Now().Unix()))
	for i := 0; i < n; i++ {
		off := 24 + i*48
		rec := pkt[off : off+48]
		copy(rec[0:4], net.ParseIP("192.0.2.50").To4())
		copy(rec[4:8], net.ParseIP("203.0.113.9").To4())
		binary.BigEndian.PutUint32(rec[16:20], 10)
		binary.BigEndian.PutUint32(rec[20:24], 1500)
		binary.BigEndian.PutUint32(rec[24:28], 1000)
		binary.BigEndian.PutUint32(rec[28:32], 60000)
		binary.BigEndian.PutUint16(rec[32:34], 40000)
		binary.BigEndian.PutUint16(rec[34:36], 443)
		rec[38] = 6
	}
	return pkt
}

// TestIntegrationUDPToAction 端到端：UDP 收包 -> 解析 -> 目标过滤 -> 聚合 -> 检测 -> 处置
func TestIntegrationUDPToAction(t *testing.T) {
	// 目标网段
	_, targetNet, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}

	// 聚合与检测
	agg := NewAggregator(2 * time.Second)
	act := &recordingAction{}
	rules := []Rule{{
		Switch:     "sw1",
		Targets:    []*net.IPNet{targetNet},
		Thresholds: Thresholds{MinFlows: 5},
	}}
	det := NewDetector(agg, rules, time.Minute, time.Hour, act, zap.NewNop())

	// UDP 监听
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cache := netflow.NewTemplateCache(time.Hour)
	// reader + 解析（模拟 main 的处理链）
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		ln.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		records, err := netflow.Parse(buf[:n], cache)
		if err != nil {
			return
		}
		now := time.Now()
		for _, r := range records {
			if r.DstIP == "" {
				continue
			}
			ip := net.ParseIP(r.DstIP)
			if ip == nil || !targetNet.Contains(ip) {
				continue
			}
			agg.Add(Key{IP: r.DstIP, Port: r.DstPort}, r.Proto, r.Packets, r.Bytes, now)
		}
	}()

	// 发送攻击流量：10 条同一目标 IP:443 的流
	if _, err := ln.WriteToUDP(buildAttackV5(10), ln.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	<-done

	// 检测
	var hits []Hit
	for i := 0; i < 5 && len(hits) == 0; i++ {
		hits = det.Check(time.Now())
		time.Sleep(20 * time.Millisecond)
	}
	if len(hits) != 1 {
		t.Fatalf("hits=%d, want 1", len(hits))
	}
	if hits[0].Key.IP != "203.0.113.9" || hits[0].Key.Port != 443 {
		t.Fatalf("hit key: %+v", hits[0].Key)
	}
	if hits[0].Stats.Flows != 10 || hits[0].Stats.Bytes != 15000 {
		t.Fatalf("hit stats: %+v", hits[0].Stats)
	}

	// 处置已触发
	time.Sleep(50 * time.Millisecond)
	calls := act.snapshot()
	if len(calls) != 1 || calls[0].IP != "203.0.113.9" || calls[0].Port != 443 {
		t.Fatalf("action calls: %+v", calls)
	}
}
