package netflow

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildV5 构造 v5 包：n 条记录，dst=10.0.0.9:443，bytes=1500，pkts=100
func buildV5(n int) []byte {
	pkt := make([]byte, v5HeaderSize+n*v5RecordSize)
	binary.BigEndian.PutUint16(pkt[0:2], 5)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(n))
	binary.BigEndian.PutUint32(pkt[4:8], 70000)
	binary.BigEndian.PutUint32(pkt[8:12], 1700000070)
	for i := 0; i < n; i++ {
		off := v5HeaderSize + i*v5RecordSize
		rec := pkt[off : off+v5RecordSize]
		copy(rec[0:4], net.ParseIP("192.0.2.10").To4())
		copy(rec[4:8], net.ParseIP("10.0.0.9").To4())
		binary.BigEndian.PutUint32(rec[16:20], 100)
		binary.BigEndian.PutUint32(rec[20:24], 1500)
		binary.BigEndian.PutUint32(rec[24:28], 1000)
		binary.BigEndian.PutUint32(rec[28:32], 60000)
		binary.BigEndian.PutUint16(rec[32:34], 40000)
		binary.BigEndian.PutUint16(rec[34:36], 443)
		rec[38] = 6
	}
	return pkt
}

func TestParseV5(t *testing.T) {
	recs, err := Parse(buildV5(2), NewTemplateCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("records=%d", len(recs))
	}
	r := recs[0]
	if r.SrcIP != "192.0.2.10" || r.DstIP != "10.0.0.9" {
		t.Errorf("ips: %s -> %s", r.SrcIP, r.DstIP)
	}
	if r.DstPort != 443 || r.SrcPort != 40000 || r.Proto != 6 {
		t.Errorf("ports/proto: %d/%d/%d", r.SrcPort, r.DstPort, r.Proto)
	}
	if r.Bytes != 1500 || r.Packets != 100 {
		t.Errorf("counters: bytes=%d packets=%d", r.Bytes, r.Packets)
	}
}

func TestParseV5ICMP(t *testing.T) {
	pkt := buildV5(1)
	off := v5HeaderSize
	pkt[off+38] = 1 // ICMP
	binary.BigEndian.PutUint16(pkt[off+32:off+34], 8)
	binary.BigEndian.PutUint16(pkt[off+34:off+36], 0)
	recs, err := Parse(pkt, NewTemplateCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if recs[0].SrcPort != 0 || recs[0].DstPort != 0 {
		t.Errorf("ICMP ports must be cleared: %d/%d", recs[0].SrcPort, recs[0].DstPort)
	}
}

// buildV9 构造 v9 包：模板(256) + 数据(n 条)
func buildV9(n int) []byte {
	fields := []struct{ t, l uint16 }{
		{8, 4}, {12, 4}, {7, 2}, {11, 2}, {1, 4}, {2, 4}, {4, 1},
	}
	tmplSet := make([]byte, 4+4+len(fields)*4)
	binary.BigEndian.PutUint16(tmplSet[0:2], 0)
	binary.BigEndian.PutUint16(tmplSet[2:4], uint16(len(tmplSet)))
	binary.BigEndian.PutUint16(tmplSet[4:6], 256)
	binary.BigEndian.PutUint16(tmplSet[6:8], uint16(len(fields)))
	o := 8
	for _, f := range fields {
		binary.BigEndian.PutUint16(tmplSet[o:o+2], f.t)
		binary.BigEndian.PutUint16(tmplSet[o+2:o+4], f.l)
		o += 4
	}

	recLen := 4 + 4 + 2 + 2 + 4 + 4 + 1
	dataSet := make([]byte, 4+n*recLen)
	binary.BigEndian.PutUint16(dataSet[0:2], 256)
	binary.BigEndian.PutUint16(dataSet[2:4], uint16(len(dataSet)))
	o = 4
	for i := 0; i < n; i++ {
		copy(dataSet[o:o+4], net.ParseIP("192.0.2.20").To4())
		copy(dataSet[o+4:o+8], net.ParseIP("10.0.0.7").To4())
		binary.BigEndian.PutUint16(dataSet[o+8:o+10], 50000)
		binary.BigEndian.PutUint16(dataSet[o+10:o+12], 80)
		binary.BigEndian.PutUint32(dataSet[o+12:o+16], 8000)
		binary.BigEndian.PutUint32(dataSet[o+16:o+20], 50)
		dataSet[o+20] = 6
		o += recLen
	}

	pkt := make([]byte, v9HeaderSize+len(tmplSet)+len(dataSet))
	binary.BigEndian.PutUint16(pkt[0:2], 9)
	binary.BigEndian.PutUint32(pkt[4:8], 70000)
	binary.BigEndian.PutUint32(pkt[8:12], 1700000070)
	binary.BigEndian.PutUint32(pkt[16:20], 42)
	copy(pkt[v9HeaderSize:], tmplSet)
	copy(pkt[v9HeaderSize+len(tmplSet):], dataSet)
	return pkt
}

func TestParseV9(t *testing.T) {
	cache := NewTemplateCache(time.Hour)
	recs, err := Parse(buildV9(3), cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("records=%d", len(recs))
	}
	r := recs[0]
	if r.SrcIP != "192.0.2.20" || r.DstIP != "10.0.0.7" || r.DstPort != 80 || r.Bytes != 8000 || r.Packets != 50 {
		t.Errorf("record: %+v", r)
	}
}

// TestParseV9TemplatePersist 第二包（纯数据）仍能解析
func TestParseV9TemplatePersist(t *testing.T) {
	cache := NewTemplateCache(time.Hour)
	if _, err := Parse(buildV9(1), cache); err != nil {
		t.Fatal(err)
	}
	// 构造纯数据包
	full := buildV9(2)
	recLen := 4 + 4 + 2 + 2 + 4 + 4 + 1
	dataSet := full[v9HeaderSize+4+4+7*4:] // 模板 set 之后
	pkt := make([]byte, v9HeaderSize+len(dataSet))
	binary.BigEndian.PutUint16(pkt[0:2], 9)
	binary.BigEndian.PutUint32(pkt[4:8], 70000)
	binary.BigEndian.PutUint32(pkt[8:12], 1700000070)
	binary.BigEndian.PutUint32(pkt[16:20], 42)
	copy(pkt[v9HeaderSize:], dataSet)
	recs, err := Parse(pkt, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("records=%d (template should persist)", len(recs))
	}
	_ = recLen
}

// TestVersion 版本识别
func TestVersion(t *testing.T) {
	if v := Version(buildV5(1)); v != 5 {
		t.Errorf("v5 version=%d", v)
	}
	if v := Version(buildV9(1)); v != 9 {
		t.Errorf("v9 version=%d", v)
	}
	if v := Version([]byte{0, 10}); v != 10 {
		t.Errorf("ipfix version=%d", v)
	}
}

// TestParseIPFIXVariableLength IPFIX 变长字段解析
func TestParseIPFIXVariableLength(t *testing.T) {
	// 模板: 8(4) 12(4) 7(2) 11(2) 1(4) 2(4) 302(变长)
	fields := []struct{ t, l uint16 }{
		{8, 4}, {12, 4}, {7, 2}, {11, 2}, {1, 4}, {2, 4}, {302, 0xFFFF},
	}
	tmplSet := make([]byte, 4+4+len(fields)*4)
	binary.BigEndian.PutUint16(tmplSet[0:2], 2)
	binary.BigEndian.PutUint16(tmplSet[2:4], uint16(len(tmplSet)))
	binary.BigEndian.PutUint16(tmplSet[4:6], 300)
	binary.BigEndian.PutUint16(tmplSet[6:8], uint16(len(fields)))
	o := 8
	for _, f := range fields {
		binary.BigEndian.PutUint16(tmplSet[o:o+2], f.t)
		binary.BigEndian.PutUint16(tmplSet[o+2:o+4], f.l)
		o += 4
	}
	rec := make([]byte, 0, 32)
	rec = append(rec, 192, 0, 2, 30)
	rec = append(rec, 10, 0, 0, 1)
	rec = append(rec, 0x13, 0x88)  // 5000
	rec = append(rec, 0x00, 0x50)  // 80
	b4 := []byte{0, 0, 0x1f, 0x40} // 8000
	rec = append(rec, b4...)
	b4 = []byte{0, 0, 0, 0x20} // 32
	rec = append(rec, b4...)
	rec = append(rec, 4) // 变长长度
	rec = append(rec, "ddos"...)
	dataSet := make([]byte, 4+len(rec))
	binary.BigEndian.PutUint16(dataSet[0:2], 300)
	binary.BigEndian.PutUint16(dataSet[2:4], uint16(len(dataSet)))
	copy(dataSet[4:], rec)

	pkt := make([]byte, ipfixHeaderSize+len(tmplSet)+len(dataSet))
	binary.BigEndian.PutUint16(pkt[0:2], 10)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint32(pkt[4:8], 1700000000)
	binary.BigEndian.PutUint32(pkt[12:16], 7)
	copy(pkt[ipfixHeaderSize:], tmplSet)
	copy(pkt[ipfixHeaderSize+len(tmplSet):], dataSet)

	cache := NewTemplateCache(time.Hour)
	recs, err := Parse(pkt, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("records=%d", len(recs))
	}
	r := recs[0]
	if r.DstIP != "10.0.0.1" || r.DstPort != 80 || r.Bytes != 8000 || r.Packets != 32 {
		t.Errorf("record: %+v", r)
	}
}

// buildV5Sampled 构造带采样间隔的 v5 包
func buildV5Sampled(interval uint16) []byte {
	pkt := buildV5(1)
	binary.BigEndian.PutUint16(pkt[22:24], interval)
	return pkt
}

// TestV5Sampling 与 netstream 一致：v5 头采样间隔 → 计数按采样率放大
func TestV5Sampling(t *testing.T) {
	recs, err := Parse(buildV5Sampled(2048), NewTemplateCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if recs[0].SamplerInterval != 2048 || recs[0].SamplerMode != 1 {
		t.Fatalf("sampler: interval=%d mode=%d", recs[0].SamplerInterval, recs[0].SamplerMode)
	}
	recs[0].ScaleSampledCounters()
	if recs[0].Packets != 100*2048 || recs[0].Bytes != 1500*2048 {
		t.Errorf("scaled: packets=%d bytes=%d", recs[0].Packets, recs[0].Bytes)
	}
}

// TestV9SamplingIE34 与 netstream 一致：v9 IE 34（samplingFlowInterval）→ 放大
func TestV9SamplingIE34(t *testing.T) {
	// 模板: 8(4) 12(4) 11(2) 1(4) 2(4) 34(2)
	fields := []struct{ t, l uint16 }{
		{8, 4}, {12, 4}, {11, 2}, {1, 4}, {2, 4}, {34, 2},
	}
	tmplSet := make([]byte, 4+4+len(fields)*4)
	binary.BigEndian.PutUint16(tmplSet[0:2], 0)
	binary.BigEndian.PutUint16(tmplSet[2:4], uint16(len(tmplSet)))
	binary.BigEndian.PutUint16(tmplSet[4:6], 256)
	binary.BigEndian.PutUint16(tmplSet[6:8], uint16(len(fields)))
	o := 8
	for _, f := range fields {
		binary.BigEndian.PutUint16(tmplSet[o:o+2], f.t)
		binary.BigEndian.PutUint16(tmplSet[o+2:o+4], f.l)
		o += 4
	}
	recLen := 4 + 4 + 2 + 4 + 4 + 2
	dataSet := make([]byte, 4+recLen)
	binary.BigEndian.PutUint16(dataSet[0:2], 256)
	binary.BigEndian.PutUint16(dataSet[2:4], uint16(len(dataSet)))
	o = 4
	copy(dataSet[o:o+4], net.ParseIP("192.0.2.50").To4())
	copy(dataSet[o+4:o+8], net.ParseIP("203.0.113.9").To4())
	binary.BigEndian.PutUint16(dataSet[o+8:o+10], 443)
	binary.BigEndian.PutUint32(dataSet[o+10:o+14], 1500)
	binary.BigEndian.PutUint32(dataSet[o+14:o+18], 10)
	binary.BigEndian.PutUint16(dataSet[o+18:o+20], 2048)

	pkt := make([]byte, v9HeaderSize+len(tmplSet)+len(dataSet))
	binary.BigEndian.PutUint16(pkt[0:2], 9)
	binary.BigEndian.PutUint32(pkt[4:8], 70000)
	binary.BigEndian.PutUint32(pkt[8:12], 1700000070)
	binary.BigEndian.PutUint32(pkt[16:20], 42)
	copy(pkt[v9HeaderSize:], tmplSet)
	copy(pkt[v9HeaderSize+len(tmplSet):], dataSet)

	recs, err := Parse(pkt, NewTemplateCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].SamplerInterval != 2048 {
		t.Fatalf("records=%d sampler=%d", len(recs), recs[0].SamplerInterval)
	}
	recs[0].ScaleSampledCounters()
	if recs[0].Packets != 10*2048 || recs[0].Bytes != 1500*2048 {
		t.Errorf("scaled: packets=%d bytes=%d", recs[0].Packets, recs[0].Bytes)
	}
}

// TestV9OptionSampling 与 netstream 一致：选项数据记录的采样率应用到流记录
func TestV9OptionSampling(t *testing.T) {
	// 普通模板 256: 8(4) 12(4) 11(2) 1(4) 2(4)
	tmplSet := make([]byte, 4+4+5*4)
	binary.BigEndian.PutUint16(tmplSet[0:2], 0)
	binary.BigEndian.PutUint16(tmplSet[2:4], uint16(len(tmplSet)))
	binary.BigEndian.PutUint16(tmplSet[4:6], 256)
	binary.BigEndian.PutUint16(tmplSet[6:8], 5)
	of := tmplSet[8:]
	fields := []struct{ t, l uint16 }{{8, 4}, {12, 4}, {11, 2}, {1, 4}, {2, 4}}
	for i, f := range fields {
		binary.BigEndian.PutUint16(of[i*4:i*4+2], f.t)
		binary.BigEndian.PutUint16(of[i*4+2:i*4+4], f.l)
	}

	// 选项模板 257: scope=48(2B) + option=34(2B)
	optSet := make([]byte, 4+6+2*4)
	binary.BigEndian.PutUint16(optSet[0:2], 1)
	binary.BigEndian.PutUint16(optSet[2:4], uint16(len(optSet)))
	binary.BigEndian.PutUint16(optSet[4:6], 257)
	binary.BigEndian.PutUint16(optSet[6:8], 4)
	binary.BigEndian.PutUint16(optSet[8:10], 4)
	binary.BigEndian.PutUint16(optSet[10:12], 48)
	binary.BigEndian.PutUint16(optSet[12:14], 2)
	binary.BigEndian.PutUint16(optSet[14:16], 34)
	binary.BigEndian.PutUint16(optSet[16:18], 2)

	// 选项数据: samplerID=1, interval=2048
	optData := make([]byte, 4+4)
	binary.BigEndian.PutUint16(optData[0:2], 257)
	binary.BigEndian.PutUint16(optData[2:4], uint16(len(optData)))
	binary.BigEndian.PutUint16(optData[4:6], 1)
	binary.BigEndian.PutUint16(optData[6:8], 2048)

	// 流数据: 一条记录
	recLen := 4 + 4 + 2 + 4 + 4
	dataSet := make([]byte, 4+recLen)
	binary.BigEndian.PutUint16(dataSet[0:2], 256)
	binary.BigEndian.PutUint16(dataSet[2:4], uint16(len(dataSet)))
	o := 4
	copy(dataSet[o:o+4], net.ParseIP("192.0.2.50").To4())
	copy(dataSet[o+4:o+8], net.ParseIP("203.0.113.9").To4())
	binary.BigEndian.PutUint16(dataSet[o+8:o+10], 443)
	binary.BigEndian.PutUint32(dataSet[o+10:o+14], 1500)
	binary.BigEndian.PutUint32(dataSet[o+14:o+18], 10)

	pkt := make([]byte, v9HeaderSize+len(tmplSet)+len(optSet)+len(optData)+len(dataSet))
	binary.BigEndian.PutUint16(pkt[0:2], 9)
	binary.BigEndian.PutUint32(pkt[4:8], 70000)
	binary.BigEndian.PutUint32(pkt[8:12], 1700000070)
	binary.BigEndian.PutUint32(pkt[16:20], 42)
	pos := v9HeaderSize
	copy(pkt[pos:], tmplSet)
	pos += len(tmplSet)
	copy(pkt[pos:], optSet)
	pos += len(optSet)
	copy(pkt[pos:], optData)
	pos += len(optData)
	copy(pkt[pos:], dataSet)

	cache := NewTemplateCache(time.Hour)
	recs, err := Parse(pkt, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("records=%d (option data must not produce flows)", len(recs))
	}
	if recs[0].SamplerInterval != 2048 {
		t.Fatalf("sampler from option record = %d, want 2048", recs[0].SamplerInterval)
	}
	recs[0].ScaleSampledCounters()
	if recs[0].Packets != 10*2048 || recs[0].Bytes != 1500*2048 {
		t.Errorf("scaled: packets=%d bytes=%d", recs[0].Packets, recs[0].Bytes)
	}
}

// TestDefaultSamplingConfig 与 netstream 一致：设备无采样信息时按导出 IP 用默认采样率
func TestDefaultSamplingConfig(t *testing.T) {
	recs, err := Parse(buildV5(1), NewTemplateCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	r := &recs[0]
	if r.SamplerInterval != 0 {
		t.Fatalf("unexpected sampler: %d", r.SamplerInterval)
	}
	defaults := map[string]int{"192.168.100.1": 2048}
	r.ApplyDefaultSampling("10.0.0.9", defaults) // 未配置的 exporter
	if r.SamplerInterval != 0 {
		t.Errorf("unconfigured exporter must not get sampler")
	}
	r.ApplyDefaultSampling("192.168.100.1", defaults)
	if r.SamplerInterval != 2048 || r.SamplerMode != 1 {
		t.Fatalf("default sampler not applied: %d/%d", r.SamplerInterval, r.SamplerMode)
	}
	r.ScaleSampledCounters()
	if r.Packets != 100*2048 || r.Bytes != 1500*2048 {
		t.Errorf("scaled: packets=%d bytes=%d", r.Packets, r.Bytes)
	}
}
