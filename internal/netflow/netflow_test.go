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
