// Package netflow 解析 NetFlow v5/v9 与 IPFIX(v10) 数据包，
// 提取 DDoS 检测所需字段：目标 IP/端口、源 IP、协议、包数、字节数、时间。
package netflow

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// Record 单条流记录（检测所需字段）
type Record struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Packets uint64
	Bytes   uint64
	First   int64 // 首包时间（ms epoch），0 表示未知
	Last    int64 // 末包时间（ms epoch），0 表示未知
}

// 协议版本常量
const (
	Version5  = 5
	Version9  = 9
	Version10 = 10
)

// 模板字段
type fieldSpec struct {
	Type   uint16
	Length uint16
}

// template v9/IPFIX 模板
type template struct {
	ID       uint16
	Fields   []fieldSpec
	TotalLen uint16
	IsOption bool
	LastSeen time.Time
}

// TemplateCache v9/IPFIX 模板缓存（并发安全）
type TemplateCache struct {
	mu        sync.Mutex
	templates map[uint64]*template
	timeout   time.Duration
}

// NewTemplateCache 创建模板缓存；timeout <= 0 使用 30 分钟
func NewTemplateCache(timeout time.Duration) *TemplateCache {
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	return &TemplateCache{
		templates: make(map[uint64]*template),
		timeout:   timeout,
	}
}

func (c *TemplateCache) key(version uint8, domainID uint32, tmplID uint16) uint64 {
	return uint64(version)<<48 | uint64(domainID)<<16 | uint64(tmplID)
}

func (c *TemplateCache) get(version uint8, domainID uint32, tmplID uint16) *template {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := c.key(version, domainID, tmplID)
	t, ok := c.templates[k]
	if !ok {
		return nil
	}
	if time.Since(t.LastSeen) > c.timeout {
		delete(c.templates, k)
		return nil
	}
	t.LastSeen = time.Now() // 命中刷新，避免活跃模板被误删
	return t
}

func (c *TemplateCache) put(version uint8, domainID uint32, t *template) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t.LastSeen = time.Now()
	c.templates[c.key(version, domainID, t.ID)] = t
}

// Parse 解析数据包，返回流记录
func Parse(data []byte, cache *TemplateCache) ([]Record, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("packet too short")
	}
	switch binary.BigEndian.Uint16(data[0:2]) {
	case Version5:
		return parseV5(data)
	case Version9:
		return parseV9(data, cache)
	case Version10:
		return parseIPFIX(data, cache)
	default:
		return nil, fmt.Errorf("unsupported netflow version")
	}
}

// Version 返回数据包协议版本
func Version(data []byte) uint16 {
	if len(data) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(data[0:2])
}

// ---- NetFlow v5 ----

const (
	v5HeaderSize = 24
	v5RecordSize = 48
)

func parseV5(data []byte) ([]Record, error) {
	if len(data) < v5HeaderSize {
		return nil, fmt.Errorf("v5: packet too short")
	}
	count := int(binary.BigEndian.Uint16(data[2:4]))
	sysUptime := int64(binary.BigEndian.Uint32(data[4:8]))
	unixSecs := int64(binary.BigEndian.Uint32(data[8:12]))
	if count == 0 {
		return nil, nil
	}
	if len(data) < v5HeaderSize+count*v5RecordSize {
		return nil, fmt.Errorf("v5: truncated records")
	}
	base := unixSecs*1000 - sysUptime

	out := make([]Record, 0, count)
	for i := 0; i < count; i++ {
		off := v5HeaderSize + i*v5RecordSize
		rec := data[off : off+v5RecordSize]
		r := Record{
			SrcIP:   net.IP(rec[0:4]).String(),
			DstIP:   net.IP(rec[4:8]).String(),
			Packets: uint64(binary.BigEndian.Uint32(rec[16:20])),
			Bytes:   uint64(binary.BigEndian.Uint32(rec[20:24])),
			SrcPort: binary.BigEndian.Uint16(rec[32:34]),
			DstPort: binary.BigEndian.Uint16(rec[34:36]),
			Proto:   rec[38],
		}
		r.First = base + int64(binary.BigEndian.Uint32(rec[24:28]))
		r.Last = base + int64(binary.BigEndian.Uint32(rec[28:32]))
		if r.Proto == 1 || r.Proto == 58 {
			// ICMP: 端口字段存放 type/code，不作为端口统计
			r.SrcPort, r.DstPort = 0, 0
		}
		out = append(out, r)
	}
	return out, nil
}

// ---- NetFlow v9 ----

const (
	v9HeaderSize = 20
	v9TemplateID = 0
	v9OptionID   = 1
	v9DataMin    = 256
)

// v9 字段编号（IANA/Cisco 共享）
const (
	fSrcIPv4       = 8
	fDstIPv4       = 12
	fSrcPort       = 7
	fDstPort       = 11
	fInBytes       = 1
	fInPkts        = 2
	fProto         = 4
	fFirstSwitched = 22
	fLastSwitched  = 21
	fSrcIPv6       = 27
	fDstIPv6       = 28
	fOutBytes      = 23
	fOutPkts       = 24
	fOctetTotal    = 85
	fPacketTotal   = 86
)

func parseV9(data []byte, cache *TemplateCache) ([]Record, error) {
	if len(data) < v9HeaderSize {
		return nil, fmt.Errorf("v9: packet too short")
	}
	sysUptime := int64(binary.BigEndian.Uint32(data[4:8]))
	unixSecs := int64(binary.BigEndian.Uint32(data[8:12]))
	domainID := binary.BigEndian.Uint32(data[16:20])
	base := unixSecs*1000 - sysUptime

	var out []Record
	offset := v9HeaderSize
	for offset+4 <= len(data) {
		setID := binary.BigEndian.Uint16(data[offset : offset+2])
		setLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if setLen < 4 || offset+setLen > len(data) {
			break
		}
		set := data[offset : offset+setLen]
		switch {
		case setID == v9TemplateID || setID == v9OptionID:
			parseV9Templates(set, domainID, cache, setID == v9OptionID)
		case setID >= v9DataMin:
			t := cache.get(Version9, domainID, setID)
			if t != nil {
				if t.IsOption {
					// 选项数据（采样器等）与检测无关，跳过
				} else {
					out = append(out, parseV9Records(set, t, base)...)
				}
			}
		}
		offset += setLen
	}
	return out, nil
}

func parseV9Templates(set []byte, domainID uint32, cache *TemplateCache, isOption bool) {
	offset := 4
	for offset+4 <= len(set) {
		tmplID := binary.BigEndian.Uint16(set[offset : offset+2])
		offset += 2
		var fieldCount uint16
		if isOption {
			// Options Template: Template ID + Scope Length + Option Length
			if offset+4 > len(set) {
				return
			}
			scopeLen := binary.BigEndian.Uint16(set[offset : offset+2])
			optLen := binary.BigEndian.Uint16(set[offset+2 : offset+4])
			offset += 4
			fieldCount = (scopeLen + optLen) / 4
		} else {
			fieldCount = binary.BigEndian.Uint16(set[offset : offset+2])
			offset += 2
		}
		if offset+int(fieldCount)*4 > len(set) {
			return
		}
		t := &template{ID: tmplID, IsOption: isOption}
		var total uint16
		for i := uint16(0); i < fieldCount; i++ {
			ft := binary.BigEndian.Uint16(set[offset : offset+2])
			fl := binary.BigEndian.Uint16(set[offset+2 : offset+4])
			offset += 4
			t.Fields = append(t.Fields, fieldSpec{Type: ft, Length: fl})
			total += fl
		}
		t.TotalLen = total
		cache.put(Version9, domainID, t)
	}
}

// parseV9Records 解析固定长度数据记录
func parseV9Records(set []byte, t *template, base int64) []Record {
	recLen := int(t.TotalLen)
	if recLen <= 0 {
		return nil
	}
	var out []Record
	offset := 4
	for offset+recLen <= len(set) {
		r := Record{}
		pos := offset
		for _, f := range t.Fields {
			if pos+int(f.Length) > len(set) {
				return out
			}
			applyField(&r, f.Type, set[pos:pos+int(f.Length)], base)
			pos += int(f.Length)
		}
		out = append(out, r)
		offset += recLen
	}
	return out
}

// applyField 应用 v9/IPFIX 字段值（编号共享）
func applyField(r *Record, fieldType uint16, data []byte, base int64) {
	switch fieldType {
	case fSrcIPv4:
		if len(data) >= 4 {
			r.SrcIP = net.IP(data[:4]).String()
		}
	case fDstIPv4:
		if len(data) >= 4 {
			r.DstIP = net.IP(data[:4]).String()
		}
	case fSrcIPv6:
		if len(data) >= 16 {
			r.SrcIP = net.IP(data[:16]).String()
		}
	case fDstIPv6:
		if len(data) >= 16 {
			r.DstIP = net.IP(data[:16]).String()
		}
	case fSrcPort:
		if len(data) >= 2 {
			r.SrcPort = binary.BigEndian.Uint16(data[:2])
		}
	case fDstPort:
		if len(data) >= 2 {
			r.DstPort = binary.BigEndian.Uint16(data[:2])
		}
	case fInBytes, fOutBytes, fOctetTotal:
		r.Bytes = readUint(data)
	case fInPkts, fOutPkts, fPacketTotal:
		r.Packets = readUint(data)
	case fProto:
		if len(data) >= 1 {
			r.Proto = data[0]
		}
	case fFirstSwitched:
		if r.First == 0 {
			r.First = base + int64(readUint(data))
		}
	case fLastSwitched:
		r.Last = base + int64(readUint(data))
	}
}

// ---- IPFIX(v10) ----

const (
	ipfixHeaderSize  = 16
	ipfixSetTemplate = 2
	ipfixSetOption   = 3
	ipfixDataMin     = 256
	enterpriseBit    = 0x8000
)

// IPFIX 特有字段
const (
	fIPFIXStartMs  = 152
	fIPFIXEndMs    = 153
	fIPFIXStartSec = 150
	fIPFIXEndSec   = 151
)

func parseIPFIX(data []byte, cache *TemplateCache) ([]Record, error) {
	if len(data) < ipfixHeaderSize {
		return nil, fmt.Errorf("ipfix: packet too short")
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length > len(data) || length < ipfixHeaderSize {
		length = len(data)
	}
	exportTime := int64(binary.BigEndian.Uint32(data[4:8]))
	domainID := binary.BigEndian.Uint32(data[12:16])

	var out []Record
	offset := ipfixHeaderSize
	for offset+4 <= length {
		setID := binary.BigEndian.Uint16(data[offset : offset+2])
		setLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if setLen < 4 || offset+setLen > length {
			break
		}
		set := data[offset : offset+setLen]
		switch {
		case setID == ipfixSetTemplate || setID == ipfixSetOption:
			parseIPFIXTemplates(set, domainID, cache, setID == ipfixSetOption)
		case setID >= ipfixDataMin:
			t := cache.get(Version10, domainID, setID)
			if t != nil && !t.IsOption {
				out = append(out, parseIPFIXRecords(set, t, exportTime)...)
			}
		}
		offset += setLen
	}
	return out, nil
}

func parseIPFIXTemplates(set []byte, domainID uint32, cache *TemplateCache, isOption bool) {
	offset := 4
	for offset+4 <= len(set) {
		tmplID := binary.BigEndian.Uint16(set[offset : offset+2])
		offset += 2
		fieldCount := binary.BigEndian.Uint16(set[offset : offset+2])
		offset += 2
		if isOption {
			offset += 2 // Scope Field Count
		}
		if offset+int(fieldCount)*4 > len(set) {
			return
		}
		t := &template{ID: tmplID, IsOption: isOption}
		var total uint16
		for i := uint16(0); i < fieldCount; i++ {
			ft := binary.BigEndian.Uint16(set[offset : offset+2])
			fl := binary.BigEndian.Uint16(set[offset+2 : offset+4])
			offset += 4
			if ft&enterpriseBit != 0 {
				offset += 4
				ft &^= enterpriseBit
			}
			t.Fields = append(t.Fields, fieldSpec{Type: ft, Length: fl})
			total += fl
		}
		t.TotalLen = total
		cache.put(Version10, domainID, t)
	}
}

// parseIPFIXRecords 解析 IPFIX 数据记录，支持变长字段（长度 0xFFFF）
func parseIPFIXRecords(set []byte, t *template, exportTime int64) []Record {
	var out []Record
	offset := 4
	end := len(set)
	for offset < end {
		r := Record{}
		pos := offset
		ok := true
		for _, f := range t.Fields {
			flen := int(f.Length)
			if f.Length == 0xFFFF {
				if pos >= end {
					ok = false
					break
				}
				l := int(set[pos])
				pos++
				if l == 255 {
					if pos+2 > end {
						ok = false
						break
					}
					l = int(binary.BigEndian.Uint16(set[pos : pos+2]))
					pos += 2
				}
				flen = l
			}
			if pos+flen > end {
				ok = false
				break
			}
			applyIPFIXField(&r, f.Type, set[pos:pos+flen], exportTime)
			pos += flen
		}
		if !ok {
			break
		}
		out = append(out, r)
		offset = pos
	}
	return out
}

func applyIPFIXField(r *Record, fieldType uint16, data []byte, exportTime int64) {
	switch fieldType {
	case fIPFIXStartMs:
		if len(data) >= 8 {
			r.First = int64(binary.BigEndian.Uint64(data))
		}
	case fIPFIXEndMs:
		if len(data) >= 8 {
			r.Last = int64(binary.BigEndian.Uint64(data))
		}
	case fIPFIXStartSec:
		if len(data) >= 4 {
			r.First = int64(binary.BigEndian.Uint32(data)) * 1000
		}
	case fIPFIXEndSec:
		if len(data) >= 4 {
			r.Last = int64(binary.BigEndian.Uint32(data)) * 1000
		}
	default:
		applyField(r, fieldType, data, exportTime*1000)
	}
}

// readUint 读取 1/2/4/8 字节大端无符号整数
func readUint(data []byte) uint64 {
	switch len(data) {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(data))
	case 4:
		return uint64(binary.BigEndian.Uint32(data))
	case 8:
		return binary.BigEndian.Uint64(data)
	}
	return 0
}
