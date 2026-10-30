package config

import (
	"fmt"
	"net"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"io/ioutil"
)

// Config 应用配置
type Config struct {
	Collector CollectorConfig `yaml:"collector"`
	Detection DetectionConfig `yaml:"detection"`
	Switches  []SwitchConfig  `yaml:"switches"`
	HTTP      HTTPConfig      `yaml:"http"`
	Sampling  SamplingConfig  `yaml:"sampling"`
}

// SamplingConfig 采样配置（与 netstream-collector 相同语义）
type SamplingConfig struct {
	// Defaults 设备未在流记录/选项记录中提供采样率时的默认采样间隔
	// （按导出设备 IP），华为等设备常不提供采样信息。
	Defaults map[string]int `yaml:"defaults"`
}

// HTTPConfig metrics/health 监听配置
type HTTPConfig struct {
	// Listen 监听地址（如 ":8080" 或 "127.0.0.1:9090"）；空=不启用
	Listen string `yaml:"listen"`
}

// CollectorConfig NetFlow 接收配置
type CollectorConfig struct {
	Listen     string `yaml:"listen"`
	BufferSize int    `yaml:"buffer_size"`
	Workers    int    `yaml:"workers"`
}

// DetectionConfig 全局检测参数（可被每个交换机单独覆盖）
type DetectionConfig struct {
	Window        time.Duration `yaml:"window"`         // 聚合窗口，默认 5s
	CheckInterval time.Duration `yaml:"check_interval"` // 检测周期，默认 1s
	Cooldown      time.Duration `yaml:"cooldown"`       // 最小重发间隔，默认 300s
	// DedupTTL 同一「交换机+IP+端口」处置后的去重时间（默认 24h）：
	// 已下发 ACL 的目标在此时长内不再重复下发，避免持续攻击导致 ACL 膨胀。
	DedupTTL   time.Duration `yaml:"dedup_ttl"`
	MinFlows   uint64        `yaml:"min_flows"`   // 窗口内最小连接数（flow 数）
	MinBytes   uint64        `yaml:"min_bytes"`   // 窗口内最小字节数
	MinPackets uint64        `yaml:"min_packets"` // 窗口内最小包数（可选）
}

// SwitchConfig 交换机 + 目标 IP 段 + 命令模板
type SwitchConfig struct {
	Name       string        `yaml:"name"`
	Host       string        `yaml:"host"`
	Port       int           `yaml:"port"`
	Username   string        `yaml:"username"`
	Password   string        `yaml:"password"`
	PrivateKey string        `yaml:"private_key"`
	Timeout    time.Duration `yaml:"timeout"`

	// ACL rule 编号：每次命中批次内的多条规则都从 RuleIDStart（默认 800）
	// 开始连续分配（800、801、802...），下一次批次重新从起始编号开始，
	// 覆盖上一次下发的规则。
	RuleIDStart int `yaml:"rule_id_start"`

	// SSHEnabled 是否执行 SSH 命令（默认 true）。
	// 设为 false 时仅检测并记录日志（含将下发的命令），不登录交换机，
	// 适合试运行/演练。
	SSHEnabled *bool `yaml:"ssh_enabled"`

	Targets []string `yaml:"targets"` // 目标 IP 段（CIDR 或单个 IP）

	// 可选：覆盖全局阈值
	MinFlows   *uint64 `yaml:"min_flows"`
	MinBytes   *uint64 `yaml:"min_bytes"`
	MinPackets *uint64 `yaml:"min_packets"`

	// 命令模板，支持 {ip} / {port} / {proto} / {rule_id} 占位符。
	// ICMP/ICMPv6 无端口，渲染时会自动去掉端口片段（如 destination-port eq {port}）。
	Commands []string `yaml:"commands"`
	// 登录后先执行的命令（可选，如 enable）
	LoginCommands []string `yaml:"login_commands"`

	// 解析后的目标网段
	Nets []*net.IPNet `yaml:"-"`
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		Collector: CollectorConfig{
			Listen:     "0.0.0.0:2055",
			BufferSize: 65535,
			Workers:    4,
		},
		Detection: DetectionConfig{
			Window:        5 * time.Second,
			CheckInterval: time.Second,
			Cooldown:      300 * time.Second,
			MinFlows:      1000,
			MinBytes:      20 * 1024 * 1024,
		},
		HTTP: HTTPConfig{Listen: ":8080"},
	}
}

// Load 加载并校验配置文件
func Load(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate 校验配置并解析目标网段
func (c *Config) Validate() error {
	if c.Collector.Listen == "" {
		c.Collector.Listen = "0.0.0.0:2055"
	}
	if c.Collector.Workers <= 0 {
		c.Collector.Workers = 4
	}
	if c.Detection.Window <= 0 {
		c.Detection.Window = 5 * time.Second
	}
	if c.Detection.CheckInterval <= 0 {
		c.Detection.CheckInterval = time.Second
	}
	if c.Detection.Cooldown <= 0 {
		c.Detection.Cooldown = 300 * time.Second
	}
	if c.Detection.DedupTTL <= 0 {
		c.Detection.DedupTTL = 24 * time.Hour
	}
	if c.Detection.MinFlows == 0 && c.Detection.MinBytes == 0 && c.Detection.MinPackets == 0 {
		return fmt.Errorf("detection: at least one of min_flows/min_bytes/min_packets must be > 0")
	}

	seen := map[string]bool{}
	for i := range c.Switches {
		sw := &c.Switches[i]
		if sw.Name == "" {
			sw.Name = sw.Host
		}
		if seen[sw.Name] {
			return fmt.Errorf("switches: duplicate name %q", sw.Name)
		}
		seen[sw.Name] = true
		if sw.Host == "" {
			return fmt.Errorf("switches[%s]: host is required", sw.Name)
		}
		if sw.Port <= 0 {
			sw.Port = 22
		}
		if sw.Username == "" {
			return fmt.Errorf("switches[%s]: username is required", sw.Name)
		}
		if sw.Password == "" && sw.PrivateKey == "" {
			return fmt.Errorf("switches[%s]: password or private_key is required", sw.Name)
		}
		if sw.Timeout <= 0 {
			sw.Timeout = 10 * time.Second
		}
		if sw.RuleIDStart <= 0 {
			sw.RuleIDStart = 800
		}
		if sw.SSHEnabled == nil {
			enabled := true
			sw.SSHEnabled = &enabled
		}
		if sw.RuleIDStart > 65534 {
			return fmt.Errorf("switches[%s]: rule_id_start must be <= 65534", sw.Name)
		}
		if len(sw.Targets) == 0 {
			return fmt.Errorf("switches[%s]: targets is required", sw.Name)
		}
		if len(sw.Commands) == 0 {
			return fmt.Errorf("switches[%s]: commands is required", sw.Name)
		}
		// 至少一个有效阈值
		mf, mb, mp := c.thresholds(sw)
		if mf == 0 && mb == 0 && mp == 0 {
			return fmt.Errorf("switches[%s]: at least one threshold must be > 0", sw.Name)
		}
		// 解析网段
		sw.Nets = nil
		for _, t := range sw.Targets {
			nw, err := parseTarget(t)
			if err != nil {
				return fmt.Errorf("switches[%s]: invalid target %q: %w", sw.Name, t, err)
			}
			sw.Nets = append(sw.Nets, nw)
		}
	}
	return nil
}

// thresholds 返回交换机生效的阈值（覆盖全局）
func (c *Config) thresholds(sw *SwitchConfig) (flows, bytes, packets uint64) {
	flows, bytes, packets = c.Detection.MinFlows, c.Detection.MinBytes, c.Detection.MinPackets
	if sw.MinFlows != nil {
		flows = *sw.MinFlows
	}
	if sw.MinBytes != nil {
		bytes = *sw.MinBytes
	}
	if sw.MinPackets != nil {
		packets = *sw.MinPackets
	}
	return
}

// Thresholds 对外暴露交换机生效阈值
func (c *Config) Thresholds(sw *SwitchConfig) (flows, bytes, packets uint64) {
	return c.thresholds(sw)
}

// parseTarget 解析目标：支持 CIDR 与单个 IP（自动补 /32 或 /128）
func parseTarget(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty target")
	}
	if strings.Contains(s, "/") {
		_, nw, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		return nw, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP")
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}
