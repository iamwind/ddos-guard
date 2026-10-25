package config

import (
	"testing"
)

// TestSSHEnabledDefault 未配置 ssh_enabled 时默认开启；显式 false 时关闭
func TestSSHEnabledDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Switches = []SwitchConfig{
		{
			Name: "sw1", Host: "10.0.0.1", Username: "u", Password: "p",
			Targets:  []string{"203.0.113.0/24"},
			Commands: []string{"x"},
		},
		{
			Name: "sw2", Host: "10.0.0.2", Username: "u", Password: "p",
			Targets:    []string{"198.51.100.0/24"},
			Commands:   []string{"x"},
			SSHEnabled: func() *bool { f := false; return &f }(),
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Switches[0].SSHEnabled == nil || !*cfg.Switches[0].SSHEnabled {
		t.Errorf("default ssh_enabled must be true")
	}
	if cfg.Switches[1].SSHEnabled == nil || *cfg.Switches[1].SSHEnabled {
		t.Errorf("explicit ssh_enabled=false must be preserved")
	}
	// 编号默认 800
	if cfg.Switches[0].RuleIDStart != 800 {
		t.Errorf("rule_id_start=%d", cfg.Switches[0].RuleIDStart)
	}
}

// TestHTTPListenConfig HTTP 监听端口可配置（默认 :8080，显式配置生效）
func TestHTTPListenConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.HTTP.Listen != ":8080" {
		t.Fatalf("default http listen = %q, want :8080", cfg.HTTP.Listen)
	}
	// 显式配置不同端口
	cfg2 := DefaultConfig()
	cfg2.HTTP.Listen = "127.0.0.1:9091"
	if err := cfg2.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg2.HTTP.Listen != "127.0.0.1:9091" {
		t.Fatalf("http listen = %q, want 127.0.0.1:9091", cfg2.HTTP.Listen)
	}
}
