package switchctl

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"ddosguard/internal/config"
	"ddosguard/internal/detect"
)

// TestRenderCommands 命令模板占位符替换
func TestRenderCommands(t *testing.T) {
	tmpl := []string{
		"sys",
		"acl name DDOS advance",
		"rule {rule_id} deny {proto} destination-port eq {port} destination {ip} 0.0.0.0",
		"commit",
		"display acl name DDOS | include {rule_id}",
	}
	got := RenderCommands(tmpl, RenderParams{IP: "203.0.113.9", Port: 443, Proto: "udp", RuleID: 800})
	want := []string{
		"sys",
		"acl name DDOS advance",
		"rule 800 deny udp destination-port eq 443 destination 203.0.113.9 0.0.0.0",
		"commit",
		"display acl name DDOS | include 800",
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cmd[%d]=%q, want %q", i, got[i], want[i])
		}
	}

	// 协议名映射
	if ProtoName(6) != "tcp" || ProtoName(17) != "udp" || ProtoName(1) != "icmp" || ProtoName(0) != "ip" {
		t.Errorf("proto names: %s %s %s", ProtoName(6), ProtoName(17), ProtoName(1))
	}
}

// mockSSHServer 测试用 SSH 服务器：记录收到的命令
type mockSSHServer struct {
	mu   sync.Mutex
	cmds []string
	ln   net.Listener
}

func startMockSSH(t *testing.T) *mockSSHServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	srv := &mockSSHServer{}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil // 接受任意密码
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.ln = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handle(conn, cfg)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return srv
}

func (s *mockSSHServer) handle(c net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range requests {
				switch req.Type {
				case "pty-req":
					req.Reply(true, nil)
				case "shell":
					req.Reply(true, nil)
					go func() {
						buf := make([]byte, 1024)
						var line []byte
						for {
							n, err := ch.Read(buf)
							if n > 0 {
								line = append(line, buf[:n]...)
								for {
									idx := strings.IndexByte(string(line), '\n')
									if idx < 0 {
										break
									}
									cmd := strings.TrimSpace(string(line[:idx]))
									if cmd != "" {
										s.mu.Lock()
										s.cmds = append(s.cmds, cmd)
										s.mu.Unlock()
									}
									line = line[idx+1:]
									if cmd == "exit" {
										ch.Close()
										return
									}
								}
							}
							if err != nil {
								return
							}
						}
					}()
				default:
					req.Reply(false, nil)
				}
			}
		}()
	}
}

func (s *mockSSHServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.cmds))
	copy(out, s.cmds)
	return out
}

// waitCmds 等待至少 n 条命令
func waitCmds(s *mockSSHServer, n int) []string {
	deadline := time.Now().Add(6 * time.Second)
	var cmds []string
	for time.Now().Before(deadline) {
		cmds = s.commands()
		if len(cmds) >= n {
			return cmds
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cmds
}

// TestExecutorRun 通过真实 SSH 协议执行命令并核对内容
func TestExecutorRun(t *testing.T) {
	srv := startMockSSH(t)
	addr := srv.ln.Addr().(*net.TCPAddr)
	cfg := config.SwitchConfig{
		Name: "mock", Host: "127.0.0.1", Port: addr.Port, Username: "admin", Password: "secret",
		Timeout: 5 * time.Second, RuleIDStart: 800,
		Commands: []string{"sys", "rule {rule_id} deny {proto} destination-port eq {port} destination {ip} 0.0.0.0", "quit"},
	}
	ex := NewExecutor(cfg, zap.NewNop())
	err := ex.RunBatch("mock", []detect.Hit{{Switch: "mock", Key: detect.Key{IP: "203.0.113.9", Port: 443}, Proto: 17}})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	cmds := waitCmds(srv, 3)
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "rule 800 deny udp destination-port eq 443 destination 203.0.113.9 0.0.0.0") {
		t.Errorf("rendered command not received: %q", joined)
	}
}

// TestExecutorAuthFailure 不可达交换机返回错误
func TestExecutorAuthFailure(t *testing.T) {
	cfg := config.SwitchConfig{
		Name: "bad", Host: "127.0.0.1", Port: 1, Username: "x", Password: "y",
		Timeout: 300 * time.Millisecond, RuleIDStart: 800, Commands: []string{"x"},
	}
	ex := NewExecutor(cfg, zap.NewNop())
	if err := ex.RunBatch("bad", []detect.Hit{{Key: detect.Key{IP: "1.1.1.1", Port: 1}, Proto: 6}}); err == nil {
		t.Fatal("expected dial error")
	}
}

// TestRunBatchRuleIDs 批次内多条规则编号从 800 连续分配（800、801）
func TestRunBatchRuleIDs(t *testing.T) {
	srv := startMockSSH(t)
	addr := srv.ln.Addr().(*net.TCPAddr)
	cfg := config.SwitchConfig{
		Name: "mock", Host: "127.0.0.1", Port: addr.Port, Username: "admin", Password: "secret",
		Timeout: 5 * time.Second, RuleIDStart: 800,
		Commands: []string{
			"sys",
			"acl name DDOS advance",
			"rule {rule_id} deny {proto} destination-port eq {port} destination {ip} 0.0.0.0",
			"commit",
			"quit",
			"display acl name DDOS | include {rule_id}",
			"quit",
		},
	}
	ex := NewExecutor(cfg, zap.NewNop())
	hits := []detect.Hit{
		{Switch: "mock", Key: detect.Key{IP: "203.0.113.9", Port: 443}, Proto: 6},
		{Switch: "mock", Key: detect.Key{IP: "203.0.113.10", Port: 6672}, Proto: 17},
	}
	if err := ex.RunBatch("mock", hits); err != nil {
		t.Fatalf("run batch: %v", err)
	}
	cmds := waitCmds(srv, 9)
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "rule 800 deny tcp destination-port eq 443 destination 203.0.113.9 0.0.0.0") {
		t.Errorf("rule 800 missing: %q", joined)
	}
	if !strings.Contains(joined, "rule 801 deny udp destination-port eq 6672 destination 203.0.113.10 0.0.0.0") {
		t.Errorf("rule 801 missing: %q", joined)
	}
	if !strings.Contains(joined, "display acl name DDOS | include 800") ||
		!strings.Contains(joined, "display acl name DDOS | include 801") {
		t.Errorf("display commands missing: %q", joined)
	}
}

// TestRunBatchRestartsAtStart 下一次批次编号再次从 800 开始（覆盖上一次）
func TestRunBatchRestartsAtStart(t *testing.T) {
	srv := startMockSSH(t)
	addr := srv.ln.Addr().(*net.TCPAddr)
	cfg := config.SwitchConfig{
		Name: "mock", Host: "127.0.0.1", Port: addr.Port, Username: "admin", Password: "secret",
		Timeout: 5 * time.Second, RuleIDStart: 800,
		Commands: []string{"rule {rule_id} deny {proto} destination-port eq {port} destination {ip} 0.0.0.0"},
	}
	ex := NewExecutor(cfg, zap.NewNop())

	// 第一批：两个目标 → 800、801
	batch1 := []detect.Hit{
		{Key: detect.Key{IP: "203.0.113.9", Port: 443}, Proto: 6},
		{Key: detect.Key{IP: "203.0.113.10", Port: 6672}, Proto: 17},
	}
	if err := ex.RunBatch("mock", batch1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	// 第二批：另一个目标 → 编号重新从 800 开始
	batch2 := []detect.Hit{{Key: detect.Key{IP: "198.51.100.20", Port: 80}, Proto: 6}}
	if err := ex.RunBatch("mock", batch2); err != nil {
		t.Fatal(err)
	}
	cmds := waitCmds(srv, 3)
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "rule 800 deny tcp destination-port eq 80 destination 198.51.100.20 0.0.0.0") {
		t.Errorf("second batch must restart at 800: %q", joined)
	}
}

// TestBatchSkipWhenSubset 新批次目标是上一批的子集/相同时，不执行 SSH
func TestBatchSkipWhenSubset(t *testing.T) {
	srv := startMockSSH(t)
	addr := srv.ln.Addr().(*net.TCPAddr)
	cfg := config.SwitchConfig{
		Name: "mock", Host: "127.0.0.1", Port: addr.Port, Username: "admin", Password: "secret",
		Timeout: 5 * time.Second, RuleIDStart: 800,
		Commands: []string{"rule {rule_id} deny {proto} destination-port eq {port} destination {ip} 0.0.0.0"},
	}
	ex := NewExecutor(cfg, zap.NewNop())

	// 第一批：A + B → 执行（800、801）
	batch1 := []detect.Hit{
		{Key: detect.Key{IP: "203.0.113.9", Port: 443}, Proto: 6},
		{Key: detect.Key{IP: "198.51.100.20", Port: 80}, Proto: 6},
	}
	if err := ex.RunBatch("mock", batch1); err != nil {
		t.Fatal(err)
	}
	cmds := waitCmds(srv, 2)
	if len(cmds) < 2 {
		t.Fatalf("first batch commands=%d", len(cmds))
	}

	// 第二批：{A}（子集）→ 跳过
	if err := ex.RunBatch("mock", []detect.Hit{{Key: detect.Key{IP: "203.0.113.9", Port: 443}, Proto: 6}}); err != nil {
		t.Fatal(err)
	}
	// 第三批：{A, B}（相同）→ 跳过
	if err := ex.RunBatch("mock", batch1); err != nil {
		t.Fatal(err)
	}
	// 等待，确认没有新命令
	time.Sleep(1 * time.Second)
	if got := len(srv.commands()); got != len(cmds) {
		t.Fatalf("subset/same batch must skip ssh: commands %d -> %d", len(cmds), got)
	}

	// 第四批：{A, C}（有新增目标 C）→ 执行整批（800、801 覆盖）
	batch4 := []detect.Hit{
		{Key: detect.Key{IP: "203.0.113.9", Port: 443}, Proto: 6},
		{Key: detect.Key{IP: "192.0.2.77", Port: 9999}, Proto: 17},
	}
	if err := ex.RunBatch("mock", batch4); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	joined := strings.Join(srv.commands(), "\n")
	if !strings.Contains(joined, "rule 801 deny udp destination-port eq 9999 destination 192.0.2.77 0.0.0.0") {
		t.Errorf("new target must trigger ssh: %q", joined)
	}
}

// TestSSHDisabled 交换机 ssh_enabled=false 时不执行 SSH，仅记录（试运行）
func TestSSHDisabled(t *testing.T) {
	srv := startMockSSH(t)
	addr := srv.ln.Addr().(*net.TCPAddr)
	disabled := false
	cfg := config.SwitchConfig{
		Name: "mock", Host: "127.0.0.1", Port: addr.Port, Username: "admin", Password: "secret",
		Timeout: 5 * time.Second, RuleIDStart: 800, SSHEnabled: &disabled,
		Commands: []string{"rule {rule_id} deny {proto} destination-port eq {port} destination {ip} 0.0.0.0"},
	}
	ex := NewExecutor(cfg, zap.NewNop())
	hits := []detect.Hit{
		{Key: detect.Key{IP: "203.0.113.9", Port: 443}, Proto: 6},
		{Key: detect.Key{IP: "198.51.100.20", Port: 80}, Proto: 6},
	}
	if err := ex.RunBatch("mock", hits); err != nil {
		t.Fatalf("dry run must not error: %v", err)
	}
	// 不应有任何 SSH 命令
	time.Sleep(500 * time.Millisecond)
	if got := len(srv.commands()); got != 0 {
		t.Fatalf("ssh disabled but %d commands received", got)
	}

	// 开启后同目标应正常执行（关闭期间未记录 lastTargets）
	enabled := true
	cfg.SSHEnabled = &enabled
	ex2 := NewExecutor(cfg, zap.NewNop())
	if err := ex2.RunBatch("mock", hits); err != nil {
		t.Fatal(err)
	}
	cmds := waitCmds(srv, 2)
	if len(cmds) < 2 {
		t.Fatalf("after enabling ssh, commands=%d", len(cmds))
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "rule 800 deny tcp destination-port eq 443 destination 203.0.113.9 0.0.0.0") {
		t.Errorf("command missing after enabling: %q", joined)
	}
}
