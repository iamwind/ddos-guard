// Package switchctl 通过 SSH 在交换机上执行命令模板（填入目标 IP+端口+规则编号），
// 用于 DDoS 命中后的处置（如华为 VRP 高级 ACL 拒绝攻击流量）。
package switchctl

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"ddosguard/internal/config"
	"ddosguard/internal/detect"
)

// RenderParams 命令模板参数
type RenderParams struct {
	IP     string
	Port   uint16
	Proto  string // 协议名（tcp/udp/icmp/...），来自窗口内主导协议
	RuleID int    // ACL rule 编号（从 rule_id_start 开始逐条递增）
}

// RenderCommands 渲染命令模板：替换 {ip} / {port} / {proto} / {rule_id} 占位符
func RenderCommands(tmpl []string, p RenderParams) []string {
	replacer := strings.NewReplacer(
		"{ip}", p.IP,
		"{port}", strconv.FormatUint(uint64(p.Port), 10),
		"{proto}", p.Proto,
		"{rule_id}", strconv.Itoa(p.RuleID),
	)
	out := make([]string, 0, len(tmpl))
	for _, line := range tmpl {
		out = append(out, replacer.Replace(line))
	}
	return out
}

// ProtoName 协议号 -> ACL 可用的协议名（默认 ip 表示任意协议）
func ProtoName(proto uint8) string {
	switch proto {
	case 1:
		return "icmp"
	case 2:
		return "igmp"
	case 4:
		return "ipinip"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 51:
		return "ah"
	case 58:
		return "icmpv6"
	case 89:
		return "ospf"
	case 132:
		return "sctp"
	default:
		return "ip"
	}
}

// Executor 单个交换机的 SSH 执行器（SSH 串行执行）。
//
// rule 编号策略：每次下发都无条件使用 RuleIDStart（默认 800），
// 后一次命中覆盖上一次的 rule —— 设备上始终只保留最近一次封堵目标。
type Executor struct {
	cfg    config.SwitchConfig
	logger *zap.Logger

	sshMu sync.Mutex // 串行化 SSH 会话

	// batchMu 串行化「批次判断 + 执行 + 记录」：
	// 防止执行期间(数秒)检测器再次触发同一批次导致重复下发。
	batchMu sync.Mutex

	mu          sync.Mutex
	lastTargets map[string]struct{} // 上一批已下发规则的目标（ip:port）
}

// NewExecutor 创建交换机执行器
func NewExecutor(cfg config.SwitchConfig, logger *zap.Logger) *Executor {
	return &Executor{
		cfg:         cfg,
		logger:      logger,
		lastTargets: make(map[string]struct{}),
	}
}

// RuleID 每次下发使用的固定 rule 编号（默认 800）
func (e *Executor) RuleID() int {
	return e.cfg.RuleIDStart
}

// RunBatch 实现 detect.Action：本批次内每条规则编号从 RuleIDStart（默认 800）
// 开始连续分配（800、801、802...），逐条渲染并执行；下一次批次的编号再次
// 从起始编号开始，从而覆盖上一次下发的规则。
func (e *Executor) RunBatch(switchName string, hits []detect.Hit) error {
	if len(hits) == 0 {
		return nil
	}

	// 批次判断 + 执行 + 记录全程串行，避免执行期间(SSH 较慢)检测器重复
	// 触发同一批次造成重复下发。
	e.batchMu.Lock()
	defer e.batchMu.Unlock()

	// ssh_enabled=false：只记录将下发的命令（试运行/演练），不登录交换机，
	// 也不更新批次目标集合（开启后可立即正常下发）。
	if e.cfg.SSHEnabled != nil && !*e.cfg.SSHEnabled {
		for i, hit := range hits {
			protoName := ProtoName(hit.Proto)
			params := RenderParams{
				IP:     hit.Key.IP,
				Port:   hit.Key.Port,
				Proto:  protoName,
				RuleID: e.cfg.RuleIDStart + i,
			}
			e.logger.Info("ssh disabled, skip switch action (dry run)",
				zap.String("switch", e.cfg.Name),
				zap.String("target_ip", hit.Key.IP),
				zap.Uint16("target_port", hit.Key.Port),
				zap.String("proto", protoName),
				zap.Int("rule_id", params.RuleID),
				zap.Strings("commands", RenderCommands(e.cfg.Commands, params)),
			)
		}
		return nil
	}

	// 批次级去重：本批目标（IP+端口）若全部属于上一批已下发规则的目标集合，
	// 说明这些目标已封堵，直接跳过 SSH（不重复下发）。
	batch := make(map[string]struct{}, len(hits))
	allKnown := true
	for _, hit := range hits {
		key := targetKey(hit.Key.IP, hit.Key.Port)
		batch[key] = struct{}{}
		if _, ok := e.lastTargets[key]; !ok {
			allKnown = false
		}
	}
	if allKnown {
		e.logger.Info("batch targets already covered by previous rules, skip ssh",
			zap.String("switch", e.cfg.Name),
			zap.Int("targets", len(hits)),
		)
		return nil
	}

	for i, hit := range hits {
		ruleID := e.cfg.RuleIDStart + i
		params := RenderParams{
			IP:     hit.Key.IP,
			Port:   hit.Key.Port,
			Proto:  ProtoName(hit.Proto),
			RuleID: ruleID,
		}
		cmds := RenderCommands(e.cfg.Commands, params)

		out, err := e.execute(cmds)
		if err != nil {
			return fmt.Errorf("rule %d (%s:%d): %w", ruleID, hit.Key.IP, hit.Key.Port, err)
		}
		e.logger.Info("switch command executed",
			zap.String("switch", e.cfg.Name),
			zap.String("target_ip", hit.Key.IP),
			zap.Uint16("target_port", hit.Key.Port),
			zap.String("proto", params.Proto),
			zap.Int("rule_id", ruleID),
			zap.Int("batch_index", i),
			zap.Int("batch_size", len(hits)),
			zap.Int("commands", len(cmds)),
			zap.String("output", truncate(out, 2048)),
		)
	}

	// 整批下发成功后记录本批目标集合（下一批据此判断子集跳过）
	e.mu.Lock()
	e.lastTargets = batch
	e.mu.Unlock()
	return nil
}

// targetKey 目标键：IP+端口（批次去重比较用）
func targetKey(ip string, port uint16) string {
	return ip + ":" + strconv.FormatUint(uint64(port), 10)
}

// execute 建立 SSH 会话并逐条执行命令（交互式 shell，兼容 system-view 等模式切换）
func (e *Executor) execute(cmds []string) (string, error) {
	e.sshMu.Lock()
	defer e.sshMu.Unlock()

	auth, err := e.authMethods()
	if err != nil {
		return "", err
	}
	addr := net.JoinHostPort(e.cfg.Host, strconv.Itoa(e.cfg.Port))
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            e.cfg.Username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         e.cfg.Timeout,
	})
	if err != nil {
		return "", fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()

	var buf syncBuffer
	sess.Stdout = &buf
	sess.Stderr = &buf
	if err := sess.RequestPty("vt100", 200, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return "", fmt.Errorf("request pty: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("stdin pipe: %w", err)
	}
	if err := sess.Shell(); err != nil {
		return "", fmt.Errorf("start shell: %w", err)
	}

	// 登录后命令 + 业务命令逐条写入（部分设备回显/处理较慢）
	for _, c := range e.cfg.LoginCommands {
		if _, err := fmt.Fprintf(stdin, "%s\n", c); err != nil {
			return buf.String(), err
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, c := range cmds {
		if _, err := fmt.Fprintf(stdin, "%s\n", c); err != nil {
			return buf.String(), err
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Fprintln(stdin, "quit")
	fmt.Fprintln(stdin, "exit")

	// 等待会话结束（exit 后远程 shell 退出；超时保护，返回已收集输出）
	done := make(chan struct{})
	go func() {
		sess.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(e.cfg.Timeout):
	}

	return buf.String(), nil
}

// authMethods 构建认证方式：私钥优先，其次密码
func (e *Executor) authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if e.cfg.PrivateKey != "" {
		data, err := ioutil.ReadFile(e.cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("read private key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if e.cfg.Password != "" {
		methods = append(methods, ssh.Password(e.cfg.Password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no auth method configured")
	}
	return methods, nil
}

// syncBuffer 并发安全的缓冲区（SSH 输出协程写入，主协程读取）
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
