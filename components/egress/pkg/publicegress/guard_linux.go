// Copyright 2026 Alibaba Group Holding Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package publicegress

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const table = "opensandbox_public_egress"

type runner func(context.Context, string) error

func runNFT(ctx context.Context, rules string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("public egress nft: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// Guard is independent of the mutable user-policy table. It is deliberately
// NEVER removed on shutdown: a dead/restarting sidecar must not release root.
type Guard struct {
	mu          sync.Mutex
	cfg         *Config
	cgroup      string
	gatewayPort uint16
	run         runner
}

// Install first installs a quarantine, then proves that the live socket's
// kernel cgroup matches our leaf. No UID or kernel-version-based fallback.
func Install(ctx context.Context, cfg *Config, gatewayPort uint16) (*Guard, error) {
	if cfg == nil || gatewayPort == 0 || IsReservedPort(gatewayPort) {
		return nil, fmt.Errorf("public egress requires a policy and gateway port")
	}
	// add (not create) is idempotent; the transaction never exposes an empty table.
	quarantine := `add table inet ` + table + `
delete table inet ` + table + `
add table inet ` + table + `
add chain inet ` + table + ` output { type filter hook output priority -50; policy drop; }
add rule inet ` + table + ` output meta nfproto ipv6 drop
add rule inet ` + table + ` output meta l4proto { tcp, udp } th sport { 353, 380, 381, 15353, 18080, 18081 } drop
add rule inet ` + table + ` output meta l4proto { tcp, udp } th dport { 353, 380, 381, 15353, 18080, 18081 } drop
add rule inet ` + table + ` output ip saddr 127.0.0.0/8 oifname "lo" accept
add rule inet ` + table + ` output meta l4proto tcp ct state established ct direction reply accept
`
	// Keep a previous generation's complete guard during reinitialization. A
	// failed probe/configuration must not relax even local listener protection.
	if exec.CommandContext(ctx, "nft", "list", "table", "inet", table).Run() != nil {
		if err := runNFT(ctx, quarantine); err != nil {
			return nil, err
		}
	}
	portStart, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	if err != nil || strings.TrimSpace(string(portStart)) != "1024" {
		return nil, fmt.Errorf("public egress requires net.ipv4.ip_unprivileged_port_start=1024 and no application NET_BIND_SERVICE capability")
	}
	path, err := currentCgroup()
	if err != nil {
		return nil, err
	}
	if err := installClassifier(ctx, path); err != nil {
		return nil, err
	}
	if err := probeCgroup(ctx); err != nil {
		return nil, err
	}
	g := &Guard{cfg: cfg, cgroup: path, gatewayPort: gatewayPort, run: runNFT}
	if err := g.run(ctx, g.rules()); err != nil {
		return nil, err
	}
	return g, nil
}

func currentCgroup() (string, error) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	var path string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "0::/") {
			path = strings.TrimPrefix(line, "0::")
		}
	}
	if path == "" || filepath.Clean(path) != path || strings.ContainsAny(path, "\"\\\r\n\x00") {
		return "", fmt.Errorf("public egress requires a dedicated cgroup v2 container")
	}
	root := "/sys/fs/cgroup"
	var fs syscall.Statfs_t
	if err := syscall.Statfs(root, &fs); err != nil || fs.Type != 0x63677270 {
		return "", fmt.Errorf("public egress requires the cgroup2 mount at /sys/fs/cgroup")
	}
	info, err := os.Stat(root + path)
	if err != nil {
		return "", fmt.Errorf("cannot identify container cgroup: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Ino <= 1 {
		return "", fmt.Errorf("public egress refuses the host root cgroup")
	}
	return path, nil
}

const classifier = "OSB_PUBLIC_CGROUP"
const trustedMark = "0x40000000"

// xt_cgroup --path holds a kernel cgroup reference and matches socket ancestry,
// independently of UID. Clear the reserved bit on EVERY packet before setting
// it, so neither SO_MARK nor another policy's mark can impersonate the sidecar.
func installClassifier(ctx context.Context, path string) error {
	rules := fmt.Sprintf("*mangle\n:%s - [0:0]\n-F %s\n-A %s -j MARK --set-xmark 0x0/%s\n-A %s -m cgroup --path %s -j MARK --set-xmark %s/%s\nCOMMIT\n", classifier, classifier, classifier, trustedMark, classifier, strconv.Quote(path), trustedMark, trustedMark)
	cmd := exec.CommandContext(ctx, "iptables-restore", "--wait", "5", "--noflush")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cgroup v2 classifier unsupported: %w: %s", err, bytes.TrimSpace(out))
	}
	if exec.CommandContext(ctx, "iptables", "--wait", "5", "-t", "mangle", "-C", "OUTPUT", "-j", classifier).Run() != nil {
		if out, err := exec.CommandContext(ctx, "iptables", "--wait", "5", "-t", "mangle", "-I", "OUTPUT", "1", "-j", classifier).CombinedOutput(); err != nil {
			return fmt.Errorf("cgroup classifier hook: %w: %s", err, bytes.TrimSpace(out))
		}
	}
	return nil
}

// Probe an actual socket. Successfully parsing --path alone does not prove
// that the runtime's mounted cgroup view identifies this container correctly.
func probeCgroup(ctx context.Context) error {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	conn, err := net.Dial("udp4", listener.LocalAddr().String())
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.Write([]byte{1}); err != nil {
		return err
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err = listener.ReadFrom(make([]byte, 8)); err != nil {
		return fmt.Errorf("cgroup socket probe packet not delivered: %w", err)
	}
	out, err := exec.CommandContext(ctx, "iptables-save", "-c", "-t", "mangle").Output()
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "-A "+classifier+" -m cgroup --path ") {
			continue
		}
		var packets, bytes uint64
		if _, err := fmt.Sscanf(line, "[%d:%d]", &packets, &bytes); err == nil && packets > 0 {
			return nil
		}
	}
	return fmt.Errorf("kernel cannot identify this container's cgroup sockets; refusing UID fallback")
}

func (g *Guard) rules() string {
	var b strings.Builder
	cg := "meta mark & " + trustedMark + " != 0"
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\nadd table inet %s\n", table, table, table)
	fmt.Fprintf(&b, "add set inet %s gateway4 { type ipv4_addr; flags timeout; }\n", table)
	fmt.Fprintf(&b, "add chain inet %s intercept { type nat hook output priority -110; }\n", table)
	redirect := func(rule string) { fmt.Fprintf(&b, "add rule inet %s intercept %s\n", table, rule) }
	// These frontends must redirect even trusted callers. An app may bind an
	// unused high frontend, but no control/DNS request can reach that socket.
	redirect("ip daddr 127.0.0.0/8 tcp dport 18080 redirect to :380")
	redirect("ip daddr 127.0.0.0/8 meta l4proto { tcp, udp } th dport 15353 redirect to :353")
	redirect(cg + " return")
	redirect("meta l4proto { tcp, udp } th dport 53 redirect to :353")
	// Ordinary loopback services stay local; the filter protects egress listeners.
	redirect("ip daddr 127.0.0.0/8 return")
	var ports []string
	for _, p := range g.cfg.InterceptPorts() {
		ports = append(ports, strconv.Itoa(int(p)))
	}
	redirect("tcp dport { " + strings.Join(ports, ", ") + " } redirect to :381")
	fmt.Fprintf(&b, "add chain inet %s control_frontend { type nat hook prerouting priority -110; }\n", table)
	fmt.Fprintf(&b, "add rule inet %s control_frontend tcp dport 18080 redirect to :380\n", table)
	fmt.Fprintf(&b, "add chain inet %s input { type filter hook input priority -50; }\n", table)
	fmt.Fprintf(&b, "add rule inet %s input iifname != \"lo\" tcp dport 380 ct status dnat accept\n", table)
	fmt.Fprintf(&b, "add rule inet %s input iifname != \"lo\" meta l4proto { tcp, udp } th dport { 353, 380, 381, 15353, 18081 } drop\n", table)
	fmt.Fprintf(&b, "add rule inet %s input tcp dport 18080 drop\n", table)
	fmt.Fprintf(&b, "add chain inet %s output { type filter hook output priority -50; policy drop; }\n", table)
	add := func(rule string) { fmt.Fprintf(&b, "add rule inet %s output %s\n", table, rule) }
	add("meta nfproto ipv6 drop")
	// Only trusted processes may emit DNS replies, even if root binds a freed port.
	add(cg + " ip daddr 127.0.0.0/8 accept")
	add(cg + " udp sport 353 oifname \"lo\" ct direction reply accept")
	add(cg + " meta l4proto tcp ct state established ct direction reply accept")
	// The kernel's SYN-ACK request socket is not a full socket, so xt_cgroup
	// cannot classify it. Permit the handshake, but require the cgroup mark on
	// subsequent data from every protected listener (including a root impostor).
	add("tcp flags & (syn | ack) == (syn | ack) ct state established ct direction reply accept")
	add("meta l4proto { tcp, udp } th sport { 353, 380, 381, 15353, 18080, 18081 } drop")
	add("tcp dport 381 ct status dnat accept")
	add("meta l4proto { tcp, udp } th dport 353 ip daddr 127.0.0.1 accept")
	add("tcp dport { 380, 381, 18080, 18081 } drop")
	add("ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 oifname \"lo\" accept")
	add("meta l4proto tcp ct state established ct direction reply accept")
	// DNS TTL bounds admission of NEW gateway connections, not the lifetime of
	// an already authenticated CONNECT tunnel (SSE/WSS may last hours). Only
	// trusted sockets can set/use this reserved conntrack bit. The gateway owns
	// identity/Grant revocation; application sockets cannot inherit this bypass.
	add(fmt.Sprintf("%s ct state established ct direction original ct mark & %s != 0 tcp dport %d accept", cg, trustedMark, g.gatewayPort))
	add(fmt.Sprintf("%s ip daddr @gateway4 tcp dport %d ct mark set ct mark | %s accept", cg, g.gatewayPort, trustedMark))
	for _, ip := range g.cfg.DNSServers {
		add(cg + " ip daddr " + ip + " tcp dport 53 accept")
	}
	for _, t := range g.cfg.InternalTargets {
		for _, ip := range t.IPs {
			for _, port := range t.Ports {
				add(fmt.Sprintf("%s ip daddr %s tcp dport %d accept", cg, ip, port))
			}
		}
	}
	return b.String()
}

// SetGatewayIPs replaces the trusted resolver snapshot atomically. A failed
// update never broadens access; no application DNS answer feeds this set.
func (g *Guard) SetGatewayIPs(ctx context.Context, ips []string, ttl time.Duration) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ttl < time.Second {
		ttl = time.Second
	}
	if ttl > time.Hour {
		ttl = time.Hour
	}
	var entries []string
	seen := map[string]bool{}
	for _, ip := range ips {
		if !validIP(ip) {
			return fmt.Errorf("gateway DNS returned an unsafe IPv4 address")
		}
		if !seen[ip] {
			entries = append(entries, fmt.Sprintf("%s timeout %ds", ip, int64(ttl/time.Second)))
			seen[ip] = true
		}
	}
	rules := "flush set inet " + table + " gateway4\n"
	if len(entries) > 0 {
		rules += "add element inet " + table + " gateway4 { " + strings.Join(entries, ", ") + " }\n"
	}
	return g.run(ctx, rules)
}
