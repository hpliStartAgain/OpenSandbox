package publicegress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestKernelCgroupIsolation(t *testing.T) {
	if os.Getenv("OSB_DISPOSABLE_NETNS") != "1" {
		t.Skip("requires disposable netns and writable cgroup v2")
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_unprivileged_port_start", []byte("1024"), 0600); err != nil {
		t.Fatal(err)
	}
	original, err := currentCgroup()
	if err != nil {
		t.Fatal(err)
	}
	fixture := fmt.Sprintf("/sys/fs/cgroup/osb-egress-test-%d", os.Getpid())
	egress := filepath.Join(fixture, "egress")
	app := filepath.Join(fixture, "app")
	for _, path := range []string{fixture, egress, app} {
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		if err := os.WriteFile("/sys/fs/cgroup"+original+"/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Errorf("restore test cgroup: %v", err)
			return
		}
		for _, path := range []string{app, egress, fixture} {
			if err := os.Remove(path); err != nil {
				t.Errorf("remove fixture cgroup %s: %v", path, err)
			}
		}
	}()
	if err := os.WriteFile(egress+"/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ip", "addr", "add", "192.0.2.10/32", "dev", "lo").CombinedOutput(); err != nil {
		t.Fatalf("local fixture address: %s: %v", out, err)
	}
	if out, err := exec.Command("ip", "addr", "add", "192.0.2.53/32", "dev", "lo").CombinedOutput(); err != nil {
		t.Fatalf("DNS fixture address: %s: %v", out, err)
	}
	services := map[string]net.Listener{}
	startTCP := func(addr string) {
		listener, err := net.Listen("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		services[addr] = listener
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				c, e := listener.Accept()
				if e != nil {
					return
				}
				go func() {
					defer c.Close()
					_, _ = c.Write([]byte("trusted fixture\n"))
					_, _ = io.Copy(c, c)
				}()
			}
		}()
	}
	for _, addr := range []string{"192.0.2.10:8443", "192.0.2.10:9443", "127.0.0.1:381", "0.0.0.0:380"} {
		startTCP(addr)
	}
	startDNS := func() net.PacketConn {
		dnsListener, err := net.ListenPacket("udp4", DNSListenAddr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = dnsListener.Close() })
		go func() {
			buffer := make([]byte, 64)
			for {
				n, peer, err := dnsListener.ReadFrom(buffer)
				if err != nil {
					return
				}
				_, _ = dnsListener.WriteTo(buffer[:n], peer)
			}
		}()
		return dnsListener
	}
	dnsListener := startDNS()
	cfg, _ := Parse(`{"version":1,"dns_servers":["192.0.2.53"],"internal_targets":[]}`)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	g, err := Install(ctx, cfg, 8443)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.SetGatewayIPs(ctx, []string{"192.0.2.10"}, time.Second); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp4", "192.0.2.10:8443", time.Second)
	if err != nil {
		t.Fatalf("trusted gateway dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, len("trusted fixture\n"))); err != nil {
		t.Fatal(err)
	}
	// Expiration must close admission, without cutting an established tunnel.
	time.Sleep(1200 * time.Millisecond)
	if _, err := conn.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 5)
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != "alive" {
		t.Fatalf("gateway tunnel did not survive DNS TTL: %q %v", buffer, err)
	}
	_ = conn.Close()
	if fresh, err := net.DialTimeout("tcp4", "192.0.2.10:8443", 200*time.Millisecond); err == nil {
		_ = fresh.Close()
		t.Fatal("new gateway connection admitted after DNS TTL")
	}
	if err := g.SetGatewayIPs(ctx, []string{"192.0.2.10"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"0", "10042"} {
		t.Run("app-uid-"+uid, func(t *testing.T) {
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKernelAppHelper$")
			cmd.Env = append(os.Environ(), "OSB_CGROUP_APP="+app, "OSB_APP_UID="+uid)
			if out, err := cmd.CombinedOutput(); err != nil {
				state, _ := exec.Command("iptables-save", "-c").CombinedOutput()
				t.Logf("iptables: %s", state)
				state, _ = exec.Command("nft", "list", "table", "inet", table).CombinedOutput()
				t.Logf("guard: %s", state)
				t.Fatalf("root boundary: %v: %s", err, out)
			}
		})
	}
	// Crash all three services. Root must not bind their backend ports, and
	// taking every old high frontend must not prevent recovery or receive data.
	_ = dnsListener.Close()
	_ = services["127.0.0.1:381"].Close()
	_ = services["0.0.0.0:380"].Close()
	t.Run("root-hijack-and-recovery", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKernelAppHelper$")
		cmd.Env = append(os.Environ(), "OSB_CGROUP_APP="+app, "OSB_APP_UID=0", "OSB_HIJACK_TEST=1")
		proceed, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		ready, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		marker := make([]byte, 1)
		if _, err := ready.Read(marker); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatal(err)
		}
		startTCP("127.0.0.1:381")
		startTCP("0.0.0.0:380")
		startDNS()
		dial, err := net.DialTimeout("tcp4", "127.0.0.1:18080", time.Second)
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatal(err)
		}
		_ = dial.SetDeadline(time.Now().Add(300 * time.Millisecond))
		answer := make([]byte, len("trusted fixture\n"))
		if _, err := io.ReadFull(dial, answer); err != nil || string(answer) != "trusted fixture\n" {
			t.Errorf("control frontend reached wrong listener: %q %v", answer, err)
		}
		_ = dial.Close()
		probeRemoteControl(t)
		_, _ = proceed.Write([]byte{1})
		_ = proceed.Close()
		remaining, _ := io.ReadAll(ready)
		if err := cmd.Wait(); err != nil {
			t.Errorf("hijack fixture: %v: marker=%v %s", err, marker, remaining)
		}
	})
}

func TestKernelAppHelper(t *testing.T) {
	app := os.Getenv("OSB_CGROUP_APP")
	if app == "" {
		return
	}
	if !strings.HasPrefix(app, "/sys/fs/cgroup/osb-egress-test-") {
		t.Fatal("invalid fixture cgroup")
	}
	if err := os.WriteFile(app+"/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(os.Getenv("OSB_APP_UID"))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setgroups(nil); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setgid(uid); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setuid(uid); err != nil {
		t.Fatal(err)
	}
	// The root fixture has the production network capabilities removed.
	if uid == 0 {
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		data := [2]unix.CapUserData{}
		if _, _, err := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0); err != 0 {
			t.Fatal(err)
		}
	}
	if os.Getenv("OSB_HIJACK_TEST") == "1" {
		for _, port := range []string{"353", "380", "381"} {
			for _, address := range []string{"127.0.0.1:", "0.0.0.0:"} {
				listener, err := net.Listen("tcp4", address+port)
				if err == nil {
					listener.Close()
					t.Fatalf("root bound protected backend %s%s", address, port)
				}
				if !errors.Is(err, syscall.EACCES) {
					t.Fatalf("expected EACCES, got %v", err)
				}
			}
		}
		udp, err := net.ListenPacket("udp4", DNSListenAddr)
		if err == nil {
			udp.Close()
			t.Fatal("root bound protected UDP DNS")
		}
		if !errors.Is(err, syscall.EACCES) {
			t.Fatal(err)
		}
		var intercepted atomic.Int32
		for _, port := range []string{"15353", "18080", "18081"} {
			listener, err := net.Listen("tcp4", "0.0.0.0:"+port)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				if conn, err := listener.Accept(); err == nil {
					intercepted.Add(1)
					conn.Close()
				}
			}()
		}
		udp, err = net.ListenPacket("udp4", "127.0.0.1:15353")
		if err != nil {
			t.Fatal(err)
		}
		defer udp.Close()
		go func() {
			if _, _, err := udp.ReadFrom(make([]byte, 64)); err == nil {
				intercepted.Add(1)
			}
		}()
		_, _ = os.Stdout.Write([]byte{1})
		if _, err := os.Stdin.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if intercepted.Load() != 0 {
				t.Error("fake frontend intercepted service traffic")
			}
		}()
	}
	for _, addr := range []string{"192.0.2.10:8443", "192.0.2.10:9443", "127.0.0.1:18081", "192.0.2.10:18081"} {
		c, err := net.DialTimeout("tcp4", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			t.Errorf("untrusted UID %d bypassed via %s", uid, addr)
		}
	}
	dns, err := net.Dial("udp4", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	_ = dns.SetDeadline(time.Now().Add(time.Second))
	_, _ = dns.Write([]byte("DNS fixture"))
	answer := make([]byte, 64)
	n, err := dns.Read(answer)
	_ = dns.Close()
	if err != nil || string(answer[:n]) != "DNS fixture" {
		t.Fatalf("DNS interception: %q %v", answer[:n], err)
	}
	udp, err := net.Dial("udp4", "192.0.2.10:8888")
	if err != nil {
		t.Fatal(err)
	}
	_ = udp.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_, _ = udp.Write([]byte("blocked"))
	if _, err := udp.Read(answer); err == nil {
		t.Error("UDP bypass")
	}
	_ = udp.Close()
	// This fake MITM only proves kernel interception; TLS/FQDN/Grant validation
	// belongs to the separate real-mitmdump integration suite.
	c, err := net.DialTimeout("tcp4", "192.0.2.10:443", time.Second)
	if err != nil {
		t.Fatalf("intercept: %v", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 64)
	n, err = c.Read(buffer)
	if err != nil || string(buffer[:n]) != "trusted fixture\n" {
		t.Fatalf("wrong intercepted listener: %q %v", buffer[:n], err)
	}
}
