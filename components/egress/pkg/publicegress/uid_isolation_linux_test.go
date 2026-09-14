package publicegress

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestKernelNonRootUIDIsolation exercises the compatibility boundary without
// touching host cgroups. It must run only inside a disposable network
// namespace because the nft table intentionally survives process exit.
func TestKernelNonRootUIDIsolation(t *testing.T) {
	if os.Getenv("OSB_DISPOSABLE_NETNS") != "1" {
		t.Skip("requires a disposable Linux network namespace")
	}
	if err := os.WriteFile(
		"/proc/sys/net/ipv4/ip_unprivileged_port_start", []byte("1024"), 0600,
	); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{
		"192.0.2.10/32",
		"192.0.2.20/32",
		"192.0.2.53/32",
	} {
		if out, err := exec.Command("ip", "addr", "add", address, "dev", "lo").CombinedOutput(); err != nil {
			t.Fatalf("add fixture address %s: %v: %s", address, err, out)
		}
	}

	start := func(address, response string) net.Listener {
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				go func() {
					defer connection.Close()
					_, _ = connection.Write([]byte(response))
				}()
			}
		}()
		return listener
	}
	start("192.0.2.10:8443", "gateway")
	start("127.0.0.1:381", "intercepted")

	cfg, err := Parse(
		`{"version":1,"dns_servers":["192.0.2.53"],"internal_targets":[]}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	guard, err := InstallNonRootUID(ctx, cfg, 8443, 10042)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.SetGatewayIPs(ctx, []string{"192.0.2.10"}, time.Minute); err != nil {
		t.Fatal(err)
	}

	trusted, err := net.DialTimeout("tcp4", "192.0.2.10:8443", time.Second)
	if err != nil {
		t.Fatalf("trusted root could not reach gateway: %v", err)
	}
	answer, err := io.ReadAll(trusted)
	_ = trusted.Close()
	if err != nil || string(answer) != "gateway" {
		t.Fatalf("trusted gateway response=%q err=%v", answer, err)
	}

	helper := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNonRootUIDAppHelper$")
	helper.Env = append(os.Environ(), "OSB_NONROOT_UID_HELPER=1")
	if output, err := helper.CombinedOutput(); err != nil {
		t.Fatalf("non-root compatibility boundary: %v: %s", err, output)
	}
}

func TestNonRootUIDAppHelper(t *testing.T) {
	if os.Getenv("OSB_NONROOT_UID_HELPER") != "1" {
		return
	}
	const uid = 65532
	if err := syscall.Setgroups(nil); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setgid(uid); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setuid(uid); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setuid(10042); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("application changed to trusted UID: %v", err)
	}
	if connection, err := net.DialTimeout(
		"tcp4", "192.0.2.10:8443", 250*time.Millisecond,
	); err == nil {
		_ = connection.Close()
		t.Fatal("non-root application reached the gateway directly")
	}
	connection, err := net.DialTimeout(
		"tcp4", "192.0.2.20:443", time.Second,
	)
	if err != nil {
		t.Fatalf("application traffic was not intercepted: %v", err)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, len("intercepted"))
	if _, err := io.ReadFull(connection, buffer); err != nil {
		t.Fatal(err)
	}
	if got := string(buffer); got != "intercepted" {
		t.Fatalf("intercept response=%q", strconv.Quote(got))
	}
	if strings.Contains(string(buffer), "gateway") {
		t.Fatal("application bypassed interception")
	}
}
