package publicegress

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// Reach the Pod's legacy control port from a second disposable netns. This
// exercises PREROUTING, unlike a loopback client which exercises only OUTPUT.
func probeRemoteControl(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "--net", os.Args[0], "-test.run=^TestRemoteControlHelper$")
	cmd.Env = append(os.Environ(), "OSB_REMOTE_CONTROL=1")
	ready, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	proceed, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	marker := make([]byte, 1)
	if _, err := io.ReadFull(ready, marker); err != nil || marker[0] != 1 {
		t.Fatalf("remote fixture start: %v %v", marker, err)
	}
	for _, args := range [][]string{
		{"link", "add", "osb-local", "type", "veth", "peer", "name", "osb-remote"},
		{"link", "set", "osb-remote", "netns", strconv.Itoa(cmd.Process.Pid)},
		{"addr", "add", "172.31.254.1/30", "dev", "osb-local"},
		{"link", "set", "osb-local", "up"},
	} {
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("veth fixture: %v %s", err, out)
		}
	}
	_, _ = proceed.Write([]byte{1})
	_ = proceed.Close()
	output, _ := io.ReadAll(ready)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("remote control: %v %s", err, output)
	}
}

func TestRemoteControlHelper(t *testing.T) {
	if os.Getenv("OSB_REMOTE_CONTROL") != "1" {
		return
	}
	if os.Getenv("OSB_DISPOSABLE_NETNS") != "1" {
		t.Fatal("not a disposable fixture")
	}
	_, _ = os.Stdout.Write([]byte{1})
	if _, err := io.ReadFull(os.Stdin, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", "172.31.254.2/30", "dev", "osb-remote"},
		{"link", "set", "osb-remote", "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("peer setup: %v %s", err, out)
		}
	}
	if conn, err := net.DialTimeout("tcp4", "172.31.254.1:380", 200*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("remote peer reached protected backend without frontend NAT")
	}
	conn, err := net.DialTimeout("tcp4", "172.31.254.1:18080", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	answer := make([]byte, len("trusted fixture\n"))
	if _, err := io.ReadFull(conn, answer); err != nil || string(answer) != "trusted fixture\n" {
		t.Fatal(fmt.Sprintf("wrong control listener: %q %v", answer, err))
	}
}
