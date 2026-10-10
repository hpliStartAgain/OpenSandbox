//go:build linux

// Copyright 2026 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mitmproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Test binaries dispatch the same private mode as the production entrypoint.
func init() {
	if handled, err := HandleOwnedListenHelper(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

// This is a real separate process. It does not accept TCP until asked to check
// that readiness produced no connection or packet probe.
func TestGuardedListenHelper(t *testing.T) {
	if os.Getenv("OPENSANDBOX_GUARDED_LISTEN_HELPER") != "1" {
		return
	}
	var listener *net.TCPListener
	port := 0
	if network := os.Getenv("OPENSANDBOX_GUARDED_LISTEN_NETWORK"); network != "" {
		address, err := net.ResolveTCPAddr(network, os.Getenv("OPENSANDBOX_GUARDED_LISTEN_ADDRESS"))
		if err != nil {
			t.Fatal(err)
		}
		listener, err = net.ListenTCP(network, address)
		if err != nil {
			fmt.Println("unavailable:", err)
			return
		}
		defer listener.Close()
		port = listener.Addr().(*net.TCPAddr).Port
	}
	fmt.Println(port)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		switch scanner.Text() {
		case "exit":
			return
		case "check":
			if listener == nil {
				t.Fatal("no listener")
			}
			if err := listener.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			connection, err := listener.Accept()
			if err == nil {
				_ = connection.Close()
				fmt.Println("connection received")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				fmt.Println("quiet")
			} else {
				t.Fatal(err)
			}
		}
	}
}

type guardedTestChild struct {
	running *Running
	port    int
	input   io.WriteCloser
	output  *bufio.Scanner
	exited  chan struct{}
}

func startGuardedTestChild(t *testing.T, network, address string) *guardedTestChild {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestGuardedListenHelper$")
	command.Env = append(os.Environ(), "OPENSANDBOX_GUARDED_LISTEN_HELPER=1", "GORACE=atexit_sleep_ms=0",
		"OPENSANDBOX_GUARDED_LISTEN_NETWORK="+network, "OPENSANDBOX_GUARDED_LISTEN_ADDRESS="+address)
	input, err := command.StdinPipe()
	require.NoError(t, err)
	output, err := command.StdoutPipe()
	require.NoError(t, err)
	command.Stderr = os.Stderr
	require.NoError(t, command.Start())
	child := &guardedTestChild{running: &Running{Cmd: command, done: make(chan error, 1)}, input: input,
		output: bufio.NewScanner(output), exited: make(chan struct{})}
	go func() { child.running.done <- command.Wait(); close(child.exited) }()
	t.Cleanup(func() {
		_ = input.Close()
		select {
		case <-child.exited:
		case <-time.After(2 * time.Second):
			_ = command.Process.Kill()
			<-child.exited
		}
	})
	require.True(t, child.output.Scan(), "child did not announce startup: %v", child.output.Err())
	if strings.HasPrefix(child.output.Text(), "unavailable:") && network == "tcp6" {
		t.Skip(child.output.Text())
	}
	child.port, err = strconv.Atoi(child.output.Text())
	require.NoError(t, err, "child startup: %s", child.output.Text())
	return child
}

func TestWaitOwnedListenContextExactChild(t *testing.T) {
	for _, test := range []struct{ network, address string }{{"tcp4", "127.0.0.1:0"}, {"tcp6", "[::1]:0"}} {
		t.Run(test.network, func(t *testing.T) {
			child := startGuardedTestChild(t, test.network, test.address)
			require.NoError(t, WaitOwnedListenContext(context.Background(), child.running, child.port, time.Second))
			_, err := fmt.Fprintln(child.input, "check")
			require.NoError(t, err)
			require.True(t, child.output.Scan())
			require.Equal(t, "quiet", child.output.Text(), "readiness must not dial the listener")
		})
	}
}

func TestWaitOwnedListenContextRejectsOtherOwners(t *testing.T) {
	owner := startGuardedTestChild(t, "tcp4", "127.0.0.1:0")
	unrelated := startGuardedTestChild(t, "", "")
	t.Run("same namespace and port but different child", func(t *testing.T) {
		err := WaitOwnedListenContext(context.Background(), unrelated.running, owner.port, 100*time.Millisecond)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
	t.Run("listener belongs to parent", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()
		err = WaitOwnedListenContext(context.Background(), unrelated.running, listener.Addr().(*net.TCPAddr).Port, 100*time.Millisecond)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
	t.Run("correct child wrong port", func(t *testing.T) {
		err := WaitOwnedListenContext(context.Background(), owner.running, owner.port%65535+1, 100*time.Millisecond)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
	t.Run("wildcard is not loopback", func(t *testing.T) {
		child := startGuardedTestChild(t, "tcp4", "0.0.0.0:0")
		require.ErrorIs(t, WaitOwnedListenContext(context.Background(), child.running, child.port, 100*time.Millisecond), context.DeadlineExceeded)
	})
}

func TestWaitOwnedListenContextChildExit(t *testing.T) {
	child := startGuardedTestChild(t, "", "")
	result := make(chan error, 1)
	go func() { result <- WaitOwnedListenContext(context.Background(), child.running, 43123, 5*time.Second) }()
	_, err := fmt.Fprintln(child.input, "exit")
	require.NoError(t, err)
	select {
	case err := <-result:
		require.Error(t, err)
		require.NotErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("readiness did not notice child exit")
	}
	<-child.exited
	require.Len(t, child.running.done, 1, "readiness must leave the supervisor's exit notification intact")
	require.ErrorIs(t, WaitOwnedListenContext(context.Background(), child.running, 43123, time.Second), os.ErrProcessDone)
}

func TestWaitOwnedListenContextDoesNotTrustReusedPID(t *testing.T) {
	dead := startGuardedTestChild(t, "", "")
	_, err := fmt.Fprintln(dead.input, "exit")
	require.NoError(t, err)
	<-dead.exited
	live := startGuardedTestChild(t, "tcp4", "127.0.0.1:0")
	// Model a stale handle whose numeric PID now names a live listener. The
	// exec-created Process identity, not the numeric PID alone, must reject it.
	dead.running.Cmd.Process.Pid = live.running.Cmd.Process.Pid
	require.ErrorIs(t, WaitOwnedListenContext(context.Background(), dead.running, live.port, time.Second), os.ErrProcessDone)
}

func TestWaitOwnedListenContextDeadlineAndCancellation(t *testing.T) {
	child := startGuardedTestChild(t, "", "")
	t.Run("expired deadline", func(t *testing.T) {
		require.ErrorIs(t, WaitOwnedListenContext(context.Background(), child.running, 43123, 0), context.DeadlineExceeded)
	})
	t.Run("already canceled with a live listener", func(t *testing.T) {
		listener := startGuardedTestChild(t, "tcp4", "127.0.0.1:0")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		require.ErrorIs(t, WaitOwnedListenContext(ctx, listener.running, listener.port, time.Second), context.Canceled)
	})
	t.Run("canceled while waiting", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		time.AfterFunc(30*time.Millisecond, cancel)
		started := time.Now()
		require.ErrorIs(t, WaitOwnedListenContext(ctx, child.running, 43123, 5*time.Second), context.Canceled)
		require.Less(t, time.Since(started), time.Second)
	})
}

func TestWaitOwnedListenContextInvalidInput(t *testing.T) {
	for _, running := range []*Running{nil, {}, {Cmd: &exec.Cmd{}}, {Cmd: exec.Command("unused")}} {
		require.Error(t, WaitOwnedListenContext(context.Background(), running, 43123, time.Second))
	}
	child := startGuardedTestChild(t, "", "")
	for _, port := range []int{-1, 0, 65536} {
		require.Error(t, WaitOwnedListenContext(context.Background(), child.running, port, time.Second))
	}
}

func guardedTestStat(pid, parent int, state string, start uint64) string {
	fields := strings.Fields(state + " " + strconv.Itoa(parent) + strings.Repeat(" 0", 18))
	fields[19] = strconv.FormatUint(start, 10)
	return fmt.Sprintf("%d (child ) with (spaces)) %s\n", pid, strings.Join(fields, " "))
}

func TestGuardedProcessIdentity(t *testing.T) {
	good := guardedTestStat(2345, 1234, "S", 6789)
	identity, err := guardedParseProcessStat(good)
	require.NoError(t, err)
	require.Equal(t, guardedProcessIdentity{pid: 2345, parent: 1234, start: 6789}, identity)
	for _, malformed := range []string{
		"", "1 child S 2", "1 (child) S 2", strings.Replace(good, "2345", "x", 1),
		guardedTestStat(0, 1234, "S", 6789), guardedTestStat(2345, 0, "S", 6789),
		guardedTestStat(2345, 1234, "S", 0), guardedTestStat(2345, 1234, "?", 6789),
		guardedTestStat(2345, 1234, "SS", 6789), strings.Replace(good, "6789", "oops", 1),
	} {
		_, err := guardedParseProcessStat(malformed)
		require.Error(t, err, "%q", malformed)
	}
	for _, state := range []string{"Z", "X", "x"} {
		_, err := guardedParseProcessStat(guardedTestStat(2345, 1234, state, 6789))
		require.ErrorContains(t, err, "exited")
	}
}

func TestGuardedProcessIdentityChangesFailClosed(t *testing.T) {
	child := startGuardedTestChild(t, "", "")
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer root.Close()
	expected := guardedProcessIdentity{pid: child.running.Cmd.Process.Pid, parent: os.Getpid(), start: 6789}
	for _, actual := range []guardedProcessIdentity{
		{pid: expected.pid, parent: expected.parent, start: expected.start + 1},
		{pid: expected.pid + 1, parent: expected.parent, start: expected.start},
		{pid: expected.pid, parent: expected.parent + 1, start: expected.start},
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "stat"), []byte(guardedTestStat(actual.pid, actual.parent, "S", actual.start)), 0600))
		require.ErrorContains(t, guardedListenVerifyProcess(child.running.Cmd.Process, root, expected), "identity changed")
	}
	require.NoError(t, os.Remove(filepath.Join(dir, "stat")))
	require.Error(t, guardedListenVerifyProcess(child.running.Cmd.Process, root, expected))
}

const guardedTCPHeader = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

func guardedTestAddress(words ...uint32) string {
	address := make([]byte, len(words)*4)
	for i, word := range words {
		binary.NativeEndian.PutUint32(address[i*4:], word)
	}
	return strings.ToUpper(hex.EncodeToString(address))
}

func guardedTestTCPRecord(address, state, inode string) string {
	remote := strings.Repeat("0", len(strings.Split(address, ":")[0])) + ":0000"
	return fmt.Sprintf("0: %s %s %s 00000000:00000000 00:00000000 00000000 1000 0 %s 1 0000000000000000\n", address, remote, state, inode)
}

func TestGuardedParseTCPListeners(t *testing.T) {
	for _, test := range []struct {
		name string
		ipv6 bool
		addr string
		want bool
	}{
		{"v4 loopback", false, guardedTestAddress(0x7f000001), true},
		{"v4 wildcard", false, guardedTestAddress(0), false},
		{"v4 different loopback", false, guardedTestAddress(0x7f000002), false},
		{"v6 loopback", true, guardedTestAddress(0, 0, 0, 1), true},
		{"v6 wildcard", true, guardedTestAddress(0, 0, 0, 0), false},
		{"v6 mapped v4 loopback", true, guardedTestAddress(0, 0, 0xffff, 0x7f000001), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			row := guardedTestTCPRecord(test.addr+":1F90", "0A", "123456")
			inodes, err := guardedParseTCPListeners(strings.NewReader(guardedTCPHeader+row), test.ipv6, 8080)
			require.NoError(t, err)
			_, found := inodes[123456]
			require.Equal(t, test.want, found)
			inodes, err = guardedParseTCPListeners(strings.NewReader(guardedTCPHeader+row), test.ipv6, 8081)
			require.NoError(t, err)
			require.Empty(t, inodes)
		})
	}
	for _, state := range []string{"01", "06", "07"} {
		row := guardedTestTCPRecord(guardedTestAddress(0x7f000001)+":1F90", state, "123456")
		inodes, err := guardedParseTCPListeners(strings.NewReader(guardedTCPHeader+row), false, 8080)
		require.NoError(t, err)
		require.Empty(t, inodes)
	}
	inodes, err := guardedParseTCPListeners(strings.NewReader(guardedTCPHeader), false, 8080)
	require.NoError(t, err)
	require.Empty(t, inodes)
}

func TestGuardedParseTCPListenersMalformed(t *testing.T) {
	good := guardedTestTCPRecord(guardedTestAddress(0x7f000001)+":1F90", "0A", "123456")
	for _, malformed := range []string{
		"", "bad header\n" + good, guardedTCPHeader + "truncated\n", guardedTCPHeader + "\n",
		guardedTCPHeader + strings.Replace(good, ":1F90", ":oops", 1),
		guardedTCPHeader + strings.Replace(good, ":1F90", ":1F9", 1),
		guardedTCPHeader + strings.Replace(good, ":1F90", ":1F900", 1),
		guardedTCPHeader + strings.Replace(good, "00000000:0000", "invalid:0000", 1),
		guardedTCPHeader + strings.Replace(good, "0A", "ZZ", 1),
		guardedTCPHeader + strings.Replace(good, "0A", "A", 1),
		guardedTCPHeader + strings.Replace(good, "123456", "oops", 1),
		guardedTCPHeader + strings.Replace(good, "123456", "18446744073709551616", 1),
		guardedTCPHeader + good + "malformed trailing row\n", guardedTCPHeader + strings.Repeat("a", 65537),
	} {
		_, err := guardedParseTCPListeners(strings.NewReader(malformed), false, 8080)
		require.Error(t, err)
	}
}

func TestGuardedListenSocketFDsMalformed(t *testing.T) {
	for _, target := range []string{"socket:bad", "socket:[]", "socket:[0]", "socket:[123", "socket:[bad]"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(dir, "fd"), 0700))
			require.NoError(t, os.Symlink(target, filepath.Join(dir, "fd", "3")))
			root, err := os.OpenRoot(dir)
			require.NoError(t, err)
			defer root.Close()
			_, err = guardedListenSocketFDs(root)
			require.Error(t, err)
		})
	}
}

func TestGuardedOwnedListenHelper(t *testing.T) {
	child := startGuardedTestChild(t, "tcp4", "127.0.0.1:0")
	proc, err := os.OpenRoot(fmt.Sprintf("/proc/%d", child.running.Cmd.Process.Pid))
	require.NoError(t, err)
	defer proc.Close()
	identity, err := guardedListenIdentity(proc)
	require.NoError(t, err)
	credential := &syscall.Credential{Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid()), NoSetGroups: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ready, err := guardedRunOwnedListenHelper(ctx, credential, identity, child.port)
	require.NoError(t, err)
	require.True(t, ready)
	ready, err = guardedRunOwnedListenHelper(ctx, credential, identity, child.port%65535+1)
	require.NoError(t, err)
	require.False(t, ready)
	identity.start++
	_, err = guardedRunOwnedListenHelper(ctx, credential, identity, child.port)
	require.Error(t, err)
}

func TestGuardedOwnedListenHelperArguments(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"--unrelated"}} {
		handled, err := HandleOwnedListenHelper(args)
		require.False(t, handled)
		require.NoError(t, err)
	}
	for _, args := range [][]string{
		{guardedListenHelperArg}, {guardedListenHelperArg, "1", "8080", "1", "extra"},
		{guardedListenHelperArg, "0", "8080", "1"}, {guardedListenHelperArg, "bad", "8080", "1"},
		{guardedListenHelperArg, "1", "65536", "1"}, {guardedListenHelperArg, "1", "0", "1"},
		{guardedListenHelperArg, "1", "8080", "bad"}, {guardedListenHelperArg, "1", "8080", "0"},
	} {
		handled, err := HandleOwnedListenHelper(args)
		require.True(t, handled)
		require.Error(t, err)
	}
}
