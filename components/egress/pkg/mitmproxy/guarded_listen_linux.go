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
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// WaitOwnedListenContext checks the exact child's loopback TCP listener without
// sending packets. This can run while a full network quarantine blocks even
// loopback traffic. Listener readiness is not application or revision readiness.
// Unreadable or malformed proc state fails closed; no network fallback is used.
func WaitOwnedListenContext(ctx context.Context, running *Running, port int, timeout time.Duration) error {
	if running == nil || running.Cmd == nil || running.Cmd.Process == nil || running.Cmd.Process.Pid <= 0 {
		return errors.New("mitmproxy: owned listener requires a started child")
	}
	if port <= 0 || port > 65535 {
		return errors.New("mitmproxy: invalid owned listener port")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("mitmproxy: waiting for owned listener: %w", err)
	}

	process := running.Cmd.Process
	// Signal zero uses the exec-created Process handle, rather than finding a
	// new process by PID. It neither delivers a signal nor consumes Running.done.
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return fmt.Errorf("mitmproxy: listener child is not live: %w", err)
	}
	// Keep the process directory open. If the child is reaped and its PID reused,
	// relative lookups cannot silently switch to the replacement's proc files.
	proc, err := os.OpenRoot(fmt.Sprintf("/proc/%d", process.Pid))
	if err != nil {
		return fmt.Errorf("mitmproxy: open listener child proc state: %w", err)
	}
	defer proc.Close()
	identity, err := guardedListenIdentity(proc)
	if err != nil {
		return err
	}
	if identity.pid != process.Pid || identity.parent != os.Getpid() {
		return errors.New("mitmproxy: owned listener process is not the launched child")
	}

	var credential *syscall.Credential
	if attr := running.Cmd.SysProcAttr; attr != nil && attr.Credential != nil && int(attr.Credential.Uid) != os.Geteuid() {
		copy := *attr.Credential
		copy.Groups = append([]uint32(nil), attr.Credential.Groups...)
		credential = &copy
	}

	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("mitmproxy: waiting for child %d listener on port %d: %w", process.Pid, port, err)
		}
		if err := guardedListenVerifyProcess(process, proc, identity); err != nil {
			return err
		}
		var ready bool
		if credential == nil {
			ready, err = guardedListenReady(proc, port)
		} else {
			// Cross-UID proc fd reads are ptrace-gated even for container root.
			// Observe with a one-shot child using mitmdump's existing credentials,
			// rather than adding SYS_PTRACE or changing this process's credentials.
			ready, err = guardedRunOwnedListenHelper(ctx, credential, identity, port)
		}
		if err != nil {
			return err
		}
		if err := guardedListenVerifyProcess(process, proc, identity); err != nil {
			return err
		}
		if ready {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("mitmproxy: waiting for owned listener: %w", err)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("mitmproxy: waiting for child %d listener on port %d: %w", process.Pid, port, ctx.Err())
		case <-ticker.C:
		}
	}
}

// HandleOwnedListenHelper handles the private, read-only listener observation
// mode before ordinary egress startup. The main entrypoint must exit after a
// handled call and must not start services, install rules, or initialize logging.
func HandleOwnedListenHelper(args []string) (handled bool, err error) {
	if len(args) == 0 || args[0] != guardedListenHelperArg {
		return false, nil
	}
	if len(args) != 4 {
		return true, errors.New("mitmproxy: invalid owned listener helper arguments")
	}
	pid, pidErr := strconv.Atoi(args[1])
	port, portErr := strconv.Atoi(args[2])
	start, startErr := strconv.ParseUint(args[3], 10, 64)
	if pidErr != nil || pid <= 0 || portErr != nil || port <= 0 || port > 65535 || startErr != nil || start == 0 {
		return true, errors.New("mitmproxy: invalid owned listener helper identity")
	}
	proc, err := os.OpenRoot(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return true, fmt.Errorf("mitmproxy: open listener child proc state: %w", err)
	}
	defer proc.Close()
	expected := guardedProcessIdentity{pid: pid, parent: os.Getppid(), start: start}
	before, err := guardedListenIdentity(proc)
	if err != nil {
		return true, err
	}
	if before != expected {
		return true, errors.New("mitmproxy: listener helper child identity changed")
	}
	ready, err := guardedListenReady(proc, port)
	if err != nil {
		return true, err
	}
	after, err := guardedListenIdentity(proc)
	if err != nil {
		return true, err
	}
	if after != expected {
		return true, errors.New("mitmproxy: listener helper child identity changed")
	}
	result := "not-ready"
	if ready {
		result = "ready"
	}
	_, err = fmt.Fprintln(os.Stdout, result)
	return true, err
}

func guardedRunOwnedListenHelper(ctx context.Context, credential *syscall.Credential, identity guardedProcessIdentity, port int) (bool, error) {
	executable, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("mitmproxy: locate owned listener helper: %w", err)
	}
	command := exec.CommandContext(ctx, executable, guardedListenHelperArg, strconv.Itoa(identity.pid), strconv.Itoa(port), strconv.FormatUint(identity.start, 10))
	command.Env = []string{} // No inherited configuration, credentials, or helper identity.
	command.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
	output, err := command.Output()
	if ctx.Err() != nil {
		return false, fmt.Errorf("mitmproxy: waiting for listener helper: %w", ctx.Err())
	}
	if err != nil {
		return false, fmt.Errorf("mitmproxy: owned listener helper failed: %w", err)
	}
	switch string(output) {
	case "ready\n":
		return true, nil
	case "not-ready\n":
		return false, nil
	default:
		return false, errors.New("mitmproxy: invalid owned listener helper response")
	}
}

func guardedListenReady(proc *os.Root, port int) (bool, error) {
	owned, err := guardedListenSocketFDs(proc)
	if err != nil {
		return false, err
	}
	listening, err := guardedListenSockets(proc, port)
	if err != nil {
		return false, err
	}
	for fd, inode := range owned {
		if _, ok := listening[inode]; !ok {
			continue
		}
		// An FD can close or be reused while the socket table is read. Recheck
		// that the same descriptor still owns the matched socket inode.
		target, err := proc.Readlink("fd/" + fd)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("mitmproxy: recheck listener socket ownership: %w", err)
		}
		if target == "socket:["+strconv.FormatUint(inode, 10)+"]" {
			return true, nil
		}
	}
	return false, nil
}

type guardedProcessIdentity struct {
	pid    int
	parent int
	start  uint64
}

func guardedListenVerifyProcess(process *os.Process, proc *os.Root, expected guardedProcessIdentity) error {
	actual, err := guardedListenIdentity(proc)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("mitmproxy: listener child process identity changed")
	}
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return fmt.Errorf("mitmproxy: listener child is not live: %w", err)
	}
	return nil
}

func guardedListenIdentity(proc *os.Root) (guardedProcessIdentity, error) {
	data, err := proc.ReadFile("stat")
	if err != nil {
		return guardedProcessIdentity{}, fmt.Errorf("mitmproxy: read listener child identity: %w", err)
	}
	return guardedParseProcessStat(string(data))
}

func guardedParseProcessStat(data string) (guardedProcessIdentity, error) {
	invalid := errors.New("mitmproxy: malformed listener child process identity")
	// comm is parenthesized and may itself contain spaces and parentheses.
	open, close := strings.IndexByte(data, '('), strings.LastIndexByte(data, ')')
	if open < 2 || close <= open || close+1 >= len(data) || data[close+1] != ' ' {
		return guardedProcessIdentity{}, invalid
	}
	pid, err := strconv.Atoi(strings.TrimSpace(data[:open]))
	if err != nil || pid <= 0 {
		return guardedProcessIdentity{}, invalid
	}
	fields := strings.Fields(data[close+1:])
	if len(fields) < 20 || len(fields[0]) != 1 {
		return guardedProcessIdentity{}, invalid
	}
	if strings.Contains("ZXx", fields[0]) {
		return guardedProcessIdentity{}, errors.New("mitmproxy: listener child exited")
	}
	if !strings.Contains("RSDTtWKPI", fields[0]) {
		return guardedProcessIdentity{}, invalid
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil || parent <= 0 {
		return guardedProcessIdentity{}, invalid
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return guardedProcessIdentity{}, invalid
	}
	return guardedProcessIdentity{pid: pid, parent: parent, start: start}, nil
}

func guardedListenSocketFDs(proc *os.Root) (map[string]uint64, error) {
	dir, err := proc.Open("fd")
	if err != nil {
		return nil, fmt.Errorf("mitmproxy: open listener child descriptors: %w", err)
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("mitmproxy: read listener child descriptors: %w", err)
	}
	owned := make(map[string]uint64)
	for _, name := range names {
		target, err := proc.Readlink("fd/" + name)
		if errors.Is(err, os.ErrNotExist) {
			continue // The child can close unrelated descriptors during startup.
		}
		if err != nil {
			return nil, fmt.Errorf("mitmproxy: read listener child descriptor: %w", err)
		}
		if !strings.HasPrefix(target, "socket:") {
			continue
		}
		if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			return nil, errors.New("mitmproxy: malformed listener socket descriptor")
		}
		inode, err := strconv.ParseUint(target[len("socket:["):len(target)-1], 10, 64)
		if err != nil || inode == 0 {
			return nil, errors.New("mitmproxy: malformed listener socket inode")
		}
		owned[name] = inode
	}
	return owned, nil
}

func guardedListenSockets(proc *os.Root, port int) (map[uint64]struct{}, error) {
	listening := make(map[uint64]struct{})
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		file, err := proc.Open(name)
		if name == "net/tcp6" && errors.Is(err, os.ErrNotExist) {
			continue // Kernels built without IPv6 do not expose tcp6.
		}
		if err != nil {
			return nil, fmt.Errorf("mitmproxy: read listener socket table: %w", err)
		}
		inodes, err := guardedParseTCPListeners(file, name == "net/tcp6", port)
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		for inode := range inodes {
			listening[inode] = struct{}{}
		}
	}
	return listening, nil
}

func guardedParseTCPListeners(r io.Reader, ipv6 bool, port int) (map[uint64]struct{}, error) {
	scanner := bufio.NewScanner(r)
	invalid := errors.New("mitmproxy: malformed listener TCP table")
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("mitmproxy: read listener TCP table: %w", err)
		}
		return nil, invalid
	}
	header := strings.Fields(scanner.Text())
	if len(header) < 12 || header[0] != "sl" || header[1] != "local_address" ||
		(header[2] != "rem_address" && header[2] != "remote_address") || header[3] != "st" || header[11] != "inode" {
		return nil, invalid
	}
	listening := make(map[uint64]struct{})
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			return nil, invalid
		}
		loopback, localPort, err := guardedParseTCPAddress(fields[1], ipv6)
		if err != nil {
			return nil, invalid
		}
		if _, _, err := guardedParseTCPAddress(fields[2], ipv6); err != nil {
			return nil, invalid
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil || len(fields[3]) != 2 {
			return nil, invalid
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, invalid
		}
		if state == 0x0a && loopback && localPort == port && inode != 0 {
			listening[inode] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("mitmproxy: read listener TCP table: %w", err)
	}
	return listening, nil
}

func guardedParseTCPAddress(value string, ipv6 bool) (loopback bool, port int, err error) {
	address, portText, ok := strings.Cut(value, ":")
	addressLen := 8
	if ipv6 {
		addressLen = 32
	}
	if !ok || len(address) != addressLen || len(portText) != 4 {
		return false, 0, errors.New("invalid TCP address")
	}
	bytes, err := hex.DecodeString(address)
	if err != nil {
		return false, 0, err
	}
	portNumber, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return false, 0, err
	}
	// proc renders native-endian 32-bit words, including each IPv6 word.
	if ipv6 {
		loopback = binary.NativeEndian.Uint32(bytes[:4]) == 0 && binary.NativeEndian.Uint32(bytes[4:8]) == 0 &&
			binary.NativeEndian.Uint32(bytes[8:12]) == 0 && binary.NativeEndian.Uint32(bytes[12:]) == 1
	} else {
		loopback = binary.NativeEndian.Uint32(bytes) == 0x7f000001
	}
	return loopback, int(portNumber), nil
}
