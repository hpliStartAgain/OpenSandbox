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

package quarantine

import (
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// currentJournalNamespace uses kernel identities, never a PID or the printable
// net:[inode] symlink text. The boot ID prevents comparisons across host boots.
// A live process itself retains its namespace, preventing its inode from being
// recycled while that namespace is in use. These identifiers are not eternal
// capabilities: after the original namespace is destroyed, inode reuse within
// the same boot remains possible. Consequently an identity match never permits
// consumed-phase replay or whole-container restart recovery, nor proves a fence.
func currentJournalNamespace() (out journalNamespace, err error) {
	boot, err := os.Open("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return out, err
	}
	data, readErr := io.ReadAll(io.LimitReader(boot, 128))
	err = errors.Join(readErr, boot.Close())
	if err != nil {
		return out, err
	}
	out.bootID = strings.TrimSpace(string(data))
	// This proc entry is intentionally a kernel magic link to an nsfs inode.
	// O_NOFOLLOW would prevent opening the namespace itself for fstat.
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, ns.Close()) }()
	fd := int(ns.Fd())
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return out, err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return out, err
	}
	if fs.Type != unix.NSFS_MAGIC {
		return out, errors.New("network namespace is not an nsfs inode")
	}
	kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNET {
		return out, errors.Join(err, errors.New("network namespace type is unconfirmed"))
	}
	out.dev, out.inode = uint64(st.Dev), st.Ino
	if !out.valid() {
		return out, errors.New("invalid kernel boot or network namespace identity")
	}
	return out, nil
}
