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
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Run in dedicated privileged Linux CI:
// OPENSANDBOX_RUN_JOURNAL_MOUNT_TESTS=1 go test ./pkg/quarantine -run '^TestJournalPrivilegedMounts$' -v
// Requires root, CAP_SYS_ADMIN, unshare, mount, mkfs.ext4, and loop-device support.
// Enabling this suite makes missing prerequisites failures, never silent skips.
func TestJournalPrivilegedMounts(t *testing.T) {
	if os.Getenv("OPENSANDBOX_RUN_JOURNAL_MOUNT_TESTS") != "1" {
		t.Skip("set OPENSANDBOX_RUN_JOURNAL_MOUNT_TESTS=1 in privileged Linux CI")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("journal mount tests require root:root")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// /var/tmp has trusted root ancestors and is normally backed by the host
	// filesystem even when /tmp is tmpfs. Each child uses an isolated namespace.
	base, err := os.MkdirTemp("/var/tmp", "opensandbox-journal-mount-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	cmd := exec.Command("unshare", "--mount", "--propagation", "private", executable, "-test.run=^TestJournalPrivilegedMountHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "OPENSANDBOX_JOURNAL_MOUNT_CHILD="+base)
	output, err := cmd.CombinedOutput()
	t.Logf("mount namespace checks:\n%s", output)
	if err != nil {
		t.Fatalf("privileged journal checks failed: %v", err)
	}
}

func TestJournalPrivilegedMountHelper(t *testing.T) {
	base := os.Getenv("OPENSANDBOX_JOURNAL_MOUNT_CHILD")
	if base == "" {
		return
	}
	newDirectory := func(t *testing.T) string {
		t.Helper()
		dir, err := os.MkdirTemp(base, "case-")
		if err != nil {
			t.Fatal(err)
		}
		return dir
	}
	provision := func(t *testing.T) string {
		t.Helper()
		dir := newDirectory(t)
		if err := Provision(dir, testIncarnation); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	t.Run("readonly-directory", func(t *testing.T) {
		dir := provision(t)
		if err := unix.Mount(dir, dir, "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		defer unix.Unmount(dir, unix.MNT_DETACH)
		if err := unix.Mount("", dir, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			t.Fatal(err)
		}
		_, err := OpenJournal(dir, testIncarnation)
		requireJournalError(t, err)
	})
	for _, name := range []string{journalRecordName, journalLockName} {
		t.Run("same-device-file-bind-"+name, func(t *testing.T) {
			dir := provision(t)
			target := filepath.Join(dir, name)
			data, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(newDirectory(t), name)
			if err := os.WriteFile(source, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			defer unix.Unmount(target, unix.MNT_DETACH)
			_, err = OpenJournal(dir, testIncarnation)
			requireJournalError(t, err)
		})
	}
	t.Run("real-ext4-enospc", func(t *testing.T) {
		image := filepath.Join(base, "journal-ext4.img")
		f, err := os.OpenFile(image, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		err = f.Truncate(32 << 20)
		err = errors.Join(err, f.Close())
		if err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command("mkfs.ext4", "-q", "-F", "-m", "0", image).CombinedOutput(); err != nil {
			t.Fatalf("format test filesystem: %v: %s", err, output)
		}
		mount := newDirectory(t)
		if output, err := exec.Command("mount", "-o", "loop,nodev,nosuid,noexec", image, mount).CombinedOutput(); err != nil {
			t.Fatalf("mount ext4 test filesystem: %v: %s", err, output)
		}
		defer unix.Unmount(mount, unix.MNT_DETACH)
		if err := os.Chmod(mount, 0o700); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(mount, "journal")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := Provision(dir, testIncarnation); err != nil {
			t.Fatal(err)
		}
		j, err := OpenJournal(dir, testIncarnation)
		if err != nil {
			t.Fatal(err)
		}
		defer j.Close()
		if err := j.GuardBootstrap(); err != nil {
			t.Fatal(err)
		}
		if err := j.StartBootstrap(); err != nil {
			t.Fatal(err)
		}
		fill, err := os.OpenFile(filepath.Join(mount, "fill"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer fill.Close()
		// Fallocate consumes real blocks immediately, rather than relying on
		// delayed allocation to expose ENOSPC before the journal's fsync.
		for offset := int64(0); ; offset += 4096 {
			if offset > 64<<20 {
				t.Fatal("test filesystem did not fill within its size bound")
			}
			err := unix.Fallocate(int(fill.Fd()), 0, offset, 4096)
			if errors.Is(err, unix.ENOSPC) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		err = j.Commit()
		requireJournalError(t, err)
		if !errors.Is(err, unix.ENOSPC) {
			t.Fatalf("expected real ENOSPC, got %v", err)
		}
		requireJournalError(t, j.Running())
		if r := journalPhase(t, dir); r.Phase != phaseIntent {
			t.Fatalf("disk-full commit changed authority to %s", r.Phase)
		}
	})
}
