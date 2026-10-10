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
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

const testIncarnation = "sandbox-test-123"

// The checkout is persistent storage even when the environment's /tmp is tmpfs.
// Production always requires UID/GID 0. Only private test constructors substitute
// the test process owner; all path, mode, inode, mount and fsync checks still run.
func journalTestDirectory(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".journal-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func journalTestOps() journalOps {
	return journalOpsForOwner(uint32(os.Geteuid()), uint32(os.Getegid()))
}

func provisionForTest(t *testing.T) string {
	t.Helper()
	dir := journalTestDirectory(t)
	if err := provisionJournal(dir, testIncarnation, journalTestOps()); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openForTest(t *testing.T, dir string) *Journal {
	t.Helper()
	j, err := openJournal(dir, testIncarnation, journalTestOps())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}

func journalPhase(t *testing.T, dir string) journalRecord {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, journalRecordName))
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeJournal(data, testIncarnation)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func requireJournalError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrJournalUnsafe) {
		t.Fatalf("expected unsafe journal error, got %v", err)
	}
}

func TestJournalLifecycleAndStickyQuarantine(t *testing.T) {
	dir := provisionForTest(t)
	prestart := openForTest(t, dir)
	if err := prestart.GuardBootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := prestart.Close(); err != nil {
		t.Fatal(err)
	}
	worker := openForTest(t, dir)
	for _, advance := range []func() error{worker.StartBootstrap, worker.Commit, worker.Running} {
		if err := advance(); err != nil {
			t.Fatal(err)
		}
	}
	if err := worker.Begin("network-policy"); err != nil {
		t.Fatal(err)
	}
	if r := journalPhase(t, dir); r.Phase != phaseIntent || r.Operation != "network-policy" {
		t.Fatalf("unexpected intent: %+v", r)
	}
	if err := worker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := worker.Running(); err != nil {
		t.Fatal(err)
	}
	if r := journalPhase(t, dir); r.Phase != phaseRunning || r.Operation != "" {
		t.Fatalf("unexpected running marker: %+v", r)
	}
	if err := worker.Quarantine(); err != nil {
		t.Fatal(err)
	}
	if err := worker.Quarantine(); err != nil {
		t.Fatal(err)
	}
	requireJournalError(t, worker.Begin("vault"))
	requireJournalError(t, worker.StartBootstrap())
	requireJournalError(t, worker.Running())
	if r := journalPhase(t, dir); r.Phase != phaseQuarantine {
		t.Fatalf("quarantine was cleared: %+v", r)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	requireJournalError(t, worker.Quarantine())
}

func TestJournalRestartsCannotReplayInterruptedPhases(t *testing.T) {
	for _, phase := range []string{phaseFresh, phaseGuarded, phaseIntent, phaseCommitted, phaseRunning, phaseQuarantine} {
		t.Run(phase, func(t *testing.T) {
			dir := provisionForTest(t)
			r := journalRecord{Version: journalVersion, Incarnation: testIncarnation, Phase: phase}
			if phase != phaseFresh {
				n, err := currentJournalNamespace()
				if err != nil {
					t.Fatal(err)
				}
				r.bindNamespace(n)
			}
			if phase == phaseQuarantine {
				r.Reason = reasonQuarantine
			}
			if phase == phaseIntent || phase == phaseCommitted {
				r.Operation = "bootstrap"
			}
			data, _ := json.Marshal(r)
			if err := os.WriteFile(filepath.Join(dir, journalRecordName), data, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{"commit", "running", "begin"} {
				j := openForTest(t, dir)
				switch method {
				case "commit":
					requireJournalError(t, j.Commit())
				case "running":
					requireJournalError(t, j.Running())
				case "begin":
					requireJournalError(t, j.Begin("update"))
				}
			}
			if phase != phaseFresh {
				requireJournalError(t, openForTest(t, dir).GuardBootstrap())
			}
			if phase != phaseGuarded {
				requireJournalError(t, openForTest(t, dir).StartBootstrap())
			}
			if got := journalPhase(t, dir); got != r {
				t.Fatalf("restart changed marker: %+v", got)
			}
		})
	}
}

func TestJournalProvisionNeverOverwritesOrRepairs(t *testing.T) {
	dir := provisionForTest(t)
	before, err := os.ReadFile(filepath.Join(dir, journalRecordName))
	if err != nil {
		t.Fatal(err)
	}
	requireJournalError(t, provisionJournal(dir, testIncarnation, journalTestOps()))
	requireJournalError(t, provisionJournal(dir, "new-incarnation", journalTestOps()))
	after, err := os.ReadFile(filepath.Join(dir, journalRecordName))
	if err != nil || string(before) != string(after) {
		t.Fatal("exclusive provisioning changed existing record")
	}
	for _, missing := range []string{journalRecordName, journalLockName} {
		t.Run(missing, func(t *testing.T) {
			d := provisionForTest(t)
			if err := os.Remove(filepath.Join(d, missing)); err != nil {
				t.Fatal(err)
			}
			_, err := openJournal(d, testIncarnation, journalTestOps())
			requireJournalError(t, err)
			requireJournalError(t, provisionJournal(d, testIncarnation, journalTestOps()))
			if _, err := os.Lstat(filepath.Join(d, missing)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("missing artifact was recreated")
			}
		})
	}
	missingDir := filepath.Join(journalTestDirectory(t), "absent")
	_, err = openJournal(missingDir, testIncarnation, journalTestOps())
	requireJournalError(t, err)
	requireJournalError(t, provisionJournal(missingDir, testIncarnation, journalTestOps()))
	if _, err := os.Lstat(missingDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("opening/provisioning created a missing directory")
	}
}

func TestJournalConcurrentProvisionAndClaims(t *testing.T) {
	t.Run("provision", func(t *testing.T) {
		dir := journalTestDirectory(t)
		results := make(chan error, 12)
		for range 12 {
			go func() { results <- provisionJournal(dir, testIncarnation, journalTestOps()) }()
		}
		success := 0
		for range 12 {
			if err := <-results; err == nil {
				success++
			}
		}
		if success != 1 {
			t.Fatalf("provision winners = %d, want 1", success)
		}
		openForTest(t, dir)
	})
	for _, worker := range []bool{false, true} {
		name := "prestart"
		if worker {
			name = "worker"
		}
		t.Run(name, func(t *testing.T) {
			dir := provisionForTest(t)
			if worker {
				if err := openForTest(t, dir).GuardBootstrap(); err != nil {
					t.Fatal(err)
				}
			}
			journals := make([]*Journal, 12)
			for i := range journals {
				journals[i] = openForTest(t, dir)
			}
			var wg sync.WaitGroup
			results := make(chan error, len(journals))
			for _, j := range journals {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if worker {
						results <- j.StartBootstrap()
					} else {
						results <- j.GuardBootstrap()
					}
				}()
			}
			wg.Wait()
			close(results)
			success := 0
			for err := range results {
				if err == nil {
					success++
				} else {
					requireJournalError(t, err)
				}
			}
			if success != 1 {
				t.Fatalf("claim winners = %d, want 1", success)
			}
		})
	}
}

func TestJournalRejectsUnsafePathsAndFiles(t *testing.T) {
	for name, mutate := range map[string]func(string) error{
		"record symlink": func(dir string) error {
			if err := os.Rename(filepath.Join(dir, journalRecordName), filepath.Join(dir, "target")); err != nil {
				return err
			}
			return os.Symlink("target", filepath.Join(dir, journalRecordName))
		},
		"lock symlink": func(dir string) error {
			if err := os.Rename(filepath.Join(dir, journalLockName), filepath.Join(dir, "target")); err != nil {
				return err
			}
			return os.Symlink("target", filepath.Join(dir, journalLockName))
		},
		"record hardlink": func(dir string) error {
			return os.Link(filepath.Join(dir, journalRecordName), filepath.Join(dir, "linked"))
		},
		"lock hardlink": func(dir string) error {
			return os.Link(filepath.Join(dir, journalLockName), filepath.Join(dir, "linked"))
		},
		"record readonly":      func(dir string) error { return os.Chmod(filepath.Join(dir, journalRecordName), 0o400) },
		"record broad mode":    func(dir string) error { return os.Chmod(filepath.Join(dir, journalRecordName), 0o640) },
		"lock broad mode":      func(dir string) error { return os.Chmod(filepath.Join(dir, journalLockName), 0o644) },
		"directory broad mode": func(dir string) error { return os.Chmod(dir, 0o750) },
		"directory readonly":   func(dir string) error { return os.Chmod(dir, 0o500) },
		"record directory": func(dir string) error {
			if err := os.Remove(filepath.Join(dir, journalRecordName)); err != nil {
				return err
			}
			return os.Mkdir(filepath.Join(dir, journalRecordName), 0o700)
		},
		"record fifo": func(dir string) error {
			if err := os.Remove(filepath.Join(dir, journalRecordName)); err != nil {
				return err
			}
			return unix.Mkfifo(filepath.Join(dir, journalRecordName), 0o600)
		},
		"corrupt record": func(dir string) error { return os.WriteFile(filepath.Join(dir, journalRecordName), []byte("{"), 0o600) },
		"oversized record": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, journalRecordName), []byte(strings.Repeat(" ", journalLimit+1)), 0o600)
		},
		"lock content": func(dir string) error { return os.WriteFile(filepath.Join(dir, journalLockName), []byte("x"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := provisionForTest(t)
			if err := mutate(dir); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			_, err := openJournal(dir, testIncarnation, journalTestOps())
			requireJournalError(t, err)
		})
	}
	t.Run("wrong incarnation", func(t *testing.T) {
		_, err := openJournal(provisionForTest(t), "other", journalTestOps())
		requireJournalError(t, err)
	})
	t.Run("symlink ancestor", func(t *testing.T) {
		dir := provisionForTest(t)
		link := filepath.Join(journalTestDirectory(t), "linked")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		_, err := openJournal(link, testIncarnation, journalTestOps())
		requireJournalError(t, err)
	})
	t.Run("traversal", func(t *testing.T) {
		_, err := openJournal(provisionForTest(t)+"/../not-used", testIncarnation, journalTestOps())
		requireJournalError(t, err)
	})
	t.Run("record owner", func(t *testing.T) {
		dir := provisionForTest(t)
		ops := journalTestOps()
		ops.uid++
		_, err := openJournal(dir, testIncarnation, ops)
		requireJournalError(t, err)
	})
	t.Run("production root ownership", func(t *testing.T) {
		dir := journalTestDirectory(t)
		err := Provision(dir, testIncarnation)
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			requireJournalError(t, err)
			entries, e := os.ReadDir(dir)
			if e != nil || len(entries) != 0 {
				t.Fatal("rejected provision changed directory")
			}
		} else if err != nil {
			t.Fatal(err)
		}
	})
}

func TestJournalFilesystemAllowlist(t *testing.T) {
	for _, kind := range []int64{unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.OVERLAYFS_SUPER_MAGIC} {
		if err := validateJournalFilesystem(unix.Statfs_t{Type: kind}); err != nil {
			t.Fatal(err)
		}
		if err := validateJournalFilesystem(unix.Statfs_t{Type: kind, Flags: unix.ST_RDONLY}); err == nil {
			t.Fatal("readonly filesystem accepted")
		}
	}
	for _, kind := range []int64{unix.TMPFS_MAGIC, unix.RAMFS_MAGIC, unix.NFS_SUPER_MAGIC, unix.FUSE_SUPER_MAGIC, 0} {
		if err := validateJournalFilesystem(unix.Statfs_t{Type: kind}); err == nil {
			t.Fatalf("unsupported filesystem %#x accepted", kind)
		}
	}
}

func TestJournalRevalidatesPinnedDirectoryAndLock(t *testing.T) {
	for _, change := range []string{"directory", "lock", "permissions"} {
		t.Run(change, func(t *testing.T) {
			dir := provisionForTest(t)
			j := openForTest(t, dir)
			switch change {
			case "directory":
				if err := os.Rename(dir, dir+"-moved"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(dir + "-moved") })
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := provisionJournal(dir, testIncarnation, journalTestOps()); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.Rename(filepath.Join(dir, journalLockName), filepath.Join(dir, "old-lock")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, journalLockName), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(filepath.Join(dir, journalRecordName), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			requireJournalError(t, j.GuardBootstrap())
			if r := journalPhase(t, dir); r.Phase != phaseFresh {
				t.Fatal("unsafe directory/lock advanced")
			}
		})
	}
}

func TestJournalCommitFailuresNeverAuthorizeUnlock(t *testing.T) {
	injected := errors.New("injected storage failure")
	tests := []struct {
		name   string
		phase  string
		inject func(*journalOps)
	}{
		{"directory-open", phaseIntent, func(o *journalOps) { o.openDir = func(string) (*os.File, error) { return nil, injected } }},
		{"record-open", phaseIntent, func(o *journalOps) {
			old := o.openFile
			o.openFile = func(d *os.File, n string, f int) (*os.File, error) {
				if n == journalRecordName {
					return nil, injected
				}
				return old(d, n, f)
			}
		}},
		{"temporary-create", phaseIntent, func(o *journalOps) {
			old := o.openFile
			o.openFile = func(d *os.File, n string, f int) (*os.File, error) {
				if strings.HasPrefix(n, ".journal-") {
					return nil, injected
				}
				return old(d, n, f)
			}
		}},
		{"write", phaseIntent, func(o *journalOps) { o.write = func(*os.File, []byte) (int, error) { return 0, injected } }},
		{"short-write", phaseIntent, func(o *journalOps) { o.write = func(_ *os.File, b []byte) (int, error) { return len(b) - 1, nil } }},
		{"file-sync", phaseIntent, func(o *journalOps) { o.syncFile = func(*os.File) error { return injected } }},
		{"final-open", phaseIntent, func(o *journalOps) {
			old := o.openFile
			o.openFile = func(d *os.File, n string, f int) (*os.File, error) {
				if strings.HasPrefix(n, ".journal-") && f == unix.O_RDONLY {
					return nil, injected
				}
				return old(d, n, f)
			}
		}},
		{"final-sync", phaseIntent, func(o *journalOps) {
			old := o.syncFile
			count := 0
			o.syncFile = func(f *os.File) error {
				count++
				if count == 2 {
					return injected
				}
				return old(f)
			}
		}},
		{"temporary-close", phaseIntent, func(o *journalOps) {
			old := o.closeFile
			o.closeFile = func(f *os.File) error {
				e := old(f)
				if strings.HasPrefix(f.Name(), ".journal-") {
					return errors.Join(e, injected)
				}
				return e
			}
		}},
		{"rename-before-effect", phaseIntent, func(o *journalOps) { o.rename = func(*os.File, string, string) error { return injected } }},
		{"rename-after-effect", phaseCommitted, func(o *journalOps) {
			old := o.rename
			o.rename = func(d *os.File, a, b string) error { return errors.Join(old(d, a, b), injected) }
		}},
		{"directory-preflight", phaseIntent, func(o *journalOps) { o.syncDir = func(*os.File) error { return injected } }},
		{"directory-post-rename", phaseCommitted, func(o *journalOps) {
			old := o.syncDir
			count := 0
			o.syncDir = func(f *os.File) error {
				count++
				if count == 2 {
					return injected
				}
				return old(f)
			}
		}},
		{"committed-readback-open", phaseCommitted, func(o *journalOps) {
			old := o.openFile
			count := 0
			o.openFile = func(d *os.File, n string, f int) (*os.File, error) {
				if n == journalRecordName {
					count++
					if count == 2 {
						return nil, injected
					}
				}
				return old(d, n, f)
			}
		}},
		{"committed-readback-close", phaseCommitted, func(o *journalOps) {
			old := o.closeFile
			count := 0
			o.closeFile = func(f *os.File) error {
				e := old(f)
				if f.Name() == journalRecordName {
					count++
					if count == 2 {
						return errors.Join(e, injected)
					}
				}
				return e
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := provisionForTest(t)
			j := openForTest(t, dir)
			if err := j.GuardBootstrap(); err != nil {
				t.Fatal(err)
			}
			if err := j.StartBootstrap(); err != nil {
				t.Fatal(err)
			}
			original := j.ops
			tc.inject(&j.ops)
			requireJournalError(t, j.Commit())
			j.ops = original
			if r := journalPhase(t, dir); r.Phase != tc.phase {
				t.Fatalf("phase = %s, want %s", r.Phase, tc.phase)
			}
			// A matching committed record after lost readback is not proof that
			// the interrupted operation may now release the external fence.
			requireJournalError(t, j.Running())
			requireJournalError(t, j.Commit())
			requireJournalError(t, openForTest(t, dir).StartBootstrap())
			if err := j.Quarantine(); err != nil {
				t.Fatal(err)
			}
			if r := journalPhase(t, dir); r.Phase != phaseQuarantine {
				t.Fatal("failed operation was not quarantined")
			}
			requireJournalError(t, j.Running())
		})
	}
}

func TestJournalFailedProvisionCannotBeRetried(t *testing.T) {
	dir := journalTestDirectory(t)
	ops := journalTestOps()
	ops.write = func(*os.File, []byte) (int, error) { return 0, unix.EIO }
	requireJournalError(t, provisionJournal(dir, testIncarnation, ops))
	_, err := openJournal(dir, testIncarnation, journalTestOps())
	requireJournalError(t, err)
	requireJournalError(t, provisionJournal(dir, testIncarnation, journalTestOps()))
}

func TestJournalFinalizedTemporaryInodeMustMatch(t *testing.T) {
	dir := provisionForTest(t)
	j := openForTest(t, dir)
	if err := j.GuardBootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := j.StartBootstrap(); err != nil {
		t.Fatal(err)
	}
	open := j.ops.openFile
	j.ops.openFile = func(d *os.File, name string, flags int) (*os.File, error) {
		if strings.HasPrefix(name, ".journal-") && flags == unix.O_RDONLY {
			path := filepath.Join(dir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			if err := os.Rename(path, path+".old"); err != nil {
				return nil, err
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				return nil, err
			}
		}
		return open(d, name, flags)
	}
	requireJournalError(t, j.Commit())
	if r := journalPhase(t, dir); r.Phase != phaseIntent {
		t.Fatal("replacement temporary inode was published")
	}
}

// This subprocess exits without defers, so OS descriptor cleanup and flock
// release, rather than Journal.Close, establish the restart boundary.
func TestJournalProcessHelper(t *testing.T) {
	mode := os.Getenv("OPENSANDBOX_JOURNAL_TEST_CHILD")
	if mode == "" {
		return
	}
	dir := os.Getenv("OPENSANDBOX_JOURNAL_TEST_PATH")
	j, err := openJournal(dir, testIncarnation, journalTestOps())
	if err != nil {
		os.Exit(70)
	}
	if mode == "claim" {
		if err := j.GuardBootstrap(); err != nil {
			os.Exit(42)
		}
		os.Exit(0)
	}
	if err := j.GuardBootstrap(); err != nil {
		os.Exit(71)
	}
	if mode == phaseGuarded {
		os.Exit(0)
	}
	if err := j.StartBootstrap(); err != nil {
		os.Exit(72)
	}
	if mode == phaseIntent {
		os.Exit(0)
	}
	if mode == "before-rename" {
		j.ops.rename = func(*os.File, string, string) error { os.Exit(0); return nil }
	}
	if mode == "after-rename" {
		rename := j.ops.rename
		j.ops.rename = func(d *os.File, a, b string) error {
			if err := rename(d, a, b); err != nil {
				os.Exit(73)
			}
			os.Exit(0)
			return nil
		}
	}
	if err := j.Commit(); err != nil {
		os.Exit(74)
	}
	if mode == phaseCommitted {
		os.Exit(0)
	}
	if err := j.Running(); err != nil {
		os.Exit(75)
	}
	if mode == phaseRunning {
		os.Exit(0)
	}
	os.Exit(76)
}

func journalChild(t *testing.T, dir, mode string) *exec.Cmd {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "-test.run=^TestJournalProcessHelper$")
	cmd.Env = append(os.Environ(), "OPENSANDBOX_JOURNAL_TEST_CHILD="+mode, "OPENSANDBOX_JOURNAL_TEST_PATH="+dir)
	return cmd
}

func TestJournalAbruptProcessExitCannotRestart(t *testing.T) {
	for _, phase := range []string{phaseGuarded, phaseIntent, "before-rename", "after-rename", phaseCommitted, phaseRunning} {
		t.Run(phase, func(t *testing.T) {
			dir := provisionForTest(t)
			if output, err := journalChild(t, dir, phase).CombinedOutput(); err != nil {
				t.Fatalf("child failed: %v, %s", err, output)
			}
			expected := phase
			if phase == "before-rename" {
				expected = phaseIntent
			} else if phase == "after-rename" {
				expected = phaseCommitted
			}
			if r := journalPhase(t, dir); r.Phase != expected {
				t.Fatalf("crash marker = %s, expected %s", r.Phase, expected)
			}
			j := openForTest(t, dir)
			requireJournalError(t, j.GuardBootstrap())
			requireJournalError(t, j.Commit())
			requireJournalError(t, j.Running())
		})
	}
}

func TestJournalProcessClaimsHaveOneWinner(t *testing.T) {
	dir := provisionForTest(t)
	commands := make([]*exec.Cmd, 6)
	for i := range commands {
		commands[i] = journalChild(t, dir, "claim")
		if err := commands[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	winners := 0
	for _, cmd := range commands {
		err := cmd.Wait()
		if err == nil {
			winners++
			continue
		}
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 42 {
			t.Fatalf("unexpected claim exit: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("process claim winners = %d, want 1", winners)
	}
}
