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
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func namespaceFixture() journalNamespace {
	return journalNamespace{bootID: "11111111-2222-3333-4444-555555555555", dev: 4, inode: 1234567}
}

func namespaceJournal(t *testing.T) (*Journal, *journalNamespace, string) {
	t.Helper()
	dir := provisionForTest(t)
	current := namespaceFixture()
	ops := journalTestOps()
	ops.namespace = func() (journalNamespace, error) { return current, nil }
	j, err := openJournal(dir, testIncarnation, ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, &current, dir
}

func TestJournalProvisionDoesNotBindHelperNamespace(t *testing.T) {
	dir := journalTestDirectory(t)
	ops := journalTestOps()
	ops.namespace = func() (journalNamespace, error) {
		t.Fatal("provision/open fresh must not read helper namespace")
		return journalNamespace{}, unix.EIO
	}
	if err := provisionJournal(dir, testIncarnation, ops); err != nil {
		t.Fatal(err)
	}
	r := journalPhase(t, dir)
	if r.Version != 2 || r.Phase != phaseFresh || r.namespace() != (journalNamespace{}) || r.Reason != "" {
		t.Fatalf("provision was not unbound fresh: %+v", r)
	}
	j, err := openJournal(dir, testIncarnation, ops)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	worker := namespaceFixture()
	j.ops.namespace = func() (journalNamespace, error) { return worker, nil }
	if err := j.GuardBootstrap(); err != nil {
		t.Fatal(err)
	}
	r = journalPhase(t, dir)
	if r.Phase != phaseGuarded || r.namespace() != worker || r.Reason != "" {
		t.Fatalf("guard binding not persisted: %+v", r)
	}
	if err := j.CheckNamespace(); err != nil {
		t.Fatal(err)
	}
}

func TestJournalEveryLiveNamespaceMismatchIsTerminal(t *testing.T) {
	for _, mutation := range []string{"boot", "device", "inode"} {
		for _, method := range []string{"guard", "start", "commit", "running", "begin", "check", "quarantine"} {
			t.Run(mutation+"/"+method, func(t *testing.T) {
				j, current, dir := namespaceJournal(t)
				if err := j.GuardBootstrap(); err != nil {
					t.Fatal(err)
				}
				if method == "commit" || method == "running" || method == "begin" || method == "quarantine" {
					if err := j.StartBootstrap(); err != nil {
						t.Fatal(err)
					}
				}
				if method == "running" || method == "begin" {
					if err := j.Commit(); err != nil {
						t.Fatal(err)
					}
				}
				if method == "begin" {
					if err := j.Running(); err != nil {
						t.Fatal(err)
					}
				}
				before := journalPhase(t, dir)
				switch mutation {
				case "boot":
					current.bootID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
				case "device":
					current.dev++
				case "inode":
					current.inode++
				}
				var err error
				switch method {
				case "guard":
					err = j.GuardBootstrap()
				case "start":
					err = j.StartBootstrap()
				case "commit":
					err = j.Commit()
				case "running":
					err = j.Running()
				case "begin":
					err = j.Begin("policy")
				case "check":
					err = j.CheckNamespace()
				case "quarantine":
					err = j.Quarantine()
				}
				requireJournalError(t, err)
				if !strings.Contains(err.Error(), reasonNamespaceMismatch) {
					t.Fatalf("missing terminal mismatch reason: %v", err)
				}
				after := journalPhase(t, dir)
				before.Phase, before.Reason = phaseQuarantine, reasonNamespaceMismatch
				if after != before {
					t.Fatalf("mismatch changed original identity/operation: %+v", after)
				}
				// Restoring the old tuple cannot clear a terminal namespace failure.
				*current = namespaceFixture()
				requireJournalError(t, j.CheckNamespace())
				requireJournalError(t, j.StartBootstrap())
				if err := j.Close(); err != nil {
					t.Fatal(err)
				}
				_, err = openJournal(dir, testIncarnation, j.ops)
				requireJournalError(t, err)
				if got := journalPhase(t, dir); got != after {
					t.Fatal("reopening changed terminal namespace marker")
				}
			})
		}
	}
}

func TestJournalReopenMismatchPreservesOriginalNamespace(t *testing.T) {
	j, current, dir := namespaceJournal(t)
	if err := j.GuardBootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := j.StartBootstrap(); err != nil {
		t.Fatal(err)
	}
	before := journalPhase(t, dir)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	current.inode++
	opened, err := openJournal(dir, testIncarnation, j.ops)
	if opened != nil {
		t.Fatal("namespace mismatch returned a usable handle")
	}
	requireJournalError(t, err)
	before.Phase, before.Reason = phaseQuarantine, reasonNamespaceMismatch
	if got := journalPhase(t, dir); got != before {
		t.Fatalf("reopen rebound namespace: %+v", got)
	}
}

func TestJournalNamespaceCheckFailureRetainsBinding(t *testing.T) {
	for _, fresh := range []bool{true, false} {
		name := "bound"
		if fresh {
			name = "fresh"
		}
		t.Run(name, func(t *testing.T) {
			j, _, dir := namespaceJournal(t)
			if !fresh {
				if err := j.GuardBootstrap(); err != nil {
					t.Fatal(err)
				}
			}
			before := journalPhase(t, dir)
			j.ops.namespace = func() (journalNamespace, error) { return journalNamespace{}, unix.EIO }
			var err error
			if fresh {
				err = j.GuardBootstrap()
			} else {
				err = j.CheckNamespace()
			}
			requireJournalError(t, err)
			if !errors.Is(err, unix.EIO) {
				t.Fatalf("lost namespace acquisition error: %v", err)
			}
			before.Phase, before.Reason = phaseQuarantine, reasonNamespaceCheck
			if got := journalPhase(t, dir); got != before {
				t.Fatalf("namespace check failure changed binding: %+v", got)
			}
			j.ops.namespace = func() (journalNamespace, error) { return namespaceFixture(), nil }
			requireJournalError(t, j.CheckNamespace())
			_, err = openJournal(dir, testIncarnation, j.ops)
			requireJournalError(t, err)
		})
	}
}

func TestJournalNamespaceMismatchWriteFailureStillFailsClosed(t *testing.T) {
	j, current, dir := namespaceJournal(t)
	if err := j.GuardBootstrap(); err != nil {
		t.Fatal(err)
	}
	before := journalPhase(t, dir)
	current.inode++
	write := j.ops.write
	j.ops.write = func(*os.File, []byte) (int, error) { return 0, unix.ENOSPC }
	err := j.CheckNamespace()
	requireJournalError(t, err)
	if !errors.Is(err, unix.ENOSPC) || !strings.Contains(err.Error(), reasonNamespaceMismatch) {
		t.Fatalf("lost mismatch/storage error: %v", err)
	}
	if got := journalPhase(t, dir); got != before {
		t.Fatal("failed quarantine write changed original record")
	}
	j.ops.write = write
	*current = namespaceFixture()
	requireJournalError(t, j.CheckNamespace())
	requireJournalError(t, j.StartBootstrap())
}

func TestJournalOrdinaryWriteFailureAllowsIndependentNamespaceProof(t *testing.T) {
	j, _, dir := namespaceJournal(t)
	if err := j.GuardBootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := j.StartBootstrap(); err != nil {
		t.Fatal(err)
	}
	sync := j.ops.syncFile
	j.ops.syncFile = func(*os.File) error { return unix.EIO }
	requireJournalError(t, j.Commit())
	j.ops.syncFile = sync
	if err := j.CheckNamespace(); err != nil {
		t.Fatalf("ordinary write failure prevented independent namespace proof: %v", err)
	}
	requireJournalError(t, j.Commit())
	requireJournalError(t, j.Running())
	if err := j.Quarantine(); err != nil {
		t.Fatal(err)
	}
	if err := j.CheckNamespace(); err != nil {
		t.Fatal(err)
	}
	if r := journalPhase(t, dir); r.Reason != reasonQuarantine || r.namespace() != namespaceFixture() {
		t.Fatalf("unexpected quarantine: %+v", r)
	}
	if err := os.Chmod(filepath.Join(dir, journalRecordName), 0o644); err != nil {
		t.Fatal(err)
	}
	requireJournalError(t, j.CheckNamespace())
}

func TestJournalNamespaceRecordCannotBeRebound(t *testing.T) {
	j, current, dir := namespaceJournal(t)
	if err := j.GuardBootstrap(); err != nil {
		t.Fatal(err)
	}
	r := journalPhase(t, dir)
	current.inode++
	r.bindNamespace(*current)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, journalRecordName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	requireJournalError(t, j.CheckNamespace())
	requireJournalError(t, j.StartBootstrap())
	if j.bound == *current {
		t.Fatal("handle adopted a changed original namespace record")
	}
}

func TestJournalFreshNamespaceCheckCannotBind(t *testing.T) {
	j, _, dir := namespaceJournal(t)
	requireJournalError(t, j.CheckNamespace())
	r := journalPhase(t, dir)
	if r.Phase != phaseQuarantine || r.namespace() != (journalNamespace{}) || r.Reason != reasonNamespaceUnbound {
		t.Fatalf("unbound check silently bound namespace: %+v", r)
	}
	requireJournalError(t, j.GuardBootstrap())
}

func TestJournalKernelNamespaceIdentity(t *testing.T) {
	a, err := currentJournalNamespace()
	if err != nil {
		t.Fatal(err)
	}
	b, err := currentJournalNamespace()
	if err != nil {
		t.Fatal(err)
	}
	if !a.valid() || a != b {
		t.Fatalf("unstable or invalid current kernel namespace identity: %+v %+v", a, b)
	}
}
