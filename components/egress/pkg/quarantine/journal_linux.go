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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Journal is a quarantine-only crash marker, not a transaction replay log.
// Provisioning is a separate trusted lifecycle operation. Opening never repairs
// or initializes storage. Bootstrap requires an already confirmed network fence.
// Live mutations record Begin before confirming the fence; dangerous effects
// require both steps to succeed. Keep the fence on every error. Only a successful
// transition establishes durability; readback following an error cannot upgrade
// its result.
// The directory must be a private, root-owned, persistent sidecar-only mount.
// Overlayfs is supported only when its backing storage has that lifecycle and
// durability contract. A tmpfs or ephemeral container writable layer is not a
// durable journal. Close releases descriptors, never removes or resets state.
type Journal struct {
	mu              sync.Mutex
	path            string
	incarnation     string
	dir, lock       *os.File
	ops             journalOps
	failed          error
	closed          bool
	ownedPhase      string
	bound           journalNamespace
	namespaceFailed bool
}

// These narrow hooks exercise uncertain I/O outcomes without weakening the
// public root-only ownership or supported-filesystem requirements.
type journalOps struct {
	uid, gid  uint32
	openDir   func(string) (*os.File, error)
	openFile  func(*os.File, string, int) (*os.File, error)
	write     func(*os.File, []byte) (int, error)
	syncFile  func(*os.File) error
	syncDir   func(*os.File) error
	closeFile func(*os.File) error
	rename    func(*os.File, string, string) error
	namespace func() (journalNamespace, error)
}

func defaultJournalOps() journalOps { return journalOpsForOwner(0, 0) }

func journalOpsForOwner(uid, gid uint32) journalOps {
	return journalOps{
		uid: uid, gid: gid,
		namespace: currentJournalNamespace,
		openDir:   func(path string) (*os.File, error) { return secureJournalDirectory(path, uid, gid) },
		openFile: func(dir *os.File, name string, flags int) (*os.File, error) {
			fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
			if err != nil {
				return nil, err
			}
			return os.NewFile(uintptr(fd), name), nil
		},
		write:     func(f *os.File, data []byte) (int, error) { return f.Write(data) },
		syncFile:  func(f *os.File) error { return f.Sync() },
		syncDir:   func(f *os.File) error { return f.Sync() },
		closeFile: func(f *os.File) error { return f.Close() },
		rename: func(dir *os.File, old, new string) error {
			return unix.Renameat(int(dir.Fd()), old, int(dir.Fd()), new)
		},
	}
}

func journalDirectoryPath(path string) (string, error) {
	if path == "" || path != strings.TrimSpace(path) {
		return "", errors.New("empty or whitespace-padded directory path")
	}
	for _, part := range strings.Split(path, string(os.PathSeparator)) {
		if part == ".." {
			return "", errors.New("parent traversal is unsupported")
		}
	}
	return filepath.Abs(path)
}

// Provision exclusively creates a fresh journal in an existing empty directory.
// It is intended only for the trusted new-sandbox lifecycle helper, before the
// sidecar starts. It never overwrites a record, a lock, or incomplete provisioning
// artifacts. Failure leaves those artifacts in place; there is no reset API.
func Provision(dir, incarnation string) error {
	return provisionJournal(dir, incarnation, defaultJournalOps())
}

func provisionJournal(path, incarnation string, ops journalOps) (err error) {
	if !validJournalLabel(incarnation, 128) {
		return journalError("provision", errors.New("invalid incarnation"))
	}
	path, err = journalDirectoryPath(path)
	if err != nil {
		return journalError("provision-path", err)
	}
	dir, err := ops.openDir(path)
	if err != nil {
		return journalError("provision-directory", err)
	}
	defer func() {
		if e := ops.closeFile(dir); e != nil {
			err = errors.Join(err, journalError("provision-directory-close", e))
		}
	}()
	names, err := dir.Readdirnames(-1)
	if err != nil || len(names) != 0 {
		return journalError("provision", errors.New("directory must be empty and readable"))
	}
	if err := ops.syncDir(dir); err != nil {
		return journalError("provision-directory-sync", err)
	}
	lock, err := ops.openFile(dir, journalLockName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return journalError("provision-lock", err)
	}
	defer func() {
		if e := ops.closeFile(lock); e != nil {
			err = errors.Join(err, journalError("provision-lock-close", e))
		}
	}()
	if _, err := validateJournalFile(dir, lock, journalLockName, ops); err != nil {
		return journalError("provision-lock", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return journalError("provision-lock", err)
	}
	defer func() {
		if e := unix.Flock(int(lock.Fd()), unix.LOCK_UN); e != nil {
			err = errors.Join(err, journalError("provision-unlock", e))
		}
	}()
	if err := ops.syncFile(lock); err != nil {
		return journalError("provision-lock-sync", err)
	}
	if err := ops.syncDir(dir); err != nil {
		return journalError("provision-lock-directory-sync", err)
	}
	r := journalRecord{Version: journalVersion, Incarnation: incarnation, Phase: phaseFresh}
	data, _ := json.Marshal(r)
	data = append(data, '\n')
	f, err := ops.openFile(dir, journalRecordName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return journalError("provision-record", err)
	}
	if _, err = validateJournalFile(dir, f, journalRecordName, ops); err == nil {
		err = writeJournalFile(f, data, ops)
	}
	err = errors.Join(err, ops.closeFile(f))
	if err != nil {
		return journalError("provision-record", err)
	}
	if err := ops.syncDir(dir); err != nil {
		return journalError("provision-record-directory-sync", err)
	}
	j := &Journal{path: path, incarnation: incarnation, dir: dir, lock: lock, ops: ops}
	actual, _, err := j.readRecord()
	if err != nil || actual != r {
		return journalError("provision-readback", errors.Join(err, errors.New("record not confirmed")))
	}
	return nil
}

// OpenJournal validates an existing journal; it never initializes, repairs, or
// rebinds one. A namespace mismatch or acquisition failure may persist terminal
// quarantine before returning an error. Nonfresh records cannot be replayed:
// a new handle can claim only the prestart's guarded phase in the same namespace
// via StartBootstrap, never recover a consumed worker or container incarnation.
func OpenJournal(dir, incarnation string) (*Journal, error) {
	return openJournal(dir, incarnation, defaultJournalOps())
}

func openJournal(path, incarnation string, ops journalOps) (_ *Journal, err error) {
	if !validJournalLabel(incarnation, 128) {
		return nil, journalError("open", errors.New("invalid incarnation"))
	}
	path, err = journalDirectoryPath(path)
	if err != nil {
		return nil, journalError("open-path", err)
	}
	dir, err := ops.openDir(path)
	if err != nil {
		return nil, journalError("open-directory", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, ops.closeFile(dir))
		}
	}()
	if err := validateJournalEntry(dir, journalLockName, ops); err != nil {
		return nil, journalError("open-lock", err)
	}
	lock, err := ops.openFile(dir, journalLockName, unix.O_RDWR)
	if err != nil {
		return nil, journalError("open-lock", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, ops.closeFile(lock))
		}
	}()
	j := &Journal{path: path, incarnation: incarnation, dir: dir, lock: lock, ops: ops}
	if err := j.withLock(func() error {
		r, label, err := j.readRecord()
		if err != nil {
			return err
		}
		if r.Phase == phaseFresh {
			return nil
		}
		j.bound = r.namespace()
		return j.checkNamespace(r, label)
	}); err != nil {
		return nil, journalError("open-validate", err)
	}
	return j, nil
}

// GuardBootstrap is called by prestart only after installing the network fence.
// It is the sole fresh-to-bound transition, capturing the actual sandbox's boot
// and network namespace identity rather than the provisioning helper's identity.
func (j *Journal) GuardBootstrap() error { return j.transition(phaseFresh, phaseGuarded, "", false) }

// StartBootstrap durably marks intent before the worker's first external effect.
func (j *Journal) StartBootstrap() error {
	return j.transition(phaseGuarded, phaseIntent, "bootstrap", false)
}

// Begin records a metadata-only operation label before any subsequent effect.
func (j *Journal) Begin(operation string) error {
	return j.transition(phaseRunning, phaseIntent, operation, true)
}

// Commit must follow confirmed effects; it does not remove a network fence.
func (j *Journal) Commit() error { return j.transition(phaseIntent, phaseCommitted, "", true) }

// Running records completion after Commit. It never authorizes restart replay.
func (j *Journal) Running() error { return j.transition(phaseCommitted, phaseRunning, "", true) }

// Quarantine is sticky and idempotent. It may be attempted even after an earlier
// error, but success does not clear the handle's failure latch or the fence.
func (j *Journal) Quarantine() error { return j.transition("", phaseQuarantine, "", false) }

// CheckNamespace verifies only the original bound boot/network namespace. It
// cannot prove packet containment; callers must independently confirm the fence.
// A prior ordinary write failure does not forbid a successful identity proof,
// but storage/path corruption and terminal namespace failures remain unsafe.
// A mismatch may durably mark terminal quarantine while preserving the binding.
// It never grants permission to advance a failed or reopened worker handle.
func (j *Journal) CheckNamespace() (err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	defer func() {
		if err != nil && j.failed == nil {
			j.failed = err
		}
	}()
	if j.closed || j.dir == nil || j.lock == nil {
		return journalError("namespace-check", errors.New("closed journal; rebuild-required"))
	}
	return j.withLock(func() error {
		r, label, err := j.readRecord()
		if err != nil {
			return journalError("namespace-check-record", err)
		}
		return j.checkNamespace(r, label)
	})
}

// checkNamespace runs with the stable journal lock held. Mismatch is terminal;
// writing quarantine is best-effort and never converts an error into success.
func (j *Journal) checkNamespace(r journalRecord, label string) error {
	if j.namespaceFailed {
		return journalError("namespace-check", errors.New("namespace failure is terminal; rebuild-required"))
	}
	if r.Reason == reasonNamespaceMismatch || r.Reason == reasonNamespaceCheck || r.Reason == reasonNamespaceUnbound {
		j.namespaceFailed = true
		return journalError("namespace-check", errors.New(r.Reason))
	}
	if !r.namespace().valid() {
		return j.namespaceFailure(r, label, reasonNamespaceUnbound, nil)
	}
	if j.bound != (journalNamespace{}) && j.bound != r.namespace() {
		// The authoritative record no longer contains this handle's original
		// identity. Do not repair or bless the changed record by rebinding it.
		j.namespaceFailed = true
		return journalError("namespace-check", errors.New("original namespace record identity changed; rebuild-required"))
	}
	current, err := j.ops.namespace()
	if err != nil || !current.valid() {
		return j.namespaceFailure(r, label, reasonNamespaceCheck, err)
	}
	if current != r.namespace() {
		return j.namespaceFailure(r, label, reasonNamespaceMismatch, nil)
	}
	if j.bound == (journalNamespace{}) {
		j.bound = r.namespace()
	}
	return nil
}

func (j *Journal) namespaceFailure(r journalRecord, label, reason string, cause error) error {
	j.namespaceFailed = true
	r.Phase, r.Reason = phaseQuarantine, reason
	// Preserve the original identity and operation exactly; never capture the
	// current/new namespace in a terminal record.
	writeErr := j.replace(r, label)
	return journalError("namespace-check", errors.Join(errors.New(reason), cause, writeErr))
}

func (j *Journal) transition(from, to, operation string, requireOwner bool) (err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	defer func() {
		if err != nil && j.failed == nil {
			j.failed = err
		}
	}()
	if j.closed || j.dir == nil || j.lock == nil {
		return journalError("transition", errors.New("closed journal"))
	}
	if j.failed != nil && to != phaseQuarantine {
		return journalError("transition", errors.New("handle has a latched failure"))
	}
	if requireOwner && j.ownedPhase != from {
		return journalError("transition", errors.New("handle does not own this live transition"))
	}
	if to == phaseIntent && !validJournalLabel(operation, 64) {
		return journalError("transition", errors.New("invalid operation label"))
	}
	return j.withLock(func() error {
		r, label, err := j.readRecord()
		if err != nil {
			return journalError("read-before-transition", err)
		}
		if j.namespaceFailed {
			return journalError("namespace-check", errors.New("namespace failure is terminal; rebuild-required"))
		}
		if r.Phase == phaseFresh && from != phaseFresh && to != phaseQuarantine {
			return journalError("transition", errors.New("fresh journal must first bind through GuardBootstrap"))
		}
		if from == phaseFresh && to == phaseGuarded && r.Phase == phaseFresh {
			current, err := j.ops.namespace()
			if err != nil || !current.valid() {
				return j.namespaceFailure(r, label, reasonNamespaceCheck, err)
			}
			r.bindNamespace(current)
			j.bound = current
		} else if r.Phase != phaseFresh || to != phaseQuarantine {
			if err := j.checkNamespace(r, label); err != nil {
				return err
			}
		}
		if to == phaseQuarantine && r.Phase == phaseQuarantine {
			j.ownedPhase = phaseQuarantine
			return nil
		}
		if to != phaseQuarantine && r.Phase != from {
			return journalError("transition", errors.New("phase cannot advance; retain quarantine fence"))
		}
		r.Phase = to
		if to == phaseQuarantine {
			r.Reason = reasonQuarantine
		}
		switch to {
		case phaseIntent:
			r.Operation = operation
		case phaseGuarded, phaseRunning:
			r.Operation = ""
		}
		if err := j.replace(r, label); err != nil {
			return err
		}
		j.ownedPhase = to
		return nil
	})
}

func (j *Journal) withLock(fn func() error) (err error) {
	if err := unix.Flock(int(j.lock.Fd()), unix.LOCK_EX); err != nil {
		return journalError("lock", err)
	}
	defer func() {
		if e := unix.Flock(int(j.lock.Fd()), unix.LOCK_UN); e != nil {
			err = errors.Join(err, journalError("unlock", e))
		}
	}()
	// Re-open the trusted path, but operate on the pinned directory. Replacing
	// a directory or stable lock inode must never create independent writers.
	current, err := j.ops.openDir(j.path)
	if err != nil {
		return journalError("revalidate-directory", err)
	}
	err = sameJournalInode(j.dir, current)
	err = errors.Join(err, j.ops.closeFile(current))
	if err != nil {
		return journalError("revalidate-directory", err)
	}
	if _, err := validateJournalFile(j.dir, j.lock, journalLockName, j.ops); err != nil {
		return journalError("revalidate-lock", err)
	}
	if err := j.ops.syncDir(j.dir); err != nil {
		return journalError("directory-sync-preflight", err)
	}
	return fn()
}

func (j *Journal) readRecord() (r journalRecord, label string, err error) {
	if err := validateJournalEntry(j.dir, journalRecordName, j.ops); err != nil {
		return r, "", err
	}
	f, err := j.ops.openFile(j.dir, journalRecordName, unix.O_RDONLY)
	if err != nil {
		return r, "", err
	}
	defer func() { err = errors.Join(err, j.ops.closeFile(f)) }()
	label, err = validateJournalFile(j.dir, f, journalRecordName, j.ops)
	if err != nil {
		return r, "", err
	}
	data, err := io.ReadAll(io.LimitReader(f, journalLimit+1))
	if err != nil {
		return r, "", err
	}
	r, err = decodeJournal(data, j.incarnation)
	return r, label, err
}

func writeJournalFile(f *os.File, data []byte, ops journalOps) error {
	n, err := ops.write(f, data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return ops.syncFile(f)
}

func (j *Journal) replace(r journalRecord, previousLabel string) (err error) {
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return journalError("temporary-name", err)
	}
	name := ".journal-" + hex.EncodeToString(suffix[:]) + ".tmp"
	f, err := j.ops.openFile(j.dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return journalError("temporary-create", err)
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, j.ops.closeFile(f))
		}
		// Cleanup never restores the old record. An uncertain rename may have
		// consumed the temp name; removing a leftover temp cannot undo it.
		if e := unix.Unlinkat(int(j.dir.Fd()), name, 0); e != nil && !errors.Is(e, unix.ENOENT) {
			err = errors.Join(err, journalError("temporary-cleanup", e))
		}
	}()
	label, err := validateJournalFile(j.dir, f, name, j.ops)
	if err != nil || label != previousLabel {
		return journalError("temporary-metadata", errors.Join(err, errors.New("replacement security metadata not confirmed")))
	}
	data, _ := json.Marshal(r)
	data = append(data, '\n')
	if err := writeJournalFile(f, data, j.ops); err != nil {
		return journalError("temporary-write-sync", err)
	}
	var expected unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &expected); err != nil {
		return journalError("temporary-identity", err)
	}
	closed = true
	if err := j.ops.closeFile(f); err != nil {
		return journalError("temporary-close", err)
	}
	// Inspect final metadata after close-for-write, before replacing authority.
	final, err := j.ops.openFile(j.dir, name, unix.O_RDONLY)
	if err != nil {
		return journalError("temporary-readback-open", err)
	}
	label, err = validateJournalFile(j.dir, final, name, j.ops)
	var actualTemp unix.Stat_t
	if err == nil {
		err = unix.Fstat(int(final.Fd()), &actualTemp)
	}
	if err == nil && !sameJournalFileIdentity(expected, actualTemp) {
		err = errors.New("temporary journal inode changed")
	}
	if err == nil && label != previousLabel {
		err = errors.New("replacement security label changed")
	}
	if err == nil {
		err = j.ops.syncFile(final)
	}
	err = errors.Join(err, j.ops.closeFile(final))
	if err != nil {
		return journalError("temporary-finalize", err)
	}
	if err := j.ops.rename(j.dir, name, journalRecordName); err != nil {
		return journalError("rename-outcome-unknown", err)
	}
	if err := j.ops.syncDir(j.dir); err != nil {
		return journalError("directory-sync-outcome-unknown", err)
	}
	actual, _, err := j.readRecord()
	if err != nil || actual != r {
		return journalError("readback-outcome-unknown", errors.Join(err, errors.New("record not confirmed")))
	}
	return nil
}

func (j *Journal) Close() (err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	if j.lock != nil {
		err = j.ops.closeFile(j.lock)
	}
	if j.dir != nil {
		err = errors.Join(err, j.ops.closeFile(j.dir))
	}
	if err != nil {
		j.failed = err
		return journalError("close", err)
	}
	return nil
}

func secureJournalDirectory(path string, uid, gid uint32) (_ *os.File, err error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, unix.Close(fd))
		}
	}()
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil {
			return nil, err
		}
		if (st.Uid != 0 && st.Uid != uid) || (st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0) {
			return nil, errors.New("untrusted journal directory ancestor")
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		e = unix.Close(fd)
		fd = next
		if e != nil {
			return nil, e
		}
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Uid != uid || st.Gid != gid || st.Mode&0o7777 != 0o700 || st.Nlink == 0 {
		return nil, errors.New("journal directory must be root-owned with mode 0700")
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil {
		return nil, err
	}
	if err = validateJournalFilesystem(fs); err != nil {
		return nil, err
	}
	for _, attr := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		_, e := unix.Fgetxattr(fd, attr, nil)
		if errors.Is(e, unix.ENODATA) || errors.Is(e, unix.ENOTSUP) {
			continue
		}
		if e != nil {
			return nil, e
		}
		return nil, errors.New("journal directory ACLs are unsupported")
	}
	if _, err = journalMountID(fd); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func validateJournalFilesystem(fs unix.Statfs_t) error {
	if fs.Flags&unix.ST_RDONLY != 0 {
		return errors.New("read-only journal filesystem")
	}
	switch fs.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.OVERLAYFS_SUPER_MAGIC:
		return nil
	default:
		return errors.New("journal requires a supported durable filesystem")
	}
}

func validateJournalEntry(dir *os.File, name string, ops journalOps) error {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o7777 != 0o600 || st.Nlink != 1 || st.Uid != ops.uid || st.Gid != ops.gid {
		return errors.New("journal files must be root-owned mode-0600 regular files with one link")
	}
	if st.Size > journalLimit || name == journalLockName && st.Size != 0 {
		return errors.New("invalid journal file size")
	}
	return nil
}

func validateJournalFile(dir, f *os.File, name string, ops journalOps) (string, error) {
	if err := validateJournalEntry(dir, name, ops); err != nil {
		return "", err
	}
	var entry, opened unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", err
	}
	if err := unix.Fstat(int(f.Fd()), &opened); err != nil {
		return "", err
	}
	if !sameJournalFileIdentity(opened, entry) {
		return "", errors.New("journal file changed during validation")
	}
	parentMount, err := journalMountID(int(dir.Fd()))
	if err != nil {
		return "", err
	}
	fileMount, err := journalMountID(int(f.Fd()))
	if err != nil || parentMount != fileMount {
		return "", errors.Join(err, errors.New("journal file mount differs from directory"))
	}
	return journalSecurityLabel(int(f.Fd()))
}

func sameJournalFileIdentity(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode &&
		a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size
}

func sameJournalInode(a, b *os.File) error {
	var x, y unix.Stat_t
	if err := unix.Fstat(int(a.Fd()), &x); err != nil {
		return err
	}
	if err := unix.Fstat(int(b.Fd()), &y); err != nil {
		return err
	}
	am, err := journalMountID(int(a.Fd()))
	if err != nil {
		return err
	}
	bm, err := journalMountID(int(b.Fd()))
	if err != nil {
		return err
	}
	if x.Dev != y.Dev || x.Ino != y.Ino || am != bm {
		return errors.New("journal directory identity changed")
	}
	return nil
}

func journalMountID(fd int) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &st); err == nil && st.Mask&unix.STATX_MNT_ID != 0 && st.Mnt_id != 0 {
		return st.Mnt_id, nil
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return 0, errors.New("journal mount identity unavailable")
	}
	var id uint64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "mnt_id:") {
			if id != 0 {
				return 0, errors.New("duplicate mount identity")
			}
			id, err = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")), 10, 64)
			if err != nil || id == 0 {
				return 0, errors.New("invalid mount identity")
			}
		}
	}
	if id == 0 {
		return 0, errors.New("journal mount identity unavailable")
	}
	return id, nil
}

// A replacement never copies ACLs, capabilities, arbitrary xattrs or integrity
// signatures. Only a kernel-assigned SELinux label with an exact match is allowed.
func journalSecurityLabel(fd int) (string, error) {
	n, err := unix.Flistxattr(fd, nil)
	if errors.Is(err, unix.ENOTSUP) {
		return "", nil
	}
	if err != nil || n < 0 || n > 65536 {
		return "", errors.Join(err, errors.New("cannot inspect journal attributes"))
	}
	if n == 0 {
		return "", nil
	}
	names := make([]byte, n)
	n, err = unix.Flistxattr(fd, names)
	if err != nil || n == 0 || n > len(names) || names[n-1] != 0 {
		return "", errors.Join(err, errors.New("invalid journal attributes"))
	}
	if string(names[:n]) != "security.selinux\x00" {
		return "", errors.New("journal ACL, capability, integrity or unknown attributes are unsupported")
	}
	label := make([]byte, 4096)
	n, err = unix.Fgetxattr(fd, "security.selinux", label)
	if err != nil || n == 0 || n > len(label) {
		return "", errors.Join(err, errors.New("invalid journal security label"))
	}
	return string(label[:n]), nil
}
