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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	journalRecordName       = "journal.json"
	journalLockName         = "journal.lock"
	journalVersion          = 2
	journalLimit            = 4096
	phaseFresh              = "fresh"
	phaseGuarded            = "guarded"
	phaseIntent             = "intent"
	phaseCommitted          = "committed"
	phaseRunning            = "running"
	phaseQuarantine         = "quarantine"
	reasonQuarantine        = "quarantine/rebuild-required"
	reasonNamespaceMismatch = "namespace-mismatch/rebuild-required"
	reasonNamespaceCheck    = "namespace-check-failed/rebuild-required"
	reasonNamespaceUnbound  = "namespace-unbound/rebuild-required"
)

// ErrJournalUnsafe means the caller must retain its network fence. It never
// authorizes restoring previous state, restarting the worker, or replaying work.
var ErrJournalUnsafe = errors.New("quarantine journal unavailable or unsafe")

// journalRecord contains lifecycle metadata only: never credentials, policy
// payloads, or instructions which could be replayed after a restart.
type journalRecord struct {
	Version     int    `json:"version"`
	Incarnation string `json:"incarnation"`
	Phase       string `json:"phase"`
	Operation   string `json:"operation"`
	BootID      string `json:"bootID"`
	NetnsDev    uint64 `json:"netnsDev"`
	NetnsInode  uint64 `json:"netnsInode"`
	Reason      string `json:"reason"`
}

type journalNamespace struct {
	bootID     string
	dev, inode uint64
}

func (r journalRecord) namespace() journalNamespace {
	return journalNamespace{bootID: r.BootID, dev: r.NetnsDev, inode: r.NetnsInode}
}

func (r *journalRecord) bindNamespace(n journalNamespace) {
	r.BootID, r.NetnsDev, r.NetnsInode = n.bootID, n.dev, n.inode
}

func (n journalNamespace) valid() bool {
	if len(n.bootID) != 36 || n.bootID == "00000000-0000-0000-0000-000000000000" || n.dev == 0 || n.inode == 0 {
		return false
	}
	for i, c := range n.bootID {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func journalError(action string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrJournalUnsafe, action, err)
}

func validJournalLabel(s string, limit int) bool {
	if len(s) == 0 || len(s) > limit {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// decodeJournal rejects duplicate, missing, unknown, null and wrongly typed
// fields as well as trailing JSON. Ordinary struct decoding accepts duplicate
// fields and null strings, which is too permissive for this restart boundary.
func decodeJournal(data []byte, incarnation string) (journalRecord, error) {
	var r journalRecord
	if len(data) > journalLimit {
		return r, errors.New("record exceeds size limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return r, errors.New("record must be an object")
	}
	fields := make(map[string]json.RawMessage, 8)
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return r, errors.New("invalid record field")
		}
		name, ok := token.(string)
		if !ok || fields[name] != nil {
			return r, errors.New("invalid or duplicate record field")
		}
		switch name {
		case "version", "incarnation", "phase", "operation", "bootID", "netnsDev", "netnsInode", "reason":
		default:
			return r, errors.New("unknown record field")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return r, errors.New("invalid record value")
		}
		fields[name] = value
	}
	if _, err = d.Token(); err != nil || len(fields) != 8 {
		return r, errors.New("incomplete record")
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return r, errors.New("trailing record content")
	}
	if json.Unmarshal(fields["version"], &r.Version) != nil ||
		json.Unmarshal(fields["incarnation"], &r.Incarnation) != nil ||
		json.Unmarshal(fields["phase"], &r.Phase) != nil ||
		json.Unmarshal(fields["operation"], &r.Operation) != nil ||
		json.Unmarshal(fields["bootID"], &r.BootID) != nil ||
		json.Unmarshal(fields["netnsDev"], &r.NetnsDev) != nil ||
		json.Unmarshal(fields["netnsInode"], &r.NetnsInode) != nil ||
		json.Unmarshal(fields["reason"], &r.Reason) != nil {
		return r, errors.New("invalid record field type")
	}
	if r.Version != journalVersion || !validJournalLabel(r.Incarnation, 128) || r.Incarnation != incarnation {
		return r, errors.New("unsupported schema or incarnation mismatch")
	}
	switch r.Phase {
	case phaseFresh, phaseGuarded, phaseRunning:
		if r.Operation != "" {
			return r, errors.New("idle phase has an operation")
		}
	case phaseIntent, phaseCommitted:
		if !validJournalLabel(r.Operation, 64) {
			return r, errors.New("active phase requires an operation label")
		}
	case phaseQuarantine:
		if r.Operation != "" && !validJournalLabel(r.Operation, 64) {
			return r, errors.New("invalid quarantine operation label")
		}
	default:
		return r, errors.New("unknown record phase")
	}
	n := r.namespace()
	if n != (journalNamespace{}) && !n.valid() {
		return r, errors.New("invalid namespace identity")
	}
	if r.Phase == phaseFresh {
		if n != (journalNamespace{}) {
			return r, errors.New("fresh record must be unbound")
		}
	} else if r.Phase != phaseQuarantine && !n.valid() {
		return r, errors.New("active record requires a bound namespace identity")
	}
	if r.Phase != phaseQuarantine {
		if r.Reason != "" {
			return r, errors.New("non-quarantine record has a terminal reason")
		}
	} else {
		switch r.Reason {
		case reasonQuarantine, reasonNamespaceCheck:
		case reasonNamespaceUnbound:
			if n != (journalNamespace{}) {
				return r, errors.New("unbound namespace reason cannot have a bound identity")
			}
		case reasonNamespaceMismatch:
			if !n.valid() {
				return r, errors.New("namespace mismatch requires the original bound identity")
			}
		default:
			return r, errors.New("quarantine record requires a supported terminal reason")
		}
		if n == (journalNamespace{}) && r.Operation != "" {
			return r, errors.New("unbound quarantine record cannot have an active operation")
		}
	}
	return r, nil
}
