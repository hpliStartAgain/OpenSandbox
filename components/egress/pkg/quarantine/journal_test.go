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
	"strings"
	"testing"
)

func TestJournalStrictSchema(t *testing.T) {
	valid := `{"version":2,"incarnation":"sandbox-123","phase":"fresh","operation":"","bootID":"","netnsDev":0,"netnsInode":0,"reason":""}`
	bound := strings.Replace(strings.Replace(strings.Replace(valid, `"bootID":""`, `"bootID":"11111111-2222-3333-4444-555555555555"`, 1), `"netnsDev":0`, `"netnsDev":4`, 1), `"netnsInode":0`, `"netnsInode":123`, 1)
	for _, input := range []string{
		valid,
		strings.Replace(bound, `"fresh"`, `"guarded"`, 1),
		strings.Replace(bound, `"fresh"`, `"running"`, 1),
		strings.Replace(strings.Replace(bound, `"fresh"`, `"quarantine"`, 1), `"reason":""`, `"reason":"quarantine/rebuild-required"`, 1),
		strings.Replace(strings.Replace(bound, `"fresh"`, `"intent"`, 1), `"operation":""`, `"operation":"bootstrap"`, 1),
		strings.Replace(strings.Replace(bound, `"fresh"`, `"committed"`, 1), `"operation":""`, `"operation":"policy-update"`, 1),
	} {
		if _, err := decodeJournal([]byte(input), "sandbox-123"); err != nil {
			t.Errorf("valid record rejected: %v", err)
		}
	}
	invalid := map[string]string{
		"empty": "", "array": "[]", "null": "null", "truncated": valid[:len(valid)-1],
		"missing operation":           strings.Replace(valid, `,"operation":""`, "", 1),
		"duplicate version":           strings.Replace(valid, `"version":2`, `"version":2,"version":2`, 1),
		"duplicate escaped field":     strings.Replace(valid, `"version":2`, `"version":2,"\u0076ersion":2`, 1),
		"unknown field":               strings.Replace(valid, `"version":2`, `"version":2,"secret":"unused"`, 1),
		"unsupported version":         strings.Replace(valid, `"version":2`, `"version":1`, 1),
		"fractional version":          strings.Replace(valid, `"version":2`, `"version":2.0`, 1),
		"null version":                strings.Replace(valid, `"version":2`, `"version":null`, 1),
		"string version":              strings.Replace(valid, `"version":2`, `"version":"2"`, 1),
		"null operation":              strings.Replace(valid, `"operation":""`, `"operation":null`, 1),
		"numeric operation":           strings.Replace(valid, `"operation":""`, `"operation":0`, 1),
		"wrong incarnation":           strings.Replace(valid, "sandbox-123", "sandbox-other", 1),
		"empty incarnation":           strings.Replace(valid, "sandbox-123", "", 1),
		"unknown phase":               strings.Replace(valid, "fresh", "recoverable", 1),
		"idle operation":              strings.Replace(valid, `"operation":""`, `"operation":"bootstrap"`, 1),
		"missing intent operation":    strings.Replace(valid, "fresh", "intent", 1),
		"missing committed operation": strings.Replace(valid, "fresh", "committed", 1),
		"trailing object":             valid + "{}", "trailing junk": valid + "oops",
		"oversized":                   valid + strings.Repeat(" ", journalLimit),
		"legacy four-field v1":        `{"version":1,"incarnation":"sandbox-123","phase":"fresh","operation":""}`,
		"missing boot ID":             strings.Replace(valid, `,"bootID":""`, "", 1),
		"missing namespace device":    strings.Replace(valid, `,"netnsDev":0`, "", 1),
		"missing namespace inode":     strings.Replace(valid, `,"netnsInode":0`, "", 1),
		"missing reason":              strings.Replace(valid, `,"reason":""`, "", 1),
		"null boot ID":                strings.Replace(valid, `"bootID":""`, `"bootID":null`, 1),
		"null namespace device":       strings.Replace(valid, `"netnsDev":0`, `"netnsDev":null`, 1),
		"string namespace inode":      strings.Replace(valid, `"netnsInode":0`, `"netnsInode":"0"`, 1),
		"negative namespace inode":    strings.Replace(valid, `"netnsInode":0`, `"netnsInode":-1`, 1),
		"fractional namespace device": strings.Replace(valid, `"netnsDev":0`, `"netnsDev":4.0`, 1),
		"overflow namespace inode":    strings.Replace(valid, `"netnsInode":0`, `"netnsInode":18446744073709551616`, 1),
		"partially bound":             strings.Replace(valid, `"netnsDev":0`, `"netnsDev":4`, 1),
		"fresh already bound":         bound,
		"guarded unbound":             strings.Replace(valid, `"fresh"`, `"guarded"`, 1),
		"invalid boot ID":             strings.Replace(strings.Replace(bound, `"fresh"`, `"guarded"`, 1), "11111111-2222-3333-4444-555555555555", "not-a-boot-id", 1),
		"uppercase boot ID":           strings.Replace(strings.Replace(bound, `"fresh"`, `"guarded"`, 1), "11111111-2222-3333-4444-555555555555", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", 1),
		"zero boot ID":                strings.Replace(strings.Replace(bound, `"fresh"`, `"guarded"`, 1), "11111111-2222-3333-4444-555555555555", "00000000-0000-0000-0000-000000000000", 1),
		"nonterminal reason":          strings.Replace(valid, `"reason":""`, `"reason":"quarantine/rebuild-required"`, 1),
		"quarantine missing reason":   strings.Replace(bound, `"fresh"`, `"quarantine"`, 1),
		"unknown terminal reason":     strings.Replace(strings.Replace(bound, `"fresh"`, `"quarantine"`, 1), `"reason":""`, `"reason":"recoverable"`, 1),
		"unbound mismatch":            strings.Replace(strings.Replace(valid, `"fresh"`, `"quarantine"`, 1), `"reason":""`, `"reason":"namespace-mismatch/rebuild-required"`, 1),
	}
	for name, input := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeJournal([]byte(input), "sandbox-123"); err == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
}

func TestJournalMetadataLabels(t *testing.T) {
	for _, s := range []string{"", "label with spaces", "header:secret", "a/b", "a\n", "é", strings.Repeat("a", 129)} {
		if validJournalLabel(s, 128) {
			t.Errorf("invalid label accepted: %q", s)
		}
	}
	for _, s := range []string{"incarnation-123", "policy.replace", "bootstrap", "vault_rotate_2"} {
		if !validJournalLabel(s, 128) {
			t.Errorf("valid label rejected: %q", s)
		}
	}
}
