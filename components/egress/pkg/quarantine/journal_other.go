//go:build !linux

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

import "errors"

// Journal is unsupported outside the Linux sidecar runtime.
type Journal struct{}

func journalPlatformError() error {
	return journalError("platform", errors.New("durable quarantine requires Linux"))
}

func Provision(string, string) error               { return journalPlatformError() }
func OpenJournal(string, string) (*Journal, error) { return nil, journalPlatformError() }
func (*Journal) GuardBootstrap() error             { return journalPlatformError() }
func (*Journal) StartBootstrap() error             { return journalPlatformError() }
func (*Journal) Begin(string) error                { return journalPlatformError() }
func (*Journal) Commit() error                     { return journalPlatformError() }
func (*Journal) Running() error                    { return journalPlatformError() }
func (*Journal) Quarantine() error                 { return journalPlatformError() }
func (*Journal) CheckNamespace() error             { return journalPlatformError() }
func (*Journal) Close() error                      { return journalPlatformError() }
