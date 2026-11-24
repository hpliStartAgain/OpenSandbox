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

// Package adapter implements the Gate 1a OSEP-0027 E2B control-plane HTTP
// routes under the configured compatibility prefix.
package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
)

const (
	// EnvdPort is the in-sandbox envd daemon port resolved via GetEndpoint.
	EnvdPort = 49983
	redacted = "[REDACTED]"
)

var (
	ErrEnvdInitNotConfigured  = errors.New("adapter: envd initializer is not configured")
	ErrAdmissionUninitialized = errors.New("adapter: cannot open admission for uninitialized sandbox")
	ErrInvalidAdmissionRecord = errors.New("adapter: invalid admission record")
)

// EnvdInitRequest carries parameters for private envd /init bootstrap.
// All formatting, marshaling, and logging paths redact Endpoint, AccessToken, and EnvVars.
type EnvdInitRequest struct {
	SandboxID, AccessToken, ExpectedEnvdVersion string
	Endpoint                                    *native.Endpoint
	EnvVars                                     map[string]string
}

func (r EnvdInitRequest) String() string {
	return fmt.Sprintf("EnvdInitRequest{SandboxID:%q, ExpectedEnvdVersion:%q, Endpoint:%s, AccessToken:%s, EnvVars:%s}",
		r.SandboxID, r.ExpectedEnvdVersion, redacted, redacted, redacted)
}
func (r EnvdInitRequest) GoString() string             { return r.String() }
func (r EnvdInitRequest) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, r.String()) }
func (r EnvdInitRequest) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r EnvdInitRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SandboxID           string `json:"sandboxId"`
		ExpectedEnvdVersion string `json:"expectedEnvdVersion"`
		Endpoint            string `json:"endpoint"`
		AccessToken         string `json:"accessToken"`
		EnvVars             string `json:"envVars"`
	}{r.SandboxID, r.ExpectedEnvdVersion, redacted, redacted, redacted})
}

func (r EnvdInitRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("sandbox_id", r.SandboxID),
		slog.String("expected_envd_version", r.ExpectedEnvdVersion),
		slog.String("endpoint", redacted),
		slog.String("access_token", redacted),
		slog.String("env_vars", redacted),
	)
}

// EnvdInitResult reports the actual envd version observed during /init.
type EnvdInitResult struct {
	EnvdVersion string
}

// EnvdInitializer performs private envd /init bootstrap after native readiness.
type EnvdInitializer interface {
	Initialize(ctx context.Context, req EnvdInitRequest) (*EnvdInitResult, error)
}

// AdmissionRecord describes an initialized E2B sandbox admitted for routing.
type AdmissionRecord struct {
	SandboxID, TemplateRevision, EnvdVersion string
	Initialized                              bool
}

// AdmissionController gates E2B data-plane admission per sandbox.
type AdmissionController interface {
	Open(ctx context.Context, rec AdmissionRecord) error
	Close(ctx context.Context, sandboxID string) error
	IsOpen(ctx context.Context, sandboxID string) (bool, error)
}

// UnconfiguredEnvdInitializer fails closed with ErrEnvdInitNotConfigured.
type UnconfiguredEnvdInitializer struct{}

func (UnconfiguredEnvdInitializer) Initialize(context.Context, EnvdInitRequest) (*EnvdInitResult, error) {
	return nil, ErrEnvdInitNotConfigured
}

// MemoryAdmissionController is a thread-safe in-memory AdmissionController
// rejecting Open unless rec.Initialized is true.
type MemoryAdmissionController struct {
	mu      sync.RWMutex
	records map[string]AdmissionRecord
}

func NewMemoryAdmissionController() *MemoryAdmissionController {
	return &MemoryAdmissionController{records: make(map[string]AdmissionRecord)}
}

func (m *MemoryAdmissionController) Open(ctx context.Context, rec AdmissionRecord) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if !rec.Initialized {
		return ErrAdmissionUninitialized
	}
	if rec.SandboxID == "" || rec.TemplateRevision == "" || rec.EnvdVersion == "" {
		return ErrInvalidAdmissionRecord
	}
	m.mu.Lock()
	m.records[rec.SandboxID] = rec
	m.mu.Unlock()
	return nil
}

func (m *MemoryAdmissionController) Close(ctx context.Context, sandboxID string) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if sandboxID == "" {
		return ErrInvalidAdmissionRecord
	}
	m.mu.Lock()
	delete(m.records, sandboxID)
	m.mu.Unlock()
	return nil
}

func (m *MemoryAdmissionController) IsOpen(ctx context.Context, sandboxID string) (bool, error) {
	if ctx != nil && ctx.Err() != nil {
		return false, ctx.Err()
	}
	m.mu.RLock()
	rec, ok := m.records[sandboxID]
	m.mu.RUnlock()
	return ok && rec.Initialized, nil
}
