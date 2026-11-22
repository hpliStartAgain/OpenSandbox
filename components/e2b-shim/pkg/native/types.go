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

// Package native implements the HTTP client boundary for OpenSandbox's /v1
// lifecycle API with verbatim native states, explicit outcome classification,
// and credential/routing-header redaction.
package native

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"time"
)

const redacted = "[REDACTED]"

type State string

const (
	StatePending    State = "Pending"
	StateRunning    State = "Running"
	StatePausing    State = "Pausing"
	StatePaused     State = "Paused"
	StateResuming   State = "Resuming"
	StateStopping   State = "Stopping"
	StateTerminated State = "Terminated"
	StateFailed     State = "Failed"
	StateUnknown    State = "Unknown"
)

func ParseState(raw string) State {
	switch State(raw) {
	case StatePending, StateRunning, StatePausing, StatePaused,
		StateResuming, StateStopping, StateTerminated, StateFailed:
		return State(raw)
	default:
		return StateUnknown
	}
}

type SandboxStatus struct {
	State            State
	RawState         string
	Reason, Message  string
	LastTransitionAt *time.Time
}

type CreateTemplateSandboxRequest struct {
	TemplateID     string
	TimeoutSeconds int64
	Metadata       map[string]string
}

type CreateSandboxResult struct {
	ID                   string
	Status               SandboxStatus
	Metadata, Extensions map[string]string
	ExpiresAt            *time.Time
	CreatedAt            time.Time
	Entrypoint           []string
}

type Sandbox struct {
	ID                   string
	Status               SandboxStatus
	Metadata, Extensions map[string]string
	ExpiresAt            *time.Time
	CreatedAt            time.Time
	Entrypoint           []string
}

type Endpoint struct {
	URL     string
	Headers map[string]string
}

func (e Endpoint) String() string {
	return fmt.Sprintf("Endpoint{URL:%q, Headers:%s}", e.URL, redacted)
}
func (e Endpoint) GoString() string             { return e.String() }
func (e Endpoint) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, e.String()) }
func (e Endpoint) MarshalText() ([]byte, error) { return []byte(e.String()), nil }

func (e Endpoint) MarshalJSON() ([]byte, error) {
	hdrs := make(map[string]string, len(e.Headers))
	for k := range e.Headers {
		hdrs[k] = redacted
	}
	return json.Marshal(struct {
		Endpoint string            `json:"endpoint"`
		Headers  map[string]string `json:"headers"`
	}{Endpoint: e.URL, Headers: hdrs})
}

func (e Endpoint) LogValue() slog.Value {
	if len(e.Headers) == 0 {
		return slog.GroupValue(slog.String("endpoint", e.URL), slog.String("headers", redacted))
	}
	keys := slices.Sorted(maps.Keys(e.Headers))
	attrs := make([]slog.Attr, len(keys))
	for i, k := range keys {
		attrs[i] = slog.String(k, redacted)
	}
	return slog.GroupValue(slog.String("endpoint", e.URL), slog.Any("headers", slog.GroupValue(attrs...)))
}

type MetadataPatch map[string]*string

type RenewExpirationResult struct {
	ExpiresAt time.Time
}

type ListSandboxesRequest struct {
	States         []State
	Metadata       map[string]string
	Page, PageSize int
}

type PaginationInfo struct {
	Page, PageSize, TotalItems, TotalPages int
	HasNextPage                            bool
}

type ListSandboxesResult struct {
	Items      []Sandbox
	Pagination PaginationInfo
}

type Lifecycle interface {
	CreateTemplateSandbox(ctx context.Context, req CreateTemplateSandboxRequest) (*CreateSandboxResult, error)
	GetSandbox(ctx context.Context, sandboxID string) (*Sandbox, error)
	DeleteSandbox(ctx context.Context, sandboxID string) error
	GetEndpoint(ctx context.Context, sandboxID string, port int) (*Endpoint, error)
	PatchMetadata(ctx context.Context, sandboxID string, patch MetadataPatch) (*Sandbox, error)
	PauseSandbox(ctx context.Context, sandboxID string) error
	ResumeSandbox(ctx context.Context, sandboxID string) error
	RenewExpiration(ctx context.Context, sandboxID string, expiresAt time.Time) (*RenewExpirationResult, error)
	ListSandboxes(ctx context.Context, req ListSandboxesRequest) (*ListSandboxesResult, error)
}
