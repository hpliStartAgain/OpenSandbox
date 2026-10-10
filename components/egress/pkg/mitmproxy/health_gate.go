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

package mitmproxy

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
)

// HealthGate: /healthz stays 503 until MarkStackReady when transparent mitm is required (env enabled).
type HealthGate struct {
	required bool
	state    atomic.Uint64 // low bit is readiness; upper bits invalidate old restore tickets
}

func NewHealthGate() *HealthGate {
	required := constants.IsTruthy(os.Getenv(constants.EnvMitmproxyTransparent))
	g := &HealthGate{required: required}
	if !required {
		g.state.Store(1)
	}
	return g
}

func (g *HealthGate) MarkStackReady() {
	g.SetReady(true)
}

func (g *HealthGate) SetReady(v bool) {
	if g != nil {
		for {
			old := g.state.Load()
			next := (old &^ 1) + 2
			if v {
				next |= 1
			}
			if g.state.CompareAndSwap(old, next) {
				return
			}
		}
	}
}

// Pause returns a single-use restoration ticket. Any intervening readiness
// publication (including child exit/recovery) invalidates the ticket.
func (g *HealthGate) Pause() (uint64, bool) {
	if g == nil {
		return 0, false
	}
	for {
		old := g.state.Load()
		next := (old &^ 1) + 2
		if g.state.CompareAndSwap(old, next) {
			return next, old&1 != 0
		}
	}
}
func (g *HealthGate) RestoreReady(ticket uint64) bool {
	return g != nil && ticket != 0 && ticket&1 == 0 && g.state.CompareAndSwap(ticket, ticket|1)
}

func (g *HealthGate) MitmPending() bool {
	if g == nil {
		return false
	}
	return g.required && g.state.Load()&1 == 0
}

// WaitReady polls until the gate is ready, ctx is cancelled, or 30s elapses.
func (g *HealthGate) WaitReady(ctx context.Context) bool {
	deadline := time.After(30 * time.Second)
	for g.MitmPending() {
		select {
		case <-ctx.Done():
			return false
		case <-deadline:
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
	return true
}
