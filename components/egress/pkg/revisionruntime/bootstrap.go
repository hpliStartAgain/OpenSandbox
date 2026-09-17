// Copyright 2026 Alibaba Group Holding Ltd.
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

package revisionruntime

import (
	"context"

	"github.com/alibaba/opensandbox/egress/pkg/credentialvault"
	"github.com/alibaba/opensandbox/egress/pkg/revision"
)

type bootstrapState uint8

const (
	bootstrapIdle bootstrapState = iota
	bootstrapRunning
	bootstrapComplete
)

// Bootstrap installs one authoritative empty or restored decision snapshot on
// a fresh receiver. It is intentionally one-shot for each ProcessSession: a
// receiver that already reports an active identity is indeterminate, not fresh.
func (s *ProcessSession) Bootstrap(
	ctx context.Context,
	snapshot credentialvault.ActiveSnapshot,
	effectivePolicyEpoch int64,
) (identity revision.Identity, resultErr error) {
	coordinator, err := s.Coordinator()
	if err != nil {
		return revision.Identity{}, err
	}
	if err := ctx.Err(); err != nil {
		return revision.Identity{}, err
	}
	if err := s.beginBootstrap(); err != nil {
		return revision.Identity{}, err
	}
	committed := false
	defer func() { s.finishBootstrap(committed, resultErr) }()

	payload, err := credentialvault.MarshalDecisionSnapshot(snapshot, effectivePolicyEpoch)
	if err != nil {
		return revision.Identity{}, err
	}
	if err := s.WaitReady(ctx); err != nil {
		return revision.Identity{}, err
	}
	identity, err = coordinator.Apply(ctx, snapshot.Revision, effectivePolicyEpoch, payload)
	if err != nil {
		return revision.Identity{}, err
	}
	committed = true
	confirmed, err := coordinator.Confirmed()
	if err != nil {
		return revision.Identity{}, err
	}
	if confirmed == nil || *confirmed != identity {
		return revision.Identity{}, revision.ErrIndeterminate
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return revision.Identity{}, revision.ErrClosed
	}
	if !s.parentPathMatches() {
		return revision.Identity{}, revision.ErrTransportUnavailable
	}
	return identity, nil
}

func (s *ProcessSession) beginBootstrap() error {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	switch s.bootstrap {
	case bootstrapIdle:
		s.bootstrap = bootstrapRunning
		return nil
	case bootstrapRunning:
		return revision.ErrBusy
	default:
		return revision.ErrIndeterminate
	}
}

func (s *ProcessSession) finishBootstrap(committed bool, err error) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	if committed || err == nil {
		s.bootstrap = bootstrapComplete
	} else {
		s.bootstrap = bootstrapIdle
	}
}
