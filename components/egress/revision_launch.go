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

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/credentialvault"
	"github.com/alibaba/opensandbox/egress/pkg/mitmproxy"
	"github.com/alibaba/opensandbox/egress/pkg/revision"
	"github.com/alibaba/opensandbox/egress/pkg/revisionruntime"
)

const (
	defaultRevisionSessionParent   = "/run/opensandbox/egress-revisions"
	defaultRevisionMaxSnapshotSize = 8 << 20
)

type revisionMutationSession interface {
	Update(context.Context, credentialvault.ActiveSnapshot, int64) (revision.Identity, error)
	ReconcileUpdate(context.Context, revision.Identity) (bool, error)
}

type revisionProcessSession interface {
	revisionMutationSession
	MitmproxyConfig() (*mitmproxy.RevisionIPCConfig, error)
	Bootstrap(context.Context, credentialvault.ActiveSnapshot, int64) (revision.Identity, error)
	ReconcileBootstrap(context.Context) (*revision.Identity, error)
	Close() error
}

type revisionSnapshotSource func(context.Context) (credentialvault.ActiveSnapshot, int64, error)

// revisionBootstrapSnapshot reads the sidecar's current authoritative Vault
// state while policy mutations are excluded. Vault writes already wait on the
// mitm health gate, which remains pending throughout bootstrap. Policy epoch 0
// is reserved until policy/vault mutations join the revision transaction in a
// later OSEP-0023 phase.
func (s *policyServer) revisionBootstrapSnapshot(
	ctx context.Context,
) (credentialvault.ActiveSnapshot, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.credentialVault == nil {
		return credentialvault.ActiveSnapshot{}, 0, revision.ErrTransportUnavailable
	}
	snapshot, err := s.credentialVault.ActiveSnapshotWithContext(ctx)
	if errors.Is(err, credentialvault.ErrNotFound) {
		return credentialvault.ActiveSnapshot{}, 0, nil
	}
	return snapshot, 0, err
}

// revisionLaunchOwner binds one fresh revision session to one mitmdump child.
// The caller must retain the returned session until that exact child exits.
type revisionLaunchOwner struct {
	config     revisionruntime.ProcessSessionConfig
	newSession func(revisionruntime.ProcessSessionConfig) (revisionProcessSession, error)
	snapshot   revisionSnapshotSource
	stop       func(*mitmproxy.Running)
}

func (o *revisionLaunchOwner) launch(
	ctx context.Context,
	cfg mitmproxy.Config,
	launch func(mitmproxy.Config) (*mitmproxy.Running, error),
) (*mitmproxy.Running, revisionProcessSession, error) {
	if o == nil || o.newSession == nil || o.snapshot == nil || o.stop == nil || launch == nil ||
		cfg.RevisionIPC != nil {
		return nil, nil, revision.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	snapshot, policyEpoch, err := o.snapshot(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, fmt.Errorf("revision bootstrap snapshot: %w", revision.ErrTransportUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	session, err := o.newSession(o.config)
	if err != nil {
		return nil, nil, fmt.Errorf("revision session: %w", err)
	}
	closeSession := func() error {
		if err := session.Close(); err != nil {
			return fmt.Errorf("revision session cleanup: %w", err)
		}
		return nil
	}

	childConfig, err := session.MitmproxyConfig()
	if err != nil {
		if cleanupErr := closeSession(); cleanupErr != nil {
			return nil, nil, cleanupErr
		}
		return nil, nil, fmt.Errorf("revision session handoff: %w", err)
	}
	cfg.RevisionIPC = childConfig
	running, err := launch(cfg)
	if err != nil {
		if cleanupErr := closeSession(); cleanupErr != nil {
			return nil, nil, cleanupErr
		}
		return nil, nil, err
	}
	if running == nil {
		if cleanupErr := closeSession(); cleanupErr != nil {
			return nil, nil, cleanupErr
		}
		return nil, nil, revision.ErrTransportUnavailable
	}
	fail := func(cause error) (*mitmproxy.Running, revisionProcessSession, error) {
		o.stop(running)
		if err := closeSession(); err != nil {
			return nil, nil, err
		}
		return nil, nil, cause
	}

	for {
		if _, err := session.Bootstrap(ctx, snapshot, policyEpoch); err == nil {
			return running, session, nil
		} else if !errors.Is(err, revision.ErrIndeterminate) {
			return fail(fmt.Errorf("revision bootstrap: %w", err))
		}

		resolved, err := session.ReconcileBootstrap(ctx)
		if err != nil {
			return fail(fmt.Errorf("revision bootstrap reconcile: %w", err))
		}
		if resolved != nil {
			return running, session, nil
		}
	}
}

func newRevisionProcessSession(
	config revisionruntime.ProcessSessionConfig,
) (revisionProcessSession, error) {
	return revisionruntime.NewProcessSession(config)
}

func newSidecarRevisionLaunchOwner(server *policyServer) (*revisionLaunchOwner, error) {
	if !constants.IsTruthy(os.Getenv(constants.EnvExperimentalRevisionRuntime)) {
		return nil, nil
	}
	if server == nil {
		return nil, revision.ErrInvalid
	}
	uid, gid, _, err := mitmproxy.LookupUser(mitmproxy.RunAsUser)
	if err != nil {
		return nil, fmt.Errorf("revision runtime user: %w", revision.ErrInvalid)
	}
	if err := os.MkdirAll(defaultRevisionSessionParent, 0o711); err != nil {
		return nil, fmt.Errorf("revision runtime parent: %w", revision.ErrTransportUnavailable)
	}
	if err := os.Chmod(defaultRevisionSessionParent, 0o711); err != nil {
		return nil, fmt.Errorf("revision runtime parent: %w", revision.ErrTransportUnavailable)
	}
	subjectGeneration, err := revision.NewSessionToken()
	if err != nil {
		return nil, fmt.Errorf("revision runtime generation: %w", revision.ErrTransportUnavailable)
	}
	return &revisionLaunchOwner{
		config: revisionruntime.ProcessSessionConfig{
			ParentDir:         defaultRevisionSessionParent,
			UID:               int(uid),
			GID:               int(gid),
			SubjectGeneration: subjectGeneration,
			MaxSnapshotBytes:  defaultRevisionMaxSnapshotSize,
		},
		newSession: newRevisionProcessSession,
		snapshot:   server.revisionBootstrapSnapshot,
		stop: func(running *mitmproxy.Running) {
			mitmproxy.GracefulShutdown(running, time.Second)
		},
	}, nil
}
