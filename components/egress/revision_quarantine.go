// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/quarantine"
)

const quarantineDirectory = "/var/lib/opensandbox-egress/quarantine"
const quarantineIdentityEnv = "OPENSANDBOX_EGRESS_QUARANTINE_ID"

type packetQuarantineState uint32

const (
	quarantineUnknown packetQuarantineState = iota
	quarantineConfirmed
	quarantineOpen
)

func (p packetQuarantineState) String() string {
	switch p {
	case quarantineConfirmed:
		return "QuarantineConfirmed"
	case quarantineOpen:
		return "Running"
	default:
		return "QuarantineUnknown"
	}
}

type quarantineFence interface {
	Ensure(context.Context) error
	Remove(context.Context) error
}
type quarantineJournal interface {
	CheckNamespace() error
	StartBootstrap() error
	Begin(string) error
	Commit() error
	Running() error
	Quarantine() error
	Close() error
}

// The journal proves lifecycle provenance, never policy or credential contents.
// No operation here restores a previous generation or clears recovery.
type revisionQuarantine struct {
	fence   quarantineFence
	journal quarantineJournal
	state   atomic.Uint32
}

// guardCurrent never proves containment of the original sandbox namespace.
func (q *revisionQuarantine) guardCurrent() error {
	q.state.Store(uint32(quarantineUnknown))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := q.fence.Ensure(ctx); err != nil {
		return err
	}
	return nil
}
func (q *revisionQuarantine) ensure() error {
	if err := q.guardCurrent(); err != nil {
		return err
	}
	if q.journal == nil {
		return errors.New("original namespace identity unavailable; rebuild-required")
	}
	if err := q.journal.CheckNamespace(); err != nil {
		return err
	}
	q.state.Store(uint32(quarantineConfirmed))
	return nil
}
func (q *revisionQuarantine) contain() error {
	err := q.ensure()
	if q.journal != nil {
		err = errors.Join(err, q.journal.Quarantine())
	}
	log.Warnf("experimental recovery: packet isolation=%s; rebuild-required; containment error=%v", packetQuarantineState(q.state.Load()), err)
	return err
}
func (q *revisionQuarantine) begin(operation string) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	if err := q.journal.Begin(operation + "-" + hex.EncodeToString(nonce[:])); err != nil {
		return err
	}
	return q.ensure()
}
func (q *revisionQuarantine) finish() error {
	quarantineCheckpoint("before-commit")
	if err := q.journal.Commit(); err != nil {
		return err
	}
	quarantineCheckpoint("after-commit")
	// Persist final ownership before removing the fence. Neither committed nor
	// running is replayable by a later process, even if removal was never tried.
	if err := q.journal.Running(); err != nil {
		return err
	}
	q.state.Store(uint32(quarantineUnknown))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := q.journal.CheckNamespace(); err != nil {
		return err
	}
	quarantineCheckpoint("before-unfence")
	if err := q.fence.Remove(ctx); err != nil {
		return err
	}
	quarantineCheckpoint("after-unfence")
	if err := q.journal.CheckNamespace(); err != nil {
		return err
	}
	q.state.Store(uint32(quarantineOpen))
	return nil
}
func beginSidecarQuarantine() (*revisionQuarantine, error) {
	if !constants.IsTruthy(os.Getenv(constants.EnvExperimentalRevisionRuntime)) {
		return nil, nil
	}
	if err := validateQuarantineProfile(); err != nil {
		return nil, err
	}
	q := &revisionQuarantine{fence: quarantine.NewFence()}
	// Even malformed lifecycle input first attempts containment; nothing else
	// may remove redirects or run a worker on a failed check.
	if err := q.guardCurrent(); err != nil {
		return nil, fmt.Errorf("QuarantineUnknown: %w", err)
	}
	if !constants.ModeUsesNft(parseMode()) || !constants.IsTruthy(os.Getenv(constants.EnvMitmproxyTransparent)) {
		return nil, errors.New("experimental quarantine requires sidecar dns+nft and transparent MITM")
	}
	journal, err := quarantine.OpenJournal(quarantineDirectory, os.Getenv(quarantineIdentityEnv))
	if err != nil {
		return nil, fmt.Errorf("QuarantineUnknown: rebuild-required: %w", err)
	}
	q.journal = journal
	if err := q.ensure(); err != nil {
		_ = journal.Quarantine()
		_ = journal.Close()
		return nil, fmt.Errorf("QuarantineUnknown: rebuild-required: %w", err)
	}
	quarantineCheckpoint("before-intent")
	if err := journal.StartBootstrap(); err != nil {
		_ = journal.Close()
		return nil, fmt.Errorf("%s: rebuild-required: %w", packetQuarantineState(q.state.Load()), err)
	}
	quarantineCheckpoint("after-intent")
	return q, nil
}

// runQuarantineCommand executes only explicit lifecycle commands. Provision is
// invoked by the trusted Docker owner in an isolated one-shot helper, never by
// normal prestart. An environment variable cannot grant first-create authority.
func runQuarantineCommand() (bool, error) {
	if len(os.Args) != 2 {
		return false, nil
	}
	switch os.Args[1] {
	case "--provision-quarantine":
		info, err := os.Lstat(quarantineDirectory)
		if err != nil {
			return true, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return true, errors.New("invalid quarantine directory")
		}
		if err := os.Chmod(quarantineDirectory, 0700); err != nil {
			return true, err
		}
		return true, quarantine.Provision(quarantineDirectory, os.Getenv(quarantineIdentityEnv))
	case "--guard-quarantine":
		if !constants.IsTruthy(os.Getenv(constants.EnvExperimentalRevisionRuntime)) {
			return true, nil
		}
		if err := validateQuarantineProfile(); err != nil {
			return true, err
		}
		q := &revisionQuarantine{fence: quarantine.NewFence()}
		if err := q.guardCurrent(); err != nil {
			return true, fmt.Errorf("QuarantineUnknown: %w", err)
		}
		journal, err := quarantine.OpenJournal(quarantineDirectory, os.Getenv(quarantineIdentityEnv))
		if err != nil {
			return true, fmt.Errorf("QuarantineUnknown: rebuild-required: %w", err)
		}
		defer journal.Close()
		q.journal = journal
		guardErr := journal.GuardBootstrap()
		confirmErr := q.ensure()
		if err := errors.Join(guardErr, confirmErr); err != nil {
			return true, fmt.Errorf("%s: rebuild-required: %w", packetQuarantineState(q.state.Load()), err)
		}
		return true, nil
	}
	return false, nil
}
func (s *policyServer) beginQuarantineTransitionLocked(operation string) error {
	if s.quarantine == nil {
		return nil
	}
	s.quarantineReadyTicket, s.quarantineWasReady = s.mitmGate.Pause()
	if !s.quarantineWasReady {
		s.requireRevisionRecoveryLocked(revisionRecoveryUnknown)
		return errRevisionRecoveryRequired
	}
	s.invalidateRevisionBootstrapLocked()
	if err := s.quarantine.begin(operation); err != nil {
		s.requireRevisionRecoveryLocked(revisionRecoveryExternalEffectsUnknown)
		return errRevisionRecoveryRequired
	}
	return nil
}
func (s *policyServer) finishQuarantineTransitionLocked() error {
	if s.quarantine == nil {
		return nil
	}
	if err := s.revisionRecovery.recoveryErrorLocked(); err != nil {
		return err
	}
	if err := s.quarantine.finish(); err != nil {
		s.requireRevisionRecoveryLocked(revisionRecoveryExternalEffectsUnknown)
		return errRevisionRecoveryRequired
	}
	if s.quarantineWasReady && !s.mitmGate.RestoreReady(s.quarantineReadyTicket) {
		s.requireRevisionRecoveryLocked(revisionRecoveryUnknown)
		return errRevisionRecoveryRequired
	}
	s.quarantineWasReady = false
	return nil
}

// Unsupported multi-sandbox profiles must be rejected before any namespace-wide
// fence is installed; a sidecar record cannot authorize fencing other slots.
func validateQuarantineProfile() error {
	profile := strings.TrimSpace(os.Getenv(constants.EnvEgressProfile))
	if profile != "" && profile != constants.ProfileSidecar {
		return errors.New("quarantine supports only the sidecar profile")
	}
	return nil
}
