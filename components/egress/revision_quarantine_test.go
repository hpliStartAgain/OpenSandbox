// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/alibaba/opensandbox/egress/pkg/credentialvault"
	"github.com/alibaba/opensandbox/egress/pkg/nftables"
	"github.com/alibaba/opensandbox/egress/pkg/revision"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/mitmproxy"
	"github.com/stretchr/testify/require"
)

type quarantineFake struct {
	calls           []string
	fail            string
	afterRemove     func()
	namespaceChecks int
	failNamespaceAt int
}

func (f *quarantineFake) step(s string) error {
	f.calls = append(f.calls, s)
	if f.fail == s {
		return errors.New("injected")
	}
	return nil
}
func (f *quarantineFake) Ensure(context.Context) error { return f.step("ensure") }
func (f *quarantineFake) Remove(context.Context) error {
	err := f.step("remove")
	if f.afterRemove != nil {
		f.afterRemove()
	}
	return err
}
func (f *quarantineFake) CheckNamespace() error {
	f.namespaceChecks++
	if f.fail == "namespace" || (f.failNamespaceAt > 0 && f.namespaceChecks >= f.failNamespaceAt) {
		return errors.New("namespace-mismatch: rebuild-required")
	}
	return nil
}
func (f *quarantineFake) StartBootstrap() error { return f.step("bootstrap") }
func (f *quarantineFake) Begin(string) error    { return f.step("intent") }
func (f *quarantineFake) Commit() error         { return f.step("commit") }
func (f *quarantineFake) Running() error        { return f.step("running") }
func (f *quarantineFake) Quarantine() error     { return f.step("quarantine") }
func (f *quarantineFake) Close() error          { return nil }
func quarantineTestOwner(t *testing.T) (*policyServer, *quarantineFake) {
	t.Helper()
	f := &quarantineFake{}
	gate := mitmproxy.NewHealthGate()
	gate.SetReady(true)
	s := &policyServer{mitmGate: gate, quarantine: &revisionQuarantine{fence: f, journal: f}}
	return s, f
}
func TestRevisionQuarantineOrdersEffectsAndReadiness(t *testing.T) {
	s, f := quarantineTestOwner(t)
	require.NoError(t, s.beginQuarantineTransitionLocked("policy"))
	require.Equal(t, []string{"intent", "ensure"}, f.calls)
	require.Equal(t, quarantineConfirmed, packetQuarantineState(s.quarantine.state.Load()))
	f.calls = append(f.calls, "effects")
	require.NoError(t, s.finishQuarantineTransitionLocked())
	require.Equal(t, []string{"intent", "ensure", "effects", "commit", "running", "remove"}, f.calls)
	require.Equal(t, quarantineOpen, packetQuarantineState(s.quarantine.state.Load()))
	require.False(t, s.revisionRecoveryRequired.Load())
}
func TestRevisionQuarantineFailureMatrix(t *testing.T) {
	for _, stage := range []string{"intent", "ensure", "namespace", "commit", "running", "remove"} {
		t.Run(stage, func(t *testing.T) {
			s, f := quarantineTestOwner(t)
			f.fail = stage
			err := s.beginQuarantineTransitionLocked("policy")
			if stage == "intent" || stage == "ensure" || stage == "namespace" {
				require.Error(t, err)
				require.NotContains(t, f.calls, "commit")
			} else {
				require.NoError(t, err)
				require.Error(t, s.finishQuarantineTransitionLocked())
			}
			require.True(t, s.revisionRecoveryRequired.Load())
			require.ErrorIs(t, s.revisionRecovery.recoveryErrorLocked(), errRevisionRecoveryRequired)
			want := quarantineConfirmed
			if stage == "ensure" || stage == "namespace" {
				want = quarantineUnknown
			}
			require.Equal(t, want, packetQuarantineState(s.quarantine.state.Load()))
			require.Contains(t, f.calls, "quarantine")
			if stage == "commit" || stage == "running" {
				require.NotContains(t, f.calls, "remove")
			}
		})
	}
}
func TestRevisionQuarantineNeverRestoresStaleReady(t *testing.T) {
	s, f := quarantineTestOwner(t)
	require.NoError(t, s.beginQuarantineTransitionLocked("policy"))
	f.afterRemove = func() { s.mitmGate.SetReady(false) }
	require.Error(t, s.finishQuarantineTransitionLocked())
	require.True(t, s.revisionRecoveryRequired.Load())
	require.Equal(t, quarantineConfirmed, packetQuarantineState(s.quarantine.state.Load()))
}
func TestRevisionQuarantineRefusesMutationWithoutReady(t *testing.T) {
	s, f := quarantineTestOwner(t)
	s.mitmGate.SetReady(false)
	require.Error(t, s.beginQuarantineTransitionLocked("policy"))
	require.NotContains(t, f.calls, "intent")
	require.True(t, s.revisionRecoveryRequired.Load())
}
func TestRevisionQuarantineContainmentIsIndependent(t *testing.T) {
	s, f := quarantineTestOwner(t)
	f.fail = "ensure"
	s.requireRevisionRecoveryLocked(revisionRecoveryExternalEffectsUnknown)
	require.True(t, s.revisionRecoveryRequired.Load())
	require.Equal(t, quarantineUnknown, packetQuarantineState(s.quarantine.state.Load()))
	f.fail = ""
	s.requireRevisionRecoveryLocked(revisionRecoveryUnknown)
	require.Equal(t, quarantineConfirmed, packetQuarantineState(s.quarantine.state.Load()))
	require.Equal(t, revisionRecoveryExternalEffectsUnknown, s.revisionRecovery.reason)
	require.Error(t, s.finishQuarantineTransitionLocked())
	require.NotContains(t, f.calls, "remove")
}

func TestRevisionQuarantinePolicyOwnerGatesRealEffectPath(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			s := recoveryPolicyFixture(t)
			s.mitmGate.SetReady(true)
			f := &quarantineFake{}
			if failed {
				f.fail = "ensure"
			}
			s.quarantine = &revisionQuarantine{fence: f, journal: f}
			applied := 0
			s.nft = nftables.NewManagerWithRunner(func(_ context.Context, _ string) ([]byte, error) {
				applied++
				require.Equal(t, []string{"intent", "ensure"}, f.calls)
				require.Equal(t, quarantineConfirmed, packetQuarantineState(s.quarantine.state.Load()))
				return nil, nil
			})
			w := httptest.NewRecorder()
			s.handlePost(w, httptest.NewRequest(http.MethodPost, "/policy", strings.NewReader(`{"defaultAction":"allow"}`)))
			if failed {
				require.Equal(t, 0, applied)
				require.Equal(t, http.StatusServiceUnavailable, w.Code)
				require.True(t, s.revisionRecoveryRequired.Load())
			} else {
				require.Equal(t, 1, applied)
				require.Equal(t, http.StatusOK, w.Code)
				require.Equal(t, []string{"intent", "ensure", "commit", "running", "remove"}, f.calls)
			}
		})
	}
}
func TestRevisionQuarantineVaultOwnerBeforeIPC(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			s, m, session := mutationFixture(t)
			f := &quarantineFake{}
			if failed {
				f.fail = "ensure"
			}
			s.quarantine = &revisionQuarantine{fence: f, journal: f}
			original := session.update
			session.update = func(ctx context.Context, snap credentialvault.ActiveSnapshot, epoch int64) (revision.Identity, error) {
				require.Equal(t, []string{"intent", "ensure"}, f.calls)
				return original(ctx, snap, epoch)
			}
			_, err := s.mutateRevisionVault(mutationContext(t), m, prepareEmptyVault)
			if failed {
				require.Error(t, err)
				require.Zero(t, session.updateCalls)
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, session.updateCalls)
				require.Equal(t, []string{"intent", "ensure", "commit", "running", "remove"}, f.calls)
			}
		})
	}
}
func TestRevisionQuarantineBootstrapCommitBeforeReady(t *testing.T) {
	s := recoveryPolicyFixture(t)
	f := &quarantineFake{}
	s.quarantine = &revisionQuarantine{fence: f, journal: f}
	s.mitmGate.SetReady(false)
	_, _, ticket, err := s.captureRevisionBootstrap(context.Background())
	require.NoError(t, err)
	m, result := quiescencePendingResult(s, ticket)
	f.afterRemove = func() { require.True(t, s.mitmGate.MitmPending()) }
	require.NoError(t, publishRevisionReady(context.Background(), m, result))
	require.Equal(t, []string{"commit", "running", "remove"}, f.calls)
	require.False(t, s.mitmGate.MitmPending())
	require.NotNil(t, m.running)
}
func TestRevisionQuarantineCurrentChildExitIsTerminal(t *testing.T) {
	s := recoveryPolicyFixture(t)
	f := &quarantineFake{}
	s.quarantine = &revisionQuarantine{fence: f, journal: f}
	m := &mitmTransparent{currentGen: 7, revisionOwner: &revisionLaunchOwner{server: s}}
	m.recordExit(6)
	require.Empty(t, f.calls)
	m.recordExit(7)
	require.True(t, s.revisionRecoveryRequired.Load())
	require.Equal(t, []string{"ensure", "quarantine"}, f.calls)
}

func TestRevisionQuarantineUnsupportedProfileBeforeKernel(t *testing.T) {
	t.Setenv("OPENSANDBOX_EGRESS_EXPERIMENTAL_REVISION_RUNTIME", "true")
	for _, profile := range []string{"fast-sandbox", "unknown"} {
		t.Setenv("OPENSANDBOX_EGRESS_PROFILE", profile)
		q, err := beginSidecarQuarantine()
		require.Nil(t, q)
		require.EqualError(t, err, "quarantine supports only the sidecar profile")
	}
}

func TestRevisionQuarantineGuardCanonicalDisabledGate(t *testing.T) {
	before := os.Args
	os.Args = []string{"egress", "--guard-quarantine"}
	defer func() { os.Args = before }()
	for _, value := range []string{"", "false", " 0 ", "no", "OFF", "invalid"} {
		t.Setenv("OPENSANDBOX_EGRESS_EXPERIMENTAL_REVISION_RUNTIME", value)
		handled, err := runQuarantineCommand()
		require.True(t, handled)
		require.NoError(t, err)
	}
}

func TestRevisionQuarantineCurrentFenceDoesNotConfirmOriginalNamespace(t *testing.T) {
	f := &quarantineFake{}
	q := &revisionQuarantine{fence: f}
	require.ErrorContains(t, q.ensure(), "original namespace identity unavailable")
	require.Equal(t, quarantineUnknown, packetQuarantineState(q.state.Load()))
	q.journal = f
	f.fail = "namespace"
	require.ErrorContains(t, q.contain(), "namespace-mismatch")
	require.Equal(t, quarantineUnknown, packetQuarantineState(q.state.Load()))
	require.Contains(t, f.calls, "ensure")
	require.Contains(t, f.calls, "quarantine")
	require.NotContains(t, f.calls, "remove")
}

func TestRevisionQuarantineNamespaceMismatchRefusesShutdownCleanup(t *testing.T) {
	s, f := quarantineTestOwner(t)
	f.fail = "namespace"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Nil dependencies would panic if ordinary redirect/service teardown ran.
	waitForShutdown(ctx, nil, nil, nil, nil, nil, nil, s)
	require.True(t, s.revisionRecoveryRequired.Load())
	require.Equal(t, quarantineUnknown, packetQuarantineState(s.quarantine.state.Load()))
	require.Contains(t, f.calls, "ensure")
	require.NotContains(t, f.calls, "remove")
}

func TestRevisionQuarantineNamespaceProofRequiredAroundUnfence(t *testing.T) {
	t.Setenv("OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT", "true")
	for _, at := range []int{2, 3} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			s, f := quarantineTestOwner(t)
			require.NoError(t, s.beginQuarantineTransitionLocked("policy"))
			f.failNamespaceAt = at
			require.Error(t, s.finishQuarantineTransitionLocked())
			require.True(t, s.revisionRecoveryRequired.Load())
			require.True(t, s.mitmGate.MitmPending())
			require.Equal(t, quarantineUnknown, packetQuarantineState(s.quarantine.state.Load()))
			if at == 2 {
				require.NotContains(t, f.calls, "remove")
			} else {
				require.Contains(t, f.calls, "remove")
			}
		})
	}
}
