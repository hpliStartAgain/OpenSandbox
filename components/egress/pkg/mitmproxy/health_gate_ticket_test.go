// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0
package mitmproxy

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHealthGateReadyRestoreTicket(t *testing.T) {
	g := &HealthGate{required: true}
	g.SetReady(true)
	ticket, ready := g.Pause()
	require.True(t, ready)
	require.True(t, g.MitmPending())
	require.True(t, g.RestoreReady(ticket))
	require.False(t, g.MitmPending())
	require.False(t, g.RestoreReady(ticket))
	ticket, _ = g.Pause()
	g.SetReady(false)
	require.False(t, g.RestoreReady(ticket))
	require.True(t, g.MitmPending())
	ticket, _ = g.Pause()
	g.SetReady(true)
	g.SetReady(false)
	require.False(t, g.RestoreReady(ticket))
	require.True(t, g.MitmPending())
}
