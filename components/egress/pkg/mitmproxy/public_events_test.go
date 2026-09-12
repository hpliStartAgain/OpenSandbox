package mitmproxy

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPublicEventsRejectArbitraryPipeContent(t *testing.T) {
	require.Equal(t, "destination_denied", publicEvent("public policy: denied EGRESS_PUBLIC_POLICY_SNI_HOST_MISMATCH"))
	require.Equal(t, "identity_denied", publicEvent("upstream proxy: identity denied EGRESS_IDENTITY_UNAVAILABLE"))
	require.Equal(t, "route_public", publicEvent("public policy: route public"))
	for _, message := range []string{"upstream proxy: Bearer fake-secret", "GET https://example/public policy: route public", "public policy: denied EGRESS_PUBLIC_POLICY_BAD token=secret", "public policy: denied EGRESS_PUBLIC_POLICY_SECRET\nTOKEN", "upstream proxy: gateway_connect_denied status=403"} {
		require.Empty(t, publicEvent(message))
	}
}
