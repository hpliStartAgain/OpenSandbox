package mitmproxy

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/publicegress"
	"github.com/stretchr/testify/require"
)

func TestPublicPolicyArgsAndReadiness(t *testing.T) {
	t.Setenv(publicegress.EnvPolicy, `{"version":1,"dns_servers":["10.0.0.53"],"internal_targets":[]}`)
	t.Setenv(constants.EnvUpstreamProxy, "https://gateway.example")
	t.Setenv(constants.EnvUpstreamProxyIdentityFile, "/identity.jwt")
	args := buildMitmdumpArgs(Config{ListenPort: 18081})
	joined := strings.Join(args, " ")
	for _, opt := range []string{"upstream_cert=false", "connection_strategy=lazy", "rawtcp=false", "--set ignore_hosts --set tcp_hosts --set udp_hosts"} {
		require.Contains(t, joined, opt)
	}
	require.Less(t, strings.Index(joined, systemScriptPath), strings.Index(joined, publicPolicyScriptPath))
	require.Less(t, strings.Index(joined, publicPolicyScriptPath), strings.Index(joined, upstreamProxyScriptPath))
	for _, ack := range []string{"credential proxy: system addon ready\nupstream proxy: ready\n", "public policy: ready\ncredential proxy: system addon ready\nupstream proxy: ready\n"} {
		ready := make(chan struct{}, 1)
		forwardMitmdumpOutput(io.NopCloser(strings.NewReader(ack)), ready)
		require.Error(t, waitUpstreamProxyReady(ready, make(chan error), time.Millisecond))
	}
	ready := make(chan struct{}, 1)
	forwardMitmdumpOutput(io.NopCloser(strings.NewReader("credential proxy: system addon ready\npublic policy: ready\nupstream proxy: ready\n")), ready)
	require.NoError(t, waitUpstreamProxyReady(ready, make(chan error), time.Millisecond))
}
