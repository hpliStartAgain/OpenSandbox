package dnsproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/publicegress"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestPublicPolicyPinsTCPResolvers(t *testing.T) {
	t.Setenv(publicegress.EnvPolicy, `{"version":1,"dns_servers":["10.0.0.53","10.0.0.54"],"internal_targets":[]}`)
	// This untrusted discovery input is deliberately invalid: strict mode must
	// not inspect it or /etc/resolv.conf at all.
	t.Setenv(constants.EnvDNSUpstream, "attacker.invalid")
	p, err := New(nil, "", nil, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.53:53", "10.0.0.54:53"}, p.upstreams)
	require.Equal(t, "tcp", p.upstreamNetwork)
	require.Equal(t, publicegress.DNSListenAddr, p.listenAddr)
	_, err = New(nil, "127.0.0.1:9999", nil, nil)
	require.Error(t, err)

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{Listener: listener, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(93, 184, 216, 34)}}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = server.ActivateAndServe() }()
	defer server.Shutdown()
	p.upstreams = []string{listener.Addr().String()}
	p.activeUpstreams = p.upstreams
	p.upstreamExchangeTimeout = time.Second
	question := new(dns.Msg)
	question.SetQuestion("example.test.", dns.TypeA)
	resp, _, err := p.forwardContext(context.Background(), question)
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)
	require.True(t, p.probeOneUpstream(listener.Addr().String(), time.Second), "health probes must also use TCP")
}
