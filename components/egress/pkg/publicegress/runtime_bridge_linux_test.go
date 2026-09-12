package publicegress_test

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/dnsproxy"
	"github.com/alibaba/opensandbox/egress/pkg/nftables"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/publicegress"
)

// TestRuntimeBridge is a subprocess fixture for test_public_egress_runtime.py.
// It runs the real guard and real TCP DNS proxy, not simulated hook callbacks.
func TestRuntimeBridge(t *testing.T) {
	if os.Getenv("OSB_PUBLIC_RUNTIME_BRIDGE") != "1" {
		t.Skip("only launched by the isolated runtime fixture")
	}
	if os.Getenv("OSB_DISPOSABLE_NETNS") != "1" {
		t.Fatal("requires a disposable netns")
	}
	cfg, err := publicegress.Parse(os.Getenv(publicegress.EnvPolicy))
	if err != nil || cfg == nil {
		t.Fatalf("fixture policy: %v", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	guard, err := publicegress.Install(ctx, cfg, 8443)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := dnsproxy.New(&policy.NetworkPolicy{DefaultAction: policy.ActionAllow}, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy.SetInfraDomain("gateway.example", func(_ string, ips []nftables.ResolvedIP) {
		var addresses []string
		for _, ip := range ips {
			if ip.Addr.Is4() {
				addresses = append(addresses, ip.Addr.String())
			}
		}
		if err := guard.SetGatewayIPs(ctx, addresses, time.Minute); err != nil {
			fmt.Printf("OSB_TEST_GATEWAY_UPDATE_ERROR: %v\n", err)
		}
	})
	if err := proxy.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer proxy.Shutdown()
	fmt.Println("OSB_TEST_BRIDGE_READY")
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Minute):
		t.Error("runtime fixture exceeded five minutes")
	}
}
