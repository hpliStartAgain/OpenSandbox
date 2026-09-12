package publicegress

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	valid := `{"version":1,"dns_servers":["10.0.0.53"],"internal_targets":[{"host":"git.example.test","ips":["10.1.2.3"],"ports":[8443]}]}`
	c, err := Parse(valid)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.InterceptPorts(); len(got) != 3 || got[2] != 8443 {
		t.Fatalf("ports: %v", got)
	}
	for _, raw := range []string{`{}`, `null`, valid + ` {}`, strings.Replace(valid, `"10.0.0.53"`, `"127.0.0.1"`, 1), strings.Replace(valid, `"10.1.2.3"`, `"169.254.169.254"`, 1), strings.Replace(valid, `"git.example.test"`, `"*.example.test"`, 1), strings.Replace(valid, `8443`, `15353`, 1), strings.Replace(valid, `"version":1`, `"version":1,"typo":true`, 1)} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestGuardRulesNoUIDFallback(t *testing.T) {
	c, _ := Parse(`{"version":1,"dns_servers":["10.0.0.53"],"internal_targets":[]}`)
	g := &Guard{cfg: c, cgroup: "test/egress", gatewayPort: 8443}
	rules := g.rules()
	for _, want := range []string{`meta mark & 0x40000000 != 0`, `tcp dport { 80, 443 } redirect to :381`, `policy drop`, `tcp dport 53 accept`, `th sport { 353, 380, 381, 15353, 18080, 18081 } drop`, `ct status dnat accept`, `meta mark & 0x40000000 != 0 ct state established ct direction original ct mark & 0x40000000 != 0 tcp dport 8443 accept`, `ct mark set ct mark | 0x40000000`, `control_frontend tcp dport 18080 redirect to :380`} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, bad := range []string{"skuid", "uid-owner", "ct state established,related"} {
		if strings.Contains(rules, bad) {
			t.Errorf("unexpected broad bypass %s", bad)
		}
	}
}

func TestGatewayUpdates(t *testing.T) {
	var got string
	g := &Guard{run: func(_ context.Context, rules string) error { got = rules; return nil }}
	if err := g.SetGatewayIPs(context.Background(), []string{"10.0.0.2", "10.0.0.2"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, "10.0.0.2") != 1 || !strings.Contains(got, "flush set") {
		t.Fatal(got)
	}
	if err := g.SetGatewayIPs(context.Background(), []string{"127.0.0.1"}, time.Minute); err == nil {
		t.Fatal("accepted loopback")
	}
}

// Must be explicitly enabled INSIDE a disposable network namespace. Never run
// on the host namespace: Install intentionally retains a default-deny table.
func TestKernelProbeAndInstall(t *testing.T) {
	if os.Getenv("OSB_DISPOSABLE_NETNS") != "1" {
		t.Skip("requires a disposable Linux netns and CAP_NET_ADMIN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_unprivileged_port_start", []byte("1024"), 0600); err != nil {
		t.Fatal(err)
	}
	c, _ := Parse(`{"version":1,"dns_servers":["10.0.0.53"],"internal_targets":[]}`)
	g, err := Install(ctx, c, 8443)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cgroup=%s", g.cgroup)
	if err := g.SetGatewayIPs(ctx, []string{"10.0.0.2"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(ctx, c, 8443); err != nil {
		t.Fatalf("restart: %v", err)
	}
}
