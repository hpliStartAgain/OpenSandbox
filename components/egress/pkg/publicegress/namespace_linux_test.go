package publicegress

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// Exercise the cgroup namespace/mount layout used by OCI containers: self's
// cgroup is '/', and /sys/fs/cgroup names the container leaf rather than host /.
func TestKernelPrivateCgroupNamespace(t *testing.T) {
	if os.Getenv("OSB_DISPOSABLE_NETNS") != "1" {
		t.Skip("requires disposable Linux namespaces")
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_unprivileged_port_start", []byte("1024"), 0600); err != nil {
		t.Fatal(err)
	}
	fixture := fmt.Sprintf("/sys/fs/cgroup/osb-private-cgroup-test-%d", os.Getpid())
	if err := os.Mkdir(fixture, 0755); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(fixture); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCgroupNamespaceBootstrap$")
	cmd.Env = append(os.Environ(), "OSB_PRIVATE_CGROUP="+fixture)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("private cgroup namespace: %v: %s", err, out)
	}
}

func TestCgroupNamespaceBootstrap(t *testing.T) {
	path := os.Getenv("OSB_PRIVATE_CGROUP")
	if path == "" {
		return
	}
	if err := os.WriteFile(path+"/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "--cgroup", "--mount", "--propagation", "private", os.Args[0], "-test.run=^TestCgroupNamespaceProbe$")
	cmd.Env = append(os.Environ(), "OSB_PRIVATE_NAMESPACE_PROBE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("namespaced probe: %v: %s", err, out)
	}
}

func TestCgroupNamespaceProbe(t *testing.T) {
	if os.Getenv("OSB_PRIVATE_NAMESPACE_PROBE") != "1" {
		return
	}
	// The parent unshare has already isolated the mount namespace and disabled
	// propagation; this mount cannot affect the test runner or host mount view.
	if err := unix.Mount(os.Getenv("OSB_PRIVATE_CGROUP"), "/sys/fs/cgroup", "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", "/sys/fs/cgroup", "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		t.Fatal(err)
	}
	path, err := currentCgroup()
	if err != nil {
		t.Fatal(err)
	}
	if path != "/" {
		t.Fatalf("expected private cgroup root, got %s", path)
	}
	cfg, _ := Parse(`{"version":1,"dns_servers":["10.0.0.53"],"internal_targets":[]}`)
	if _, err := Install(context.Background(), cfg, 8443); err != nil {
		t.Fatal(err)
	}
}
