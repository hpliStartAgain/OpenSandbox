---
title: Administrator-managed upstream proxy
description: Experimental Kubernetes egress transport through an HTTPS CONNECT gateway with private CA and rotating identity files.
---

# Administrator-managed upstream proxy

## Root-compatible security profile

The internal Kubernetes profile retains UID 0 in the business container, including ordinary file ownership and user switching. Root does not mean privileged container access: network administration, raw sockets, host namespaces, writable cgroup access, hostPath mounts and Kubernetes service-account credentials are forbidden. The business process cannot be allowed to join or alter the egress container's cgroup.

Business and execd-installer containers also lack `NET_BIND_SERVICE`. Their own listening services must use ports **1024 or higher** (for example 8000 or 8080, not 80). This does not restrict connecting to approved HTTPS port 443. The Pod sets `net.ipv4.ip_unprivileged_port_start=1024`, and the guard verifies it before becoming ready. This is a Kubernetes [safe namespaced sysctl](https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/#safe-and-unsafe-sysctls), not a node-wide setting.

The real strict DNS, control and MITM listeners use backend ports 353, 380 and 381. The sidecar explicitly requests `NET_ADMIN` and `NET_BIND_SERVICE`; the trusted MITM child retains only the additional ambient `NET_BIND_SERVICE` capability needed to listen on 381. Persistent NAT maps local DNS frontend 15353 and control frontend 18080 to their protected backends; application HTTP(S) interception goes directly to 381. Non-loopback control requests also map to 380. An application may occupy unused high frontend ports after a crash, but cannot receive their redirected service traffic or prevent the protected backends from restarting. Both high frontends and low backends remain reserved internal-target/gateway ports.

The root-compatible implementation uses the kernel's cgroup-v2 socket identity, not a process UID, to identify egress-originated connections. Changing to the mitmproxy UID must not bypass interception or permit a direct gateway connection. It requires a dedicated cgroup per container, cgroup v2 mounted at `/sys/fs/cgroup`, the `xt_cgroup` path matcher, iptables and nftables. A packet classifier clears and recomputes a reserved mark from kernel socket ancestry on every packet. Startup probes a real socket and refuses unsupported configurations without a UID-based fallback. The independent `opensandbox_public_egress` nftables table and `OSB_PUBLIC_CGROUP` classifier survive process shutdown, cleanup and restart.

The egress container is a native Kubernetes sidecar init container with `restartPolicy: Always`. Its startup exec probe verifies the installed `bprime-root-v1` artifact manifest and the local health endpoint before allowing the generated execd init and business container to start. An old image's generic health endpoint is insufficient. The health gate waits for the guard, DNS and all three addons. The cluster and workload controller must preserve native sidecars; verify the final Pod, not only the submitted CR. A regular concurrently started sidecar is not a supported substitute.

In this strict profile, IPv6 is disabled for egress by the persistent nft filter, rather than a privileged execd-init sysctl. The execd file installer keeps UID 0 with the same limited capability/seccomp profile as the business container. The legacy, feature-disabled IPv6 setup is unchanged.

The server generates a separate per-sandbox control API token automatically. Strict sidecar startup refuses a missing token; remote control access uses authenticated frontend 18080, not direct backend 380. Ordinary sandbox processes cannot reach either control port. Leave the MITM port environment override unset, or set it to the protected backend 381 in strict deployments; the old standalone 18081 override is rejected. `Proxy-Authorization` is removed from both public and exact-internal business requests and is only added to gateway CONNECT.

The source includes disposable Linux namespace/cgroup and transparent-proxy fixtures. These tests do not certify a different kernel, container runtime, admission policy or gateway deployment. The release gates below remain mandatory.

::: warning Experimental transport integration
This internal feature is disabled by default. CONNECT transport and private file mounts do not by themselves enforce FQDN grants, prevent every direct-network bypass, or revoke existing tunnels. Production rollout requires the separate target-binding, workload-isolation, Vault and gateway acceptance checks. Do not use this feature as a production authorization boundary yet.
:::

The server consumes an administrator-configured HTTPS gateway and renders its CA and machine identity exclusively into the egress sidecar. The bundled addon order is `system.py`, `public_policy.py`, then `upstream_proxy.py`. Sandbox requests cannot choose the addon, gateway, CA, identity path or strict routing policy.

```toml
[egress]
image = "registry.example/egress@sha256:<verified-digest>"
mode = "dns+nft"
disable_ipv6 = true

[egress.upstream_proxy]
enabled = true
url = "https://gateway.example:443"
dns_servers = ["10.0.0.53", "10.0.0.54"] # Replace with trusted site resolvers.
internal_targets = [] # No implicit RFC1918, CGNAT or internal-network bypass.

[egress.upstream_proxy.ca_bundle]
secret_name = "egress-gateway-ca"
key = "ca.crt"

[egress.upstream_proxy.identity]
secret_prefix = "egress-identity-"
key = "identity.jwt"
```

This transport configuration initially accepts only Linux Kubernetes sandboxes using the default runtime. Docker, pool/fast-sandbox, gVisor, Kata and other explicitly configured RuntimeClasses are unsupported. The server requires `networkPolicy` on every create while the feature is enabled; omitting it cannot silently create a sandbox without the configured sidecar. Existing sandboxes are not changed.

The gateway URL must be HTTPS with a DNS hostname, without userinfo, path, query or fragment. When enabled, `egress.image` must end in `@sha256:` followed by a 64-character lowercase hexadecimal digest; replace the example placeholder with the verified build digest. Tags alone are rejected. Use a dedicated server configuration for testing this feature. Request environment overrides for transparent interception, insecure TLS, policy files and additional interception ports are rejected under this configuration.

The trusted issuer creates and updates `<secret_prefix><sandbox_id>` in the workload namespace. Sandbox IDs are generated by the server. The Secret must contain a signed compact JWT at the configured key. The addon reopens the file before every new proxy connection and rejects missing, empty, malformed, not-yet-valid or expired tokens. The checked token is bound to that connection's CONNECT; the gateway rechecks expiration after its TLS handshake. Local checks validate the envelope and validity window; signature, issuer, audience, instance binding and Grant authorization remain the gateway's responsibility.

Identity is mounted read-only at `/run/opensandbox/egress-identity/identity.jwt`; the CA is mounted at `/run/opensandbox/egress-gateway-ca/ca.crt`. Directory mounts preserve Kubernetes atomic Secret updates. The identity Secret is optional so local work may start before issuance. The CA Secret is required: a missing key prevents container startup, and an invalid PEM fails static addon initialization. Neither private volume may be exposed through another container or a template alias. A mount conflict fails workload creation.

The identity header is added only to the gateway CONNECT. It is never placed in the tunneled business request. Tokens are not stored in container environment variables, command arguments or logs. Rotation affects new CONNECTs; existing tunnels require gateway-side revocation. The issuer must reclaim or owner-reference per-sandbox Secrets after creation, and revoke identities on sandbox deletion. The server does not create or delete issuer-owned Secrets.

Gateway TLS uses the configured CA and gateway hostname verification. Target TLS retains the image's public CA trust. Disabling certificate verification is forbidden for the file-identity transport. The launcher waits for system, public-policy and upstream addons to acknowledge successful static initialization, in that order, before marking the MITM stack ready. A sandbox without identity may become Ready; its public requests fail closed. Readiness is not Grant approval.

Missing or invalid identity returns a stable `EGRESS_IDENTITY_*` rejection for buffered requests. Rejected streaming uploads are disconnected without forwarding a body: mitmproxy 11.0.2 cannot safely serve a local rejection response once request streaming has begun.

## Destination contract

Public traffic is HTTPS to a normalized DNS hostname on port 443. Every request binds its Host/HTTP2 authority to the TLS SNI, original intercepted IP/port and a fresh trusted A answer. IP literals, public plain HTTP, missing/mismatched SNI, private/special addresses and non-443 public ports are rejected. Gateway CONNECT uses the DNS hostname, not the intercepted IP. The gateway independently re-resolves the destination, checks its actual dial IP and validates the signed identity and Grant; local checks do not replace those gateway decisions.

Both gateway and destination resolution use the fixed local DNS proxy over TCP; it forwards over TCP to the administrator's literal `dns_servers`. Neither `/etc/hosts` nor `/etc/resolv.conf` is a trust source. A root process cannot impersonate the DNS/HTTP control listeners by taking over their ports after a sidecar crash. Public IPv6 and raw outbound UDP are not supported.

The reserved packet and connection mark bit is `0x40000000`; other policies must not reuse it. Gateway DNS TTL limits new connection admission. A connection admitted from the egress cgroup may continue after TTL expiry, so established SSE/WSS tunnels are not cut by DNS cache aging. Only egress-cgroup sockets may use that connection permission. DNS changes and identity-file deletion do not revoke existing tunnels: the gateway must enforce old-flow revocation.

Internal exceptions are exact administrator-owned host, IPv4 address and TCP port lists. They still pass through interception and DNS/original-destination binding; they do not grant direct network access to the business process. Approved internal routes do not require a public-gateway JWT. Internal HTTPS still verifies the target certificate against the egress image's target trust store. Add an exception under the upstream configuration, for example:

```toml
[[egress.upstream_proxy.internal_targets]]
host = "git.corp.example"
ips = ["10.20.30.40"]
ports = [443]
```

Loopback, link-local, metadata endpoints, CIDRs, wildcard hosts and reserved control ports are not valid exceptions. Do not treat the example IPs or resolvers as site defaults.

## Build identity and observations

The egress image contains `/opt/opensandbox-egress/public-egress-manifest.json`, generated from the installed binary, supervisor, cleanup script, bundled addons and static MITM configuration. It records SHA-256 content identities and the installed mitmproxy/Python versions. Read back this file from the built image and retain it with paired server/egress registry digests and vulnerability scan results. The manifest is provenance, not a substitute for registry digest pinning or an image signature.

The startup probe runs `python3 /opt/opensandbox-egress/public_egress_manifest.py --check-ready`. Missing artifacts, mismatched installed bytes, a mitmproxy version other than 11.0.2 or an unready stack fail the probe. It neither reads identity files nor contacts the gateway. Normal readiness retains `/healthz` and does not repeat whole-image hashing.

Local routing and denial events cross the MITM log pipe using a bounded format. `egress.public.events_total` has one finite `outcome` label plus existing shared labels; it never labels a hostname, path, identity, JWT or arbitrary gateway error. `route_public`/`route_internal` mean a local routing decision, **not** gateway authorization or request success. Multiple hooks can produce events for one request, so this is not a unique-request counter. Existing DNS observations supply normalized destination names separately. Keep OTLP destinations explicitly allowed as internal infrastructure; enabling metrics does not grant unrestricted network access.

Gateway events distinguish connection failure, TLS failure, generic CONNECT rejection, CONNECT 403 (`gateway_grant_denied`) and CONNECT 429 (`gateway_rate_limited`). A business HTTP 403 is not a Grant event. No arbitrary gateway reason, header or identity is included. These are local observations of gateway status, not verification of the gateway's authorization implementation. Strict public transport errors disconnect the affected request without forwarding the upstream error text: a gateway's CONNECT rejection reason could contain reflected machine credentials. Only local policy/identity rejections have the documented stable local codes. Successful business responses, including ordinary HTTP 403 responses, are unchanged.

Migration requires draining and recreating sandboxes after publishing and verifying paired server/egress images. Preserve the previous image digests and server configuration. Disabling this transport is not an approved fallback to unrestricted public access; keep the external egress restrictions in place during rollback.

Before production enablement, accept the paired image build and scan; the actual API → workload CR → final Pod path (including native sidecar ordering, private mounts and cgroup isolation); real issuer signature/Grant checks and revocation; and deletion/recreation with Secret cleanup and rollback. Site DNS, exact internal targets, signer ownership and gateway authorization are administrator deployment inputs, not defaults supplied by this fork.
