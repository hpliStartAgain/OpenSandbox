---
title: Envoy Credential Vault Backend
authors:
  - "@hpliStartAgain"
creation-date: 2026-09-09
last-updated: 2026-09-09
status: draft
---

# OSEP-0024: Envoy Credential Vault Backend

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Requirements](#requirements)
- [Proposal](#proposal)
  - [Notes/Constraints/Caveats](#notesconstraintscaveats)
  - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
- [Test Plan](#test-plan)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
- [Infrastructure Needed](#infrastructure-needed)
- [Upgrade & Migration Strategy](#upgrade--migration-strategy)
<!-- /toc -->

## Summary

Propose an opt-in Envoy L7 backend inside the existing OpenSandbox egress
sidecar that can preserve Credential Vault's HTTPS credential-injection
behavior. Envoy would replace mitmproxy for an opted-in sandbox, not run as a
second transparent interceptor. Existing deployments would keep their default
behavior.

This is a design proposal, not an implementation or a claim of Istio
compatibility. It asks maintainers to agree on a small, staged contribution
path before introducing runtime changes.

## Motivation

Applications can currently use placeholder credentials while the sandbox-local
Credential Vault supplies real provider credentials through mitmproxy. Replacing
that proxy with an opaque TLS forwarder would lose credential injection, even
if the vault process and its API remained present.

[PR #1221](https://github.com/opensandbox-group/OpenSandbox/pull/1221), by
@ryanzhang-oss, already proposes an optional Envoy backend. Its current head
`5ddfe2b7ac7f` implements a storage-only extension API/SDK PoC, explicitly not
Envoy traffic enforcement. Its first Envoy design excludes TLS interception
and leaves migration of mitmproxy-dependent vault behavior to later work.
This proposal addresses that later compatibility problem. It credits and
complements #1221 rather than copying its extension API or assuming ownership
of the author's branch. The old proposal's OSEP number is not reused: current
main assigns OSEP-0016 to release governance.

The [current service-mesh compatibility warning](../docs/components/egress.md#service-mesh-compatibility)
identifies competing transparent capture layers in one Pod network namespace.
A single Envoy L7 engine could avoid that particular conflict while preserving
sandbox-local credential handling. Merely packaging processes in one container
is insufficient: redirect ownership and configuration ownership must also be
unambiguous.

### Goals

- Preserve application URLs and the existing Credential Vault API and binding
  semantics without exposing provider credentials to application code.
- Make Envoy an optional L7 implementation with one capture owner per port.
- Preserve DNS/nft enforcement and explicit fail-closed startup behavior.
- Reuse the security contracts of [OSEP-0012](0012-credential-vault.md) and
  [OSEP-0023](0023-credential-bound-tls-interception.md).
- Establish reproducible compatibility tests and a bounded implementation
  sequence that can be reviewed independently.

### Non-Goals

- Changing the default backend, removing mitmproxy, or breaking operator addons.
- Running a second transparent service-mesh proxy alongside this backend.
- Replacing DNS/nft, a CNI, centralized egress routing, or NAT infrastructure.
- Building a new approval service, database, or cluster-wide policy controller.
- Claiming the extension store from #1221 already programs Envoy.
- Requiring Istio, or claiming an arbitrary Envoy bootstrap can join Istiod.
- Supporting every TLS client or transport in the first implementation.

## Requirements

| ID | Requirement |
|---|---|
| R1 | An omitted backend option preserves current mitmproxy behavior and contracts. |
| R2 | Backend selection is separate from interception mode and immutable for a sandbox generation. |
| R3 | Only one L7 engine installs capture rules for a given outbound port; proxy-originated traffic cannot loop. |
| R4 | Every accepted credential configuration has defined behavior; unsupported combinations fail explicitly, never silently forward unchanged placeholders. |
| R5 | SNI can select decryption but cannot authorize credential injection; the full request binding match remains authoritative. |
| R6 | Provider certificate chain and hostname verification remain enabled. |
| R7 | Credentials remain sandbox-local and absent from cluster policy resources, logs, traces, and configuration dumps. |
| R8 | Binding revisions, request fencing, and draining satisfy the applicable OSEP-0023 contract before this backend advertises that mode. |
| R9 | The same Envoy listener/route/cluster resource has exactly one configuration owner. |
| R10 | A backend is not ready until its required policy, vault state, certificates, and capture path are usable. |

## Proposal

Introduce an operator-controlled, opt-in implementation of the egress L7 path.
The public selector and capability/error representation should be agreed in the
implementation review; this proposal does not add a lifecycle field or depend
on unmerged SDK extension endpoints.

```text
Application in sandbox
  -> one transparent L7 capture path
  -> Envoy TLS handling
       -> opaque forwarding where the selected interception contract permits it
       -> TLS termination for credential-bound requests
            -> HTTP connection manager
            -> local Credential Vault adapter (protected Unix socket)
            -> HTTP router
            -> verified upstream TLS to provider
  -> existing DNS/nft network boundary still applies
```

The local Go vault remains the owner of credential state. A request-processing
adapter evaluates the same binding and placeholder rules and returns only the
per-request modifications needed by Envoy. Envoy necessarily handles the
injected credential bytes; sandbox locality does not mean Envoy never sees
secrets. The complete vault must not be copied into xDS configuration.

### Notes/Constraints/Caveats

Envoy supports [listener TLS termination and upstream TLS origination](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ssl.html),
but `tcp_proxy` alone does not inspect or modify HTTP headers. HTTPS injection
needs an HTTP-processing path after TLS termination and certificate provisioning
appropriate for the sandbox's trusted CA. These are implementation tasks, not
an automatic consequence of replacing the binary.

This proposal does not promise to preserve a running sandbox during backend
replacement. It also does not equate ordinary Istio mesh mTLS with the
application-to-provider TLS interception needed by Credential Vault.

### Risks and Mitigations

| Risk | Mitigation / release gate |
|---|---|
| Credential leakage through processor or diagnostics | Protected local socket; per-request data minimization; redaction and adversarial access tests. |
| Destination changes after credential selection | Bind TLS identity, HTTP authority, policy, and actual upstream destination; reject inconsistent mutation. |
| Divergent binding behavior | Reuse authoritative matching logic or shared conformance fixtures; do not create an approximate Envoy-specific matcher. |
| Partial policy or certificate updates | Explicit request admission fencing and revision handling; no assumption that xDS updates are globally atomic. |
| Two capture or configuration owners | Reject conflicting deployment modes before readiness. |
| Increased runtime and maintenance cost | Measure against existing backends; keep opt-in and require maintainable upstream Envoy APIs. |

## Design Details

### Local HTTP adapter

Envoy's [external processing filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter.html)
provides a standard gRPC request/response processing interface and is a candidate
for this adapter. The existing Credential Proxy Unix-socket HTTP interface is
not that protocol; an adapter is required. Maintainers may prefer another
HTTP-filter integration after evaluating streaming and failure semantics.

Start with an explicitly bounded HTTPS/443, exact-host, header-injection slice
covering supported bearer, basic, API-key, and custom-header bindings. That
slice must preserve all applicable scheme, host, port, method, and path checks.
If body/query placeholder substitutions, wildcard bindings, credential sources,
or other accepted forms are not implemented yet, the opted-in profile must
reject those configurations before use. It must not advertise general Vault
parity. Existing mitmproxy users remain unaffected.

The adapter must not trust application-supplied identity headers or permit a
post-authorization target rewrite. A credential-required request cannot fall
back to forwarding a placeholder if the adapter or authoritative vault state
is unavailable. Request-body processing must be explicitly selected; a
header-only implementation must not buffer arbitrary bodies by accident.

The socket and private credential state must be inaccessible to the application
container. Process privileges, admin endpoints, debug access, core dumps, and
crash cleanup need review as part of this boundary.

### TLS and certificate lifecycle

A credential-bound host requires a suitable leaf certificate and an established
sandbox CA trust path. Define leaf provisioning, key ownership, rotation,
certificate-cache bounds, and any local SDS integration before claiming HTTPS
support. Stock Envoy is not assumed to synthesize arbitrary host certificates.
Both the application's trust in the sandbox certificate and Envoy's upstream
verification must be tested without insecure bypass flags.

Backend choice must not redefine OSEP-0023's interception modes. Under its
credential-bound contract, the acknowledged binding-host snapshot determines
whether decryption is needed; the complete HTTP binding match still determines
whether injection is authorized. Preserve that proposal's explicit behavior
for no-SNI, ECH-hidden, static-ignore, and unbound traffic rather than inventing
a different policy in this backend. Certificate-pinned clients and unsupported
transports must be documented as limitations, not silently downgraded.

### Revisions and compatibility

OSEP-0023 is already on main with status `implementing`; it remains the source
for credential-bound revision and connection semantics. In particular, an
SNI host match is not sufficient to inject a credential, and removing a binding
is not the same event as revoking all network access to its host.

Implement and test the required request-admission fences, previous-revision
completion rules, and bounded draining. Updating multiple Envoy resources and
receiving ACKs alone does not prove an atomic transition. Keep traffic gated
where required while a transition is incomplete, and never publish a successful
vault mutation whose required proxy behavior was not installed.

### Configuration ownership and optional Istio integration

The initial reference path can use an operator-owned local bootstrap and a
local adapter, coordinated with #1221's eventual lifecycle work. It does not
require completion of that PR's Gateway API translator or a new controller.

Istio integration should be a separate, explicit follow-up. It must establish
bootstrap, node/workload identity, proxy lifecycle, certificate ownership,
filter support, and the boundary between Istiod-managed configuration and local
credential handling. Two controllers must not compete for the same LDS/RDS/CDS
resources. Sharing an xDS protocol is not sufficient evidence of compatibility.
The current service-mesh coexistence warning remains valid until a supported
profile and its tests exist.

### Suggested contribution sequence

1. **This PR:** review the compatibility and security contract; no runtime change.
2. **Lifecycle/capture slice:** coordinate with #1221 to deliver an optional
   Envoy process and one capture path, tested against a fixed TLS target with
   correct trust. Report Vault capability unavailable until it is implemented.
3. **Local Vault slice:** add the bounded HTTP-processing adapter and its
   positive/negative binding tests. Reject unsupported forms explicitly.
4. **Usable credential-bound profile:** complete revision transitions,
   certificate lifecycle, recovery, and streaming tests before advertising
   usable support for that profile.
5. **Independent integration slice:** validate Istio ownership and lifecycle
   without adding a second transparent proxy or changing existing defaults.

Maintainer input is requested on whether this is a useful follow-up to #1221,
which slice should land first, the preferred HTTP adapter, and how backend
capability discovery should align with the current APIs. No merge or resource
commitment from the original author is assumed.

## Test Plan

All items below are planned acceptance criteria, not tests already run for an
Envoy implementation in this PR.

- Differential tests against the existing Vault binding and placeholder
  behavior, including invalid and unsupported configurations.
- Trusted/untrusted CA, wrong hostname/SNI, HTTP authority mismatch, wrong
  destination, and cross-sandbox credential access negative cases.
- Unbound HTTPS remaining opaque where required; network-denied destinations
  remaining denied regardless of decryption mode.
- HTTP/1.1 and HTTP/2 request admission, large uploads, SSE events above 1 MiB,
  backpressure and streaming; trailers and WebSocket behavior where supported.
- Vault-adapter outage, Envoy crash, invalid configuration, NACK, restart, and
  incomplete revision transitions with fail-closed behavior.
- Binding add/remove and credential rotation concurrent with new and existing
  requests, including the OSEP-0023 fence and drain boundaries.
- DNS/nft and original-destination behavior with explicit UID/mark exemptions;
  no capture loop or path bypass.
- Fresh creation, Pool templates, replacement, and snapshot/restore handling of
  ephemeral proxy state and credentials. Test each supported runtime; do not
  presume gVisor or fleet-profile compatibility from a runc-sidecar test.
- Resource and latency measurements against the existing backend, with actual
  results reported rather than projected performance improvements.

## Drawbacks

This adds certificate, HTTP-processing, and process-lifecycle work inside a
security-sensitive component. Envoy's mature primitives do not remove those
costs. Maintaining a second backend and its compatibility matrix may be more
expensive than fixing current mitmproxy issues, especially without sustained
upstream review and ownership.

## Alternatives

- **Keep mitmproxy:** least migration work and preserves existing addons; remains
  the default and fallback deployment choice.
- **Opaque Envoy only:** useful for SNI/network policy but cannot preserve HTTPS
  header-based credential injection by itself.
- **Add a separate mesh sidecar:** leaves the documented capture conflict and
  does not migrate Vault behavior automatically.
- **Centralize credential injection:** changes the sandbox-local secret and TLS
  trust boundary; it is outside this proposal.
- **Require Istio from the outset:** may align with some operators, but couples
  the backend to an additional control plane before the local Vault path is
  proven. Separate integration keeps the initial contribution smaller.

## Infrastructure Needed

A maintained Envoy build, an isolated Linux test environment, local TLS test
services, and the chosen HTTP-processing adapter dependencies. No production
credentials, public provider account, new database, or mandatory mesh control
plane is needed for the first reference tests.

## Upgrade & Migration Strategy

Keep existing defaults, `/policy`, and Credential Vault contracts unchanged.
Enable the new backend only for newly created sandboxes with supported
configurations. Preserve the current implementation until compatibility and
operational gates pass; do not silently migrate existing Pods.

Switching backends requires sandbox replacement using existing supported
workspace/state recovery mechanisms. No preservation of live sockets, process
memory, or zero-downtime replacement is claimed. Rollback creates a sandbox
using the existing backend and configuration rather than attempting to switch
an active TLS connection between proxy engines.
