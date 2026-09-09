---
title: Optional Envoy L7 Backend for OpenSandbox Egress
authors:
  - "@hpliStartAgain"
creation-date: 2026-09-09
last-updated: 2026-09-09
status: draft
---

# OSEP-0024: Optional Envoy L7 Backend for OpenSandbox Egress

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

Add an opt-in Envoy L7 backend to the existing OpenSandbox egress sidecar.
The first milestone establishes backend selection, Envoy lifecycle, transparent
capture, basic HTTP policy, and opaque HTTPS forwarding while retaining DNS/nft
enforcement and the existing mitmproxy default.

Credential Vault injection with Envoy and Istio management are explicit later
milestones. Neither is a prerequisite for merging the first backend implementation,
and neither may be advertised as supported before its own acceptance tests pass.
This PR contains only a proposal and index entry, not a runtime implementation.

## Motivation

[PR #1221](https://github.com/opensandbox-group/OpenSandbox/pull/1221), by
@ryanzhang-oss, explored an optional Envoy backend. Its current head
`5ddfe2b7ac7f` implements a storage-only extension API/SDK PoC, not Envoy
lifecycle, capture, or traffic enforcement. It has not been merged. We therefore
cannot start a Vault migration on the assumption that an Envoy backend already
exists in main.

This proposal credits that earlier work and asks for a narrower implementation
sequence. It does not require the unmerged extension store, Gateway API
translator, or agentgateway resource model. Its initial scope is the missing
backend foundation; those configuration models can be discussed independently.
The old proposal's OSEP number is not reused because main now assigns OSEP-0016
to release governance.

The [service-mesh compatibility warning](../docs/components/egress.md#service-mesh-compatibility)
explains why two transparent interceptors in one sandbox network namespace can
conflict. An Envoy backend should replace mitmproxy's L7 role for an opted-in
sandbox, not add another competing capture stack. This alone does not make it
compatible with Istio or preserve Credential Vault injection.

### Goals

- Provide a selectable Envoy backend without changing existing defaults.
- Establish one L7 capture owner, working lifecycle and readiness, and bounded
  failure handling before adding higher-level integrations.
- Support a small HTTP policy surface and transparent HTTPS byte forwarding.
- Preserve DNS/nft network policy and reject unsupported feature combinations.
- Define independent acceptance gates for later Vault and Istio work.

### Non-Goals

- HTTPS MITM, generated leaf certificates, or credential injection in milestone 1.
- Running mitmproxy and Envoy as simultaneous interceptors for the same ports.
- Replacing DNS/nft, CNI enforcement, centralized egress routing, or NAT.
- Building an approval service, database, or cluster-wide policy controller.
- Requiring Istio, new CRDs, or the extension APIs from #1221.
- Changing existing SDK or Credential Vault contracts in this proposal-only PR.
- Claiming performance improvements or production readiness without measurements.

## Requirements

| ID | Requirement |
|---|---|
| R1 | Omitting backend selection preserves existing DNS/nft and mitmproxy behavior. |
| R2 | Backend selection is operator-controlled, distinct from interception mode, and immutable for a sandbox generation. |
| R3 | Exactly one L7 backend owns capture for the selected ports; proxy-originated traffic cannot loop. |
| R4 | Readiness requires a valid configuration, a healthy proxy, and the required capture/network enforcement state. |
| R5 | A requested Envoy/Vault combination fails explicitly until that capability exists; runtime Vault updates must not succeed while being ignored. |
| R6 | HTTP policy and HTTPS forwarding cannot bypass the existing DNS/nft boundary or change the authorized destination. |
| R7 | Initialization and recovery never leave an unintended direct-egress window. |
| R8 | The same listener, route, or cluster configuration has a single owner. |
| R9 | Supported runtime, address-family, and protocol limits are explicit and tested. |
| R10 | Optional-backend failure does not silently switch to another backend. |

## Proposal

Provide an optional Envoy implementation behind the egress component's L7
boundary. Agree on the exact server/operator selector and error representation
before the implementation PR; do not overload `credentialProxy.interceptionMode`
or add an unreviewed lifecycle API field here.

Milestone 1 uses operator-owned local configuration and existing policy inputs.
It does not require a new general-purpose xDS control plane.

```text
Sandbox application
  -> existing DNS proxy / DNS-derived network policy
  -> single L7 transparent capture
       -> HTTP: Envoy HTTP connection manager, basic policy, router
       -> HTTPS: opaque TLS bytes, optional SNI/destination policy
  -> original-destination forwarding
  -> existing nft policy still gates outbound traffic
```

For HTTP, start with a small, explicitly supported host-based allow/deny surface.
Validate authority and destination consistency against the available network and
original-destination context. Do not introduce a target-rewrite path after policy
checks. Reject configurations whose required policy cannot be represented.

For HTTPS, the first backend does not decrypt, originate replacement provider
TLS, or inject credentials. The application continues to validate the provider's
certificate. A TLS inspector may expose SNI for policy, but cannot read encrypted
HTTP headers. If a configured policy requires visible SNI and it is absent or
hidden, do not silently treat the requirement as satisfied.

### Notes/Constraints/Caveats

A new backend is useful without Vault: operators can opt in workloads that do
not require credential injection. Workloads that need current Vault behavior
continue using mitmproxy. This limitation must be visible in configuration
validation and documentation, not discovered after requests lose credentials.

Putting Envoy in the same container as the egress process is not enough to
establish correctness. Redirect ownership, upstream exemptions, configuration
ownership, and startup/termination sequencing all need implementation and tests.

### Risks and Mitigations

| Risk | Mitigation / gate |
|---|---|
| Capture loops or bypass | One capture owner; explicit UID/mark exemptions; preserve and test DNS/nft policy. |
| Proxy crashes after rules are installed | Gate traffic and readiness during recovery; do not fall back to direct access. |
| Loss of Vault behavior | Reject unsupported Envoy/Vault combinations before readiness and at runtime mutation boundaries. |
| Broader policy than requested | Reject unsupported policy forms; test authority, SNI, and original-destination handling. |
| Two configuration writers | One owner for each resource; defer external control-plane integration. |
| Larger images and resource overhead | Bound resources and measure against existing backends before recommending rollout. |

## Design Details

### Backend lifecycle and configuration

Keep the existing implementation as the default. The optional backend must
manage Envoy process startup, health, shutdown, and crash recovery. Separate
privileged rule installation from steady-state proxy execution, and protect
admin/debug interfaces from sandbox application code.

Start from a pinned Envoy build and a minimal local bootstrap. Validate supported
filters and configuration before activating capture. A malformed startup config
must prevent readiness. If configuration reload is implemented, a failed update
must retain a safe previous state or deny traffic; it must not advertise the
failed configuration as active. Multi-resource xDS ACKs are not assumed to be
an atomic policy transaction.

Capture initially covers canonical HTTP/HTTPS ports 80/443. Define the IPv4 and
IPv6 handling explicitly; an IPv4-only implementation must reject unsupported
IPv6 requirements or enforce an appropriate deny boundary, not allow an
uncontrolled bypass. Non-HTTP traffic remains subject to the existing network
policy; this proposal does not make Envoy its sole security boundary.

### Capability and compatibility behavior

Selecting Envoy with Credential Proxy/Vault injection must fail clearly until
the backend implements it. The same rule applies to runtime credential-vault
mutations: no successful-looking write to a store whose injection path does
not exist. Implementation review should decide how to expose this through
current APIs without depending on #1221's unmerged extension endpoints.

Existing mitmproxy scripts are not automatically translated into Envoy filters.
Operator configurations that require them must remain on mitmproxy or receive
an explicit incompatibility error when selecting Envoy.

Do not conflate selecting an L7 backend with selecting the interception modes
in [OSEP-0023](0023-credential-bound-tls-interception.md). That proposal's
credential-bound behavior is a later compatibility requirement for a
Vault-capable Envoy backend, not a behavior implemented by opaque forwarding.

### Contribution milestones

1. **This PR: design agreement.** Confirm the optional-backend scope, validation
   boundaries, and the smallest implementation slice. No runtime changes.
2. **Milestone 1: usable optional Envoy L7 backend.** Implement selection and
   validation, lifecycle/configuration, single capture ownership, basic HTTP
   policy, HTTPS passthrough, readiness, and fail-closed recovery. These can be
   split into dependent implementation PRs, but the backend is not advertised
   as usable until the complete gate passes. Coordinate overlapping work with
   #1221's author rather than silently taking over that branch.
3. **Milestone 2: Credential Vault integration.** After the backend works,
   implement and validate local HTTPS credential injection. Preserve
   [OSEP-0012](0012-credential-vault.md) binding and redaction semantics and the
   applicable OSEP-0023 interception/revision contract. This is not a milestone-1
   merge prerequisite.
4. **Milestone 3: optional Istio management.** Agree on bootstrap, node/workload
   identity, certificates/SDS, lifecycle, and configuration ownership. Early
   interface review is useful, but Istio is not an initial dependency and no
   second transparent proxy is introduced.

### Later Vault and Istio boundaries

Vault storage alone does not enable HTTPS injection. Milestone 2 needs TLS
termination, suitable sandbox-trusted certificates, an HTTP-processing adapter
to the local Go Vault, and verified upstream TLS. `tcp_proxy` alone cannot
modify HTTP headers. The adapter protocol and certificate provisioning must be
reviewed; neither is assumed to be provided automatically by Envoy.

Before advertising Vault support, preserve full binding checks, placeholder
behavior, credential isolation, streaming, and **per-request response-header
redaction when a provider echoes an injected secret**. Redaction must retain
knowledge of the credential used by an in-flight request across rotation, rather
than consult only the newest vault value. Unsupported binding forms must reject
explicitly; a limited prototype is not full Vault parity. Include response
redaction and rotation tests before releasing any credential-injection profile.

Istiod integration also needs more than compatible xDS messages. The proposal
must not create competing local and mesh owners of the same LDS/RDS/CDS
resources, assume standard mesh mTLS provides provider HTTPS interception, or
claim that Istiod automatically provisions MITM leaf certificates. The current
service-mesh compatibility warning remains valid until a supported integration
profile is implemented and tested.

## Test Plan

These are planned acceptance tests. No Envoy runtime tests are claimed by this
proposal-only PR.

**Milestone 1:**

- Default-omitted behavior and existing mitmproxy/DNS/nft tests remain unchanged.
- Selection validation and explicit rejection of Vault/addon incompatibilities,
  including runtime mutation attempts.
- Fixed HTTP targets with positive/negative host policy and original-destination
  checks; no policy-bypassing rewrites.
- Opaque HTTPS responses with normal client certificate verification; SNI-required
  policy rejects missing or mismatched information without treating it as HTTP
  credential authorization.
- Capture ordering, UID/mark exemptions, DNS resolution, private/network-denied
  destinations, address-family restrictions, and no forwarding loops.
- Startup config rejection, proxy crash/restart, shutdown, and recovery without
  an unintended direct-egress window. Reload/NACK cases where reload is offered.
- Fresh creation, Pool template creation, and replacement; snapshot/restore must
  reinitialize ephemeral proxy/capture state safely.
- Explicit runtime compatibility results. Do not infer gVisor, Kata, or fleet
  support from a runc-sidecar test.
- Measured image size, memory, CPU, latency, and streaming behavior against the
  current baseline; no projected performance advantage is assumed.

**Later gates:** differential Vault binding/placeholder tests; wrong CA, hostname,
SNI, authority and credential-access negatives; provider-echo response-header
redaction across rotation; HTTP/1.1, HTTP/2, large uploads and SSE; applicable
revision fences and request draining; separate Istio ownership and lifecycle
conformance. Backend availability is not evidence these later capabilities work.

## Drawbacks

Maintaining two L7 backends adds dependency, operational, and compatibility
costs. The first milestone deliberately cannot serve workloads that require
Vault injection. A later TLS/Vault implementation remains substantial security
work, and Istio integration is not guaranteed by the initial choice of Envoy.

## Alternatives

- **Keep mitmproxy only:** least migration work and preserves current addons;
  remains the default and a valid operator choice.
- **Merge #1221 wholesale first:** retains its broader extension-resource work,
  but does not itself supply the missing Envoy enforcement backend.
- **Implement Vault first:** has no working Envoy foundation on main to integrate
  with and obscures the first reviewable deliverable.
- **Inject a second mesh proxy:** leaves the documented transparent-capture
  conflict unresolved.
- **Require Istio initially:** couples backend adoption to another control plane
  before lifecycle and traffic correctness have been established.

## Infrastructure Needed

A pinned Envoy build, isolated Linux test environments, and controlled HTTP/TLS
fixtures. The first milestone needs no new database, provider account, cluster
policy controller, production credentials, or mandatory service mesh.

## Upgrade & Migration Strategy

Existing deployments keep their defaults. Enable Envoy only on newly created
sandboxes with supported configurations. Backend selection is immutable for a
sandbox generation; do not switch active connections between engines.

Pool templates must select the backend before Pods are created. Replacing or
rolling back a sandbox uses existing supported workspace/state recovery and
lifecycle mechanisms. No preservation of process memory, live sockets, or
zero-downtime replacement is promised. Vault-dependent workloads stay on
mitmproxy until the later backend capability is explicitly available.
