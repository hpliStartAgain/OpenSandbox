# OSEP-0023 live credential-bound Vault loop: candidate evidence

Candidate: branch `feat/osep0023-live-vault`, commit `a90a4133`, based on the
merged PR #2172 head (`447a7be3`, "verify quarantine across older nft readback
formats"). All results below were produced on this candidate with a clean
worktree.

## Scope of this slice

Wired and verified in the experimental sidecar profile only:

- a real Vault binding is installed through the revision transaction and takes
  over new TLS connections for its hosts;
- matching requests receive header credentials; unbound HTTPS is never
  decrypted;
- credential rotation switches per request, including on one HTTP/1.1
  keepalive connection;
- removing the final binding fences tracked connections permanently and
  force-closes them at the drain deadline, and remove/re-add cannot revive a
  retired connection.

Deliberately not in this slice: HTTP/2 GOAWAY and stream drain, the
fast-sandbox subject profile, dynamic policy and always-rule reload
participation, ECH detection (the mitmproxy 11 ClientHello API does not expose
it; the outer SNI is the visible name and injection still requires the full
request binding match plus SNI/authority agreement), and recovery across a
complete sidecar replacement.

## Evidence layers

Unit tests do not substitute for the real-image run, and no environment skip is
reported as a pass.

### 1. Go unit and cross-language IPC integration

```
cd components/egress && umask 022 && go test ./...
```

Result: 18 packages `ok`, no failures. New coverage includes:

- `TestRevisionWriteHandler*` (create/patch/delete through the mutation
  transaction, required `expectedRevision`, stale-revision conflict, fixed
  error vocabulary, indeterminate outcome fails closed);
- `TestExperimentalRevisionRuntimeRejectsVaultWritesWithoutMitm`;
- `TestRevisionVaultMutationSanitizesCandidateAndSessionFailures`;
- `TestRevisionVaultMutationIPCChildLiveAdmission`, which runs the real Go
  Store/ProcessSession/coordinator against a Python child using the production
  authenticated IPC endpoint and the admission-enabled `LiveReceiver`;
- `TestBuildMitmdumpEnvHandsOffLiveAdmissionBundle` and the live-admission
  validation cases.

`umask 022` is required on hosts whose umask is `0002`: `t.TempDir()`
subdirectories then inherit group-write and the atomic policy store's
fail-closed parent check rejects them. This affects pre-existing
`pkg/policy` tests identically at the base commit and is not caused by this
candidate.

### 2. Python addon unit tests

```
cd components/egress && python -m unittest discover -v -s tests -p "test_*.py"
```

Result with `mitmdump` present (CI parity, run in a container with
mitmproxy 11.0.2): **309 tests, OK, no skips**. Without `mitmdump` on PATH the
22 mitmproxy-dependent tests skip and the remaining 287 pass.

New coverage: `tests/test_credential_bound.py` (28 live-admission unit cases:
bootstrapping deny, active-empty and unbound pass-through, invalid SNI deny,
registry exhaustion, authority/SNI agreement, rotation per keepalive request,
fence persistence across remove/re-add, drain expiry, rejected payload
agreement, live-bundle validation) and `tests/test_credential_bound_runtime.py`
(6 real-mitmdump cases: deny with no snapshot, bound decrypt + credential,
unbound and no-SNI end-to-end with the origin's own certificate verified,
wrong path/method, keepalive rotation, removal fence and pass-through return).

### 3. Real Docker image end-to-end

```
python components/egress/scripts/test_live_vault_image.py --image <egress image> \
    --artifacts <evidence dir>
```

Result: `TestLiveVaultImagePrerequisites`, `TestUnboundTrafficKeepsEndToEndTLS`,
`TestBoundHostInjectsCredential`, `TestRotationStaleAndKeepalive`,
`TestDeleteRevocationAndRemoveReadd`, `TestFailureBoundaries` — all **PASS**
(6/6). The run exercises the real sidecar entrypoint on a Docker network with
an independent HTTPS origin that verifies received credentials, and asserts:

- a client trusting only the origin CA completes HTTPS to an unbound host
  (end-to-end TLS intact, no credential delivered);
- a bound host is decrypted and the origin receives the injected credential
  only on the exact path and method;
- rotation switches the credential on one keepalive connection, and a stale
  `expectedRevision` conflicts;
- removal fences the live transport (403, no credential), re-adding the host
  over that same transport still denies, new connections become opaque, the
  idle retired transport is force-closed at the drain deadline, and a fresh
  create is usable again;
- a client without the MITM CA cannot complete TLS to a bound host, an origin
  presenting the wrong certificate never receives the request, no-SNI traffic
  passes through with the origin's own certificate, and an unauthorized API
  call is rejected.

The same script is wired into `.github/workflows/egress-test.yml` and runs
there against an image built by the ordinary Dockerfile. Two environment notes
for local reproduction:

- On a host whose Docker daemon has exhausted its predefined address pools the
  script allocates an explicit private subnet; on a Docker user-defined network
  the embedded DNS at `127.0.0.1:53` is reached through the daemon's own
  `DOCKER_OUTPUT` chain before the sidecar's port-53 redirect, so the script
  pins the origin addresses and allows them statically instead of relying on
  DNS-learned dynamic entries. Kubernetes deployments resolve through a
  non-loopback cluster DNS and keep the dynamic path.
- The local run used an image assembled from the candidate's own binaries and
  scripts on top of runtime layers built from the byte-identical
  `components/egress/Dockerfile` at an earlier commit, because the local Debian
  mirror could not finish the `apt-get` layer within the build timeout. CI
  builds the image from source.

## Evidence hygiene

Test output and this document contain no credential values: the image test
masks the injected header to a length marker, the origin fixture records only
header names, and runtime failures are reported through fixed error classes.

## Resource cleanup

The image test removes its containers, network and temporary directories in a
`finally` path, and the Go/Python suites clean up their temporary sockets and
processes; a leaked container or socket is a test failure, not a warning.