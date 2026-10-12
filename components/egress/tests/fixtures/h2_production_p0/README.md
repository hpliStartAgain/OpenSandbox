# OSEP-0023 production H2 P0 checkpoint: STOP

Date: 2026-10-12. This is an isolated evidence checkpoint, not production H2 integration.

## Decision

P0 fails the approved guarantee that every owned upstream obligation can be terminated through normal connection commands. P1–P3 must not begin under that contract. No production source, dependency, IPC format, workflow, or deployment changed. No remote branch/PR/CI operation was performed.

Approved design identity: SHA-256 `67d37962c19c0ff96c388dad96c9d53ff0665cf9584abddfe775ec9126ced383` (22,660 bytes). D1 delayed GOAWAY and D2 Go 1.25.9 synthetic-GET acceptance scope were approved on 2026-10-12 at 05:01:30 UTC. Those decisions remain unchanged; the blocker concerns exceptional upstream termination.

Baseline: upstream main `98fc6ce404d683e80b86f86e5c817b36658dcde1`, tree `907b2b068f4189ae8c727a5be5dbfad45b596855`. Egress source, OSEP-0023, and root AGENTS are unchanged from the design's `b57f7db` baseline. The implementation branch `feat/osep0023-h2-admission` remains clean at this main revision. Historical negative checkpoint `65f621b7` and the prior W2 evidence remain independent and unmodified.

## Decisive negative case

The fixed mitmproxy 11.0.2 `ConnectionHandler.open_connection` installs a new `ConnectionIO` holding a live `StreamWriter`, then awaits `ServerConnectedHook` before entering `handle_connection` and its cleanup path.

A supported asynchronous user addon can pause that hook. The proof then:

1. Identifies the exact owned upstream using the real HttpLayer/HttpClient connection and pending-command identities.
2. Emits normal `CloseConnection` through the test-only per-instance H2 adapter → actual HttpLayer → unmodified ConnectionHandler.server_event.
3. Observes the task become completed/cancelled and `connection.state` become CLOSED.
4. Still observes the current real StreamWriter open, with the transport registered and no server-disconnected/error completion callback.
5. Repeats normal close and observes the same open writer.

A task-done check and a CLOSED connection flag both produce false terminal conclusions in this case. Inspecting the old opening ConnectionIO is also unsafe: the dependency replaces it on successful connect, so its absent writer is stale evidence.

This is within the existing product configuration boundary: `components/egress/pkg/mitmproxy/launch.go:101–103,270–278` supports user ScriptPaths after the system addon, and `mitmscripts/system.py:59–60` documents this feature. Absence of asynchronous addons cannot be adopted as an unreviewed requirement.

The negative test uses real asyncio.open_connection/StreamReader/StreamWriter with a per-instance test event loop supplying a synthetic asyncio.Transport. It uses no socket, network reactor, dependency monkeypatch, dependency source modification, or global replacement. An audit hook records and rejects any socket creation; all cases report zero socket attempts. The direct writer.close at the end is **fixture cleanup only**, not an approved production fix.

Dependency source evidence:

- [Install IO, then await the connected hook before cleanup](https://github.com/mitmproxy/mitmproxy/blob/v11.0.2/mitmproxy/proxy/server.py#L244-L266)
- [Normal close only marks CLOSED and cancels the task](https://github.com/mitmproxy/mitmproxy/blob/v11.0.2/mitmproxy/proxy/server.py#L440-L463)
- [Client teardown cancels wakeups before final upstream cleanup](https://github.com/mitmproxy/mitmproxy/blob/v11.0.2/mitmproxy/proxy/server.py#L164-L183)

Installed server.py SHA-256: `51f6e28cae162e05e3a4cc94f78c006ca1c1a7025f1f0fe8c9644199f25d1283`.

## Executed checks and evidence meaning

Environment: existing cloud Python 3.12.14, mitmproxy 11.0.2, h2 4.1.0, hyperframe 6.0.1.

- 11 admission/selector tests: pass.
- 16 upstream-layer tests: pass.
- 2 task-scheduling tests: pass, including the negative regression above. **These 29 green test results establish a P0 STOP, not a P0 pass.**
- 69 pre-existing registry tests: pass.
- 22 pre-existing publication/race tests: pass.
- Independent read-only review re-ran all 29 final P0 tests and confirmed the blocker and file identities.

Useful established interfaces include raw pre-transparent pseudo-header capture, exact Request identity through requestheaders, once-only consumption, instance selector installation, precise marked kill/REFUSED handling, separate 400/413 exceptional close, no upstream commands for refused flows, three-table cleanup, upstream stream-ID reorder/concurrency queues, pending-first association over stale flow.server_conn, buffered and no-buffer upload obligations, and terminal observation for cancelled preconnect tasks with no IO.

Several cautions are part of the evidence:

- Preserve the dependency generator's protocol-stop return. Independent review found and corrected an initial fixture error that discarded it; malformed stream 1 plus valid stream 3 in the same batch is now a regression.
- Finished response hooks do not end upload obligations.
- Native reset may strand trailers even with empty DATA buffers and a CLOSED H2 stream.
- Dead dependency objects may retain inert buffers/maps. Do not clear them to manufacture drain success.
- A pending task may be cancelled before startup, during ServerConnectHook, or in a semaphore without error/completion callbacks.
- Client teardown cancels RequestWakeup tasks. They cannot be the only finalization mechanism.

## Run the isolated proofs

Use an interpreter with the exact dependencies above. From this directory:

```sh
python admission/test_admission_seams.py
python upstream/proof_upstream.py
python upstream/proof_pending_tasks.py
```

The last two scripts rewrite their local JSON observations. Logs and JSON in this checkpoint are the frozen results; reruns do not make production/runtime claims.

## Coverage boundary

- P0 interfaces: fresh observations; terminal guarantee is a fresh failure.
- P1 owner/lifecycle implementation: not started.
- P2 production addon + real authenticated Unix IPC: not started. Previously denied cloud AF_UNIX operations were not retried.
- P3 Go automatic retry and Linux transparent 443: not started; no privileged/network execution was attempted.
- H2-A0–A5 production acceptance: missing, not passed by these fixtures.
- Prior W2: historical single-scenario real-transport feasibility only. It is not fresh evidence for this production integration.

Next action is a narrowly reviewed design amendment for the exceptional termination boundary. See PROCESS_STOP_ASSESSMENT.md for the requested read-only evaluation of the existing process owner. No choice has been implemented or silently adopted.
