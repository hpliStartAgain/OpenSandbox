---
title: OSEP-0023 delayed-GOAWAY experiment
description: An isolated alternative timing experiment with explicit in-process and live-wire evidence boundaries.
---

# OSEP-0023 delayed-GOAWAY experiment

This test-only experiment investigates a different timing contract:

1. Fence new admission at revision cutover.
2. Keep the H2 state OPEN while already admitted streams finish.
3. Refuse later streams with RST_STREAM(REFUSED_STREAM), without simulated upstream dispatch.
4. After old streams and the modeled writer queue finish, send ordinary GOAWAY with the frozen admission bound.
5. Immediately request closure of the now-empty connection and enter the normal terminal layer handler.

The [original interface diagnostic](./osep-0023-h2-transport-probe.md) remains
unchanged. Its E1 requirement was to continue old streams **after** GOAWAY.
This candidate does not meet that requirement and does not change the OSEP,
production addon, dependency pin, public configuration, Fast Sandbox, or CI.

## What the isolated checks establish

The fixture uses genuine, unmodified mitmproxy 11.0.2 `Http2Server`, h2 4.1.0,
and hyperframe 6.0.1 objects, plus the existing `LiveReceiver` and registry.
They exchange serialized protocol bytes in memory. There is no socket, TLS,
real origin, HttpFlow/requestheaders hook, authenticated IPC, or running proxy.

| Case | In-process observation |
| --- | --- |
| D1 | Higher IDs are REFUSED, repeated HPACK entries remain usable, the simulated upstream receives only admitted requests, and final GOAWAY retains the lower frozen bound. |
| D2 | A finished request handle is insufficient: stream flow control and queued END_STREAM still delay GOAWAY. An independent h2 peer observes END_STREAM before final GOAWAY. |
| D3 | Admission plus stream/handle mapping and commit plus bound freezing share an explicit bridge lock. Both controlled race orders preserve the fence. |
| D4 | One reset preserves another handle; duplicate commit and remove/re-add retain the first deadline and fence; expiry requests forced closure, with cleanup on modeled disconnect. |

Additional unit cases cover completed higher-ID streams in the frozen bound,
HEADERS/CONTINUATION split across cutover, same-packet refused HEADERS and padded
DATA, stream and connection backpressure, exact-window empty END_STREAM,
multi-frame response bodies, trailers, late input, same-batch HEADERS/reset,
admitted uploads whose responses finish first, and idempotent disconnect.
All payloads and revision labels are synthetic; reports retain no bodies,
headers, credentials, IPC tokens, or TLS key logs.

The bridge lock is part of the candidate algorithm, not a test barrier that
silently supplies atomicity. It wraps the existing publication owner and keeps
its Registry → Receiver ordering. Every admission and commit in this isolated
fixture enters that boundary. Wiring real IPC and requestheaders into it is
unimplemented; the thread test is not authenticated-IPC evidence.

## Output completion is an explicit unresolved integration boundary

The fixture distinguishes:

- Request-handle completion.
- Protocol bytes produced by `SendData` or `data_to_send()`.
- Bytes retained in its modeled writer queue.
- An explicit modeled writer-completion callback.
- Independent peer decoding of those bytes.

GOAWAY readiness uses the modeled writer completion, not the peer's events as
an oracle. This callback is a test transport assumption, not an existing
mitmproxy addon API. The real server processes `SendData` using `writer.write`;
that is not proof of TLS/kernel flush or client receipt. The real integration
must preserve ordering and verify complete payload, END_STREAM, GOAWAY, and
close at the client before this hypothesis can pass live acceptance.

The final close is necessary on this pin. Feeding late input into CLOSED h2 can
produce another GOAWAY using `highest_inbound_stream_id`, including refused
streams. That can increase the previously frozen bound. A negative-control
test reproduces the increase; the candidate's normal terminal layer handler
ignores that late input. The actual `SendData` → `CloseConnection` delivery
behavior still needs a real TLS test.

## Known conservative fallback

On this dependency version, reset clears queued body data but can leave
`stream_trailers` behind. The fixture reports this residual buffer through a
unit test and conservatively refuses to declare graceful completion. The
existing deadline/close path remains the fallback. It does not patch the
dependency, erase its buffer to manufacture a pass, or count this fallback as
graceful draining. A continuation needs an explicit decision and validation
for this cancellation edge case.

REFUSED_STREAM establishes a retryable refusal; it does not make a particular
client open a replacement connection. Client retry and connection-pool behavior
are outside the in-process result.

## Run and evidence

From `components/egress`, using the pinned mitmproxy environment:

```sh
python -m unittest discover -v -s tests -p 'test_h2_delayed_goaway.py'
python -m unittest discover -v -s scripts -p 'test_h2_delayed_goaway_probe.py'
python scripts/h2_delayed_goaway_probe.py --artifacts /tmp/h2-delayed-evidence-unique
```

The new directory must not already exist. A successful in-process candidate
still returns exit 2 because live acceptance is blocked. Candidate or evidence
failures return exit 1. Missing dependencies and wrong versions remain explicit
blockers. The runner is not a permanently failing product CI step.

The report separates D1–D4 from required live cases:

- W0: production negative baseline and real client-ID/flow/handle identity.
- W1: live fence/refusal, HPACK/flow control, and zero origin processing outside the bound.
- W2: client TLS evidence for complete old payload and END_STREAM before the single frozen-bound GOAWAY and final close.
- W3: authenticated IPC cutover races, revision pinning, retries, and remove/re-add.
- W4: real reset/disconnect cleanup and both short and default 30-second deadlines.

W0 is not run; W1–W4 remain blocked. `original_E1_passed` and
`live_transport_executed` remain false even when all D cases pass. No real-client
frame or origin logs are fabricated. The manifest records the exact source
identity and the task-scoped dirty diff; cleanup names only resources the
in-process runner actually created.

## Next validation gate

The smallest useful next experiment is W2 in a permitted local executor: a
test-only real mitmdump layer adapter, verified local TLS client and origin,
actual decoded client frames, withheld flow-control credit, and an assertion
that final closure truncates neither old payload nor GOAWAY. Check refused
requests against the real origin log in the same run. Repeating the pure
runner cannot establish these properties.

Publishing a branch/PR or triggering CI requires its own authorization.
Production wiring, dependency changes, or acceptance of the changed GOAWAY
timing requires a separately reviewed design. This isolated result grants none
of those approvals.


## Prepared real-TLS W2 fixture

The separate runner below is prepared for a permitted local environment. It has
not been executed in the restricted cloud workspace. Its pure adapter and
report-validation tests are not real-wire evidence.

```sh
python -m unittest discover -v -s tests -p 'test_h2_delayed_goaway_wire_addon.py'
python -m unittest discover -v -s scripts -p 'test_h2_delayed_goaway_wire.py'
python scripts/h2_delayed_goaway_wire.py --artifacts /tmp/h2-w2-evidence-unique
```

Use the same Python environment for all commands, with exact versions
`mitmproxy==11.0.2`, `h2==4.1.0`, and `hyperframe==6.0.1`. The runner requires
loopback sockets and subprocesses, uses temporary verified client/origin TLS
certificates, and never loads the production addon. It does not inherit a TLS
keylog destination or publish private TLS material in the evidence directory.

The adapter reuses the configured `NextLayer` selector, then populates only the
unstarted `HttpLayer.connections[client]` slot preserved by its playback seam.
It adapts that one receiving `Http2Server` instance. All DATA, resets, GOAWAY,
and connection closure go through the existing protocol APIs and commands.
No global dependency patch or state restoration is involved.

An ordinary `RequestWakeup` polls a local synthetic fence control file and
commits through the existing receiver. This is not authenticated revision IPC.
The real response hook finishes the admission handle while stream output may
still be buffered. The adapter waits for both stream directions to be closed,
empty DATA/trailer buffers, and preceding `SendData` commands to be consumed
before ordinary GOAWAY and close. Command consumption is not TLS flush; the
client's independent frame decoder and h2 peer decide whether delivery worked.

The single bounded scenario uses an HTTPS/H1 origin, one old H2 stream, refused
streams 3 and 5 with HPACK insertion/reuse, a 1 KiB client receive window, a
complete synthetic payload, END_STREAM, GOAWAY(last=1), and EOF. The origin must
observe exactly the old request. It does not test upstream-H2 ID remapping,
client-library retry behavior, authenticated IPC races, or the default deadline.
The test-only drain deadline is 15 seconds; hitting it is a failure, not graceful
completion.

Exit 0 means only this W2 scenario passed actual client/origin evidence. Exit 1
means protocol/evidence failure; exit 2 means environment/dependency blocked.
The report keeps original E1, production readiness, and the other W cases
unpassed. Save the exact HEAD/tree, source fingerprints, client frames/events,
origin request log, proxy command metadata, result, and cleanup report together.
The fixture is not attached to existing product CI.
