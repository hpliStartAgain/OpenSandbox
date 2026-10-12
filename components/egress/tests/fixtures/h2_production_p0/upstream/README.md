# P0 upstream ownership and termination proof

Date: 2026-10-12. Gate result: **STOP before production implementation**.

The positive ownership, mapping, and ordinary close seams work in the pinned pure layers. The complete P0 gate does not pass: cancellation while a supported asynchronous `server_connected` addon is awaiting can leave an established upstream writer open. Repeating the normal `CloseConnection` command does not close that writer. The approved design requires proof of actual related-upstream termination and does not authorize direct writer manipulation, dependency patches, or silently excluding supported user addons.

## Scope and reproducibility

- Approved design SHA-256: `67d37962c19c0ff96c388dad96c9d53ff0665cf9584abddfe775ec9126ced383`.
- Python 3.12.14, mitmproxy 11.0.2, h2 4.1.0, hyperframe 6.0.1.
- No network, sockets, AF_UNIX, TLS runtime, real-origin traffic, IPC runtime, user-computer access, dependency changes, or production-file edits.
- `proof_upstream.py` uses real HttpLayer → HttpClient → Http2Client, and real ServerTLSLayer → HttpClient while connecting. Peer H2 frames are parsed/generated in process with h2.
- `proof_pending_tasks.py` uses real asyncio Tasks and unmodified mitmproxy `ConnectionHandler.server_event`, `open_connection`, and `close_connection`. The test scheduler advances BaseEventLoop ready Handles without starting a reactor. Its negative case supplies a synthetic asyncio.Transport through a test BaseEventLoop implementation of `create_connection`; the actual asyncio API constructs a real StreamReader/StreamWriter. No dependency functions are replaced. An audit guard rejects socket creation; observed attempts: zero.
- These are pure protocol-layer and pure task-scheduling/model proofs. They are not wire/runtime or production verification. A passing negative regression test records the failed safety property, not a passing P0 gate.

Run:

```sh
/workspace/scratch/1982e08ae44a/osep0023-venv/bin/python /workspace/shared/h2-p0-upstream-proof/proof_upstream.py
/workspace/scratch/1982e08ae44a/osep0023-venv/bin/python /workspace/shared/h2-p0-upstream-proof/proof_pending_tasks.py
```

Latest run: 16 layer tests passed in 0.038 s; 2 scheduling tests passed in 0.009 s. The scheduling positive test contains three cancellation subcases. The scheduling negative test demonstrates the stop condition.

## Positive evidence

1. Established upstream association is read-only and unique through `flow.server_conn`, its exact HttpLayer-owned child chain, `our_stream_id`, and reciprocal `their_stream_id`.
2. Arrival order is independent of inbound client IDs: delaying inbound 1 at requestheaders allows inbound 3 to map to upstream 1, followed by inbound 1 mapping to upstream 3. This confirms that upstream IDs must never define the downstream GOAWAY bound.
3. At MAX_CONCURRENT_STREAMS=1, subsequent request events stay in the dependency's client-ID-keyed `stream_queue` without an upstream ID. Normal completion frees the slot and the dependency itself maps/transmits the queued stream.
4. Connecting flows retain the original `flow.server_conn` until GetHttpConnectionCompleted. The exact pending `waiting_for_establishment` entry and `command_sources` HttpStream with identical flow object uniquely identify the real pending Server and owned ServerTLSLayer → HttpClient. This pending exact identity must be checked **before** static flow.server_conn lookup, including when the original server owns a dead old H2 child and a replacement connection is opening.
5. Response completion and even HttpLayer DropStream can occur while upstream DATA plus END_STREAM or request trailers remain buffered. Normal upstream WINDOW_UPDATE subsequently emits the pending output and closes the H2 stream. Therefore response hook/DropStream alone cannot release admission capacity or deadlines.
6. `early response completed → upload unfinished → client RST` leaves a genuine upstream orphan: HALF_CLOSED_REMOTE with no upstream reset, including when no DATA buffer exists. An upstream open stream is itself an unfinished obligation. Reset before completed response (including after headers only) does propagate and close the upstream stream. RST queued while the response hook is paused also produces the orphan after completion.
7. Normal CloseConnection commands emitted by the test-only downstream instance adapter pass through the real HttpLayer to the exact client and verified owned upstream. Synthetic acknowledged ConnectionClosed callbacks in either order leave the upstream H2 child `done`, its active stream table empty, and HttpLayer streams empty. Late WINDOW_UPDATE and repeated callbacks emit no further SendData.
8. The dependency retains inert stream_queue, buffered data, trailers, and mapping objects after abnormal close. The harness never erases them. Abnormal termination is proved by terminal ownership/transport state; it is not misreported as gracefully drained output.
9. The downstream adapter's outer `handle_event` survives the base class replacing `_handle_event` with `done`; HttpLayer can route a RequestWakeup to it. However, this is only a layer-routing proof. Actual `handle_client` cancels wakeup timers before ClientDisconnectedHook and before awaiting upstream transport termination. A timer alone cannot guarantee final upstream observation after client teardown.
10. Cancelled connection attempts that reach the TCP/UDP connect try/except can emit OpenConnectionCompleted(error), which clears waiting/source/stream maps. Cancellation before task start, while awaiting ServerConnectHook, or while waiting on the connection semaphore emits neither completion nor error/disconnected hooks. A read-only observer of the verified exact transport Task proves these three tasks terminal and writer-free without fabricating callbacks or clearing pending dependency maps.

## Decisive negative case

`test_negative_cancel_inside_server_connected_leaves_writer_open` observes this exact sequence:

1. Real `ConnectionHandler.server_event` creates the OpenConnection task and opening ConnectionIO (writer absent).
2. Unmodified `open_connection` obtains the synthetic transport through real `asyncio.open_connection`. It sets TCP setup metadata and replaces `transports[conn]` with a new ConnectionIO containing the actual StreamWriter.
3. A supported async ServerConnectedHook waits on a Future. `open_connection` has not reached its `try: await handle_connection(...) finally: ServerDisconnectedHook` block.
4. The test-only adapter rechecks exact ownership and yields normal CloseConnection(client) and CloseConnection(upstream). Unmodified server_event and close_connection cancel the real upstream task.
5. The task becomes done/cancelled, but the **current** StreamWriter is still open, current ConnectionIO remains registered, and neither ServerDisconnectedHook nor ServerConnectErrorHook nor OpenConnectionCompleted occurs.
6. A second normal CloseConnection repeats task.cancel on the completed task and still does not close the writer.
7. A conservative current-IO-aware terminal predicate rejects the result. Trusting the stale captured opening IO.writer=None would falsely declare success.

The fixture closes only its synthetic writer directly afterward for test cleanup. This is explicitly not an approved production recovery and does not change the failed gate result.

Relevant fixed-version source:

- `proxy/server.py` 240–259: replace ConnectionIO, await ServerConnectedHook, then emit OpenConnectionCompleted.
- `proxy/server.py` 260–269: only the later handle_connection block has the ServerDisconnectedHook finally.
- `proxy/server.py` 440–463: normal full close marks connection CLOSED and cancels its task; it does not directly close the writer.
- `proxy/server.py` 166–181: wakeup timers are cancelled before client_disconnected; teardown later only cancels/awaits transport tasks.
- OpenSandbox supports additional scripts through `ScriptPaths` / `OPENSANDBOX_EGRESS_MITMPROXY_SCRIPT`. Therefore silently assuming a closed, synchronous-only addon set would change the supported scope.

## Required next decision

Stop at this seam and return to design review. A solution would need an explicitly reviewed recovery/ownership boundary that proves writer termination for this supported cancellation window. No direct-writer close, dependency patch, scheduler replacement, or user-addon restriction is proposed as already authorized or implemented.

## Frozen artifacts

| Artifact | SHA-256 |
|---|---|
| proof_upstream.py | ff052cfa21091671b460f6ef84d983f194b2477ca379f3c00c64389fd0fb074c |
| proof_pending_tasks.py | f6c5294ef1fe33573298d8f9e0735fef213feae8cba53dd85a5aef8c19a3b7ca |
| proof_results.json | a84164f31ae9b147e8c0c8a2e5a697a39e80250a7d9083ae3aa371836d0a8180 |
| pending_task_results.json | 64a6cc91d9b0947aab0e65b0ee665a6ba431b1116552d6413fbd0a27b3fe3fcf |

Pinned dependency source SHA-256:

- proxy/server.py: 51f6e28cae162e05e3a4cc94f78c006ca1c1a7025f1f0fe8c9644199f25d1283
- proxy/layers/http/__init__.py: 31ac9b46d890c9785a5058ce8e6b0ade3378151afb4a9680fe7c910bee3e9106
- proxy/layers/http/_http2.py: cc8a9eb05eedec8dc91e67216c3bd81acbe5fc07cb86f5d123312f3bc098ab74
- proxy/layers/http/_http_h2.py: 62b992b8e61893a69e673c6bb54753a12cb7171b6a3ed7865718e116b13d8559
