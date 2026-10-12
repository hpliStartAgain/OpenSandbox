# Read-only assessment: process-owner fallback

Status: candidate design amendment only. No implementation, process termination, deployment, or additional runtime test was performed. Source baseline is `98fc6ce404d683e80b86f86e5c817b36658dcde1`.

## Recommended option to review

For the narrowly identified state where ordinary connection termination cannot be proved, terminate the **mitmdump child process itself** and reuse the existing generation-tagged Go OnExit/recovery owner. A Python hard self-exit would avoid manual writer.close, dependency changes, and a new IPC message. It is nevertheless NEW runtime behavior requiring explicit design approval and fresh verification. Ordinary refusal, successful drain, and routine peer reset must not become whole-process fatal events.

Actual termination releases the owning process's sockets independently of cooperative asyncio cancellation. It does not prove origin business work stopped, a request succeeded, or a request is safe to replay.

## Existing mechanisms that can be reused

- `revision_launch.go:206–208` binds the owner's stop function to GracefulShutdown with a one-second TERM grace period.
- `pkg/mitmproxy/stop.go:44–67` sends TERM, then KILL if needed, and waits for child completion.
- `pkg/mitmproxy/launch.go:201–212` obtains completion from cmd.Wait before invoking OnExit.
- `mitmproxy_transparent.go:112–118` and `revision_launch.go:147–159` close the revision session only after the exact child is stopped/reaped.
- `revision_mutation.go:188–205` already contains a failed-transaction containment/detach/stop path. It must not be reused by inventing a failed revision transaction.

The one-second grace is not a one-second total cleanup guarantee. SIGKILL/reap has no final deadline; `revision_mutation.go:43–50` already documents the lack of a hard recovery deadline. Launch manages one PID with Credential configuration (`pkg/mitmproxy/launch.go:185–191`), not a process group or cgroup. Arbitrary addon descendants or inherited descriptors are outside this demonstrated ownership guarantee. cmd.Wait also includes the child output-copy drain.

## Missing trigger

There is currently no Python runtime-fatal-to-Go-stop path:

- `system.py:189–193` and `credential_bound.py:63–66` raise SystemExit for configuration failures.
- `credential_bound.py:267–290,314–319` schedules normal handler.close_connection; it does not notify Go to stop the child.
- `revision_ipc.py:190–228` supports prepare/commit/abort/active, with no fatal message or child-to-owner alarm.
- LiveRuntime.close and system.done stop local runtime/IPC bookkeeping; they do not prove every transport terminated.

Consequently, merely saying “reuse Go stop” does not supply the required new trigger. A hard self-exit plus existing OnExit is the smallest no-new-IPC candidate. A Go-first containment→stop design could reuse lower-level primitives, but needs a separately reviewed signal, authentication/identity, and lock-order path.

## Cooperative shutdown is insufficient evidence

In fixed mitmproxy 11.0.2, master.shutdown schedules should_exit, while master.run/done still await addon done hooks (`master.py:79–103`; `addonmanager.py:265–294`). SIGTERM invokes this cooperative path (`tools/main.py:116–123`). SystemExit may enter Python asyncio shutdown, whose cancellation gather has no timeout (`Python 3.12 runners.py:65–77,198–206`). These operations are not evidence of an unconditional timely exit when an addon does not cooperate.

A hard self-exit is a distinct design choice, not a behavior already present in the Python addon. No hard exit was added in this checkpoint.

## Availability and recovery cost

For the experimental revision runtime with nft sidecar enforcement:

1. A current, owned, unexpected child exit lowers readiness and latches recovery (`mitmproxy_transparent.go:211–235`).
2. Recovery invalidates bootstrap tickets, sets the sticky unhealthy state, quiesces nft writers, and attempts namespace quarantine (`revision_recovery.go:119–140`).
3. The watcher closes the exited child's session; restart stops on recovery-required (`mitmproxy_transparent.go:435–438,482–493`).
4. No runtime unfence/reset exists. New bootstrap and ready publication are rejected while recovery is latched (`revision_recovery.go:68–80,143–147,174–176,207–235`).

Collateral impact exceeds the implicated client/upstream pair: every H1/H2/proxy connection in the mitmdump process is interrupted. Confirmed quarantine drops the original network namespace's IPv4/IPv6 input/output/forward without loopback, established-flow, DNS, proxy-UID, or control/health exceptions (`pkg/quarantine/fence.go:34–42,82–95`; `docs/architecture/network/egress.md:311–319`). Existing recovery guidance requires destroying/recreating the sandbox, not merely restarting the Go process or container (`egress.md:321–330`).

Quarantine applies only to the experimental+nft profile (`revision_quarantine.go:52–60`). Its installation/readback can fail and remain QuarantineUnknown (`revision_quarantine.go:62–84`). Process exit and a 503 response do not prove namespace packet isolation. No packet tests were run here.

Do not substitute killing the Go sidecar itself: that can bypass the current child's OnExit containment owner. Normal shutdown deliberately does not request a new fence (`mitmproxy_transparent.go:80–90,217–232`; `shutdown.go:41–45,71–79`).

## Required proof if this amendment is approved

- Trigger only the exact exceptional terminal failure, with unrelated normal refusal/drain/reset paths unchanged.
- Demonstrate real mitmdump process death and owner reap; do not infer it from SystemExit, cancelled tasks, or logs.
- Verify current-generation ownership and stale-exit exclusion.
- Verify session disposal, health/recovery latching, and refusal of re-bootstrap/ready publication.
- On an authorized Linux runner, verify packet containment and QuarantineUnknown behavior separately.
- Record collateral connection failures and the sandbox recreation requirement; never count this as graceful drain.

P0 remains STOP until a revised contract is approved and its new boundary is proved. This assessment does not select or authorize an implementation.
