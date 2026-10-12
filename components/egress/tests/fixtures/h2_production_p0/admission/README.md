# OSEP-0023 P0 admission interface evidence

This directory contains test-only, socket-free evidence. It does not implement the production addon and does not validate TLS, authenticated IPC, transparent port 443, or Go client retry behavior.

## Frozen inputs

- Approved design SHA-256: `67d37962c19c0ff96c388dad96c9d53ff0665cf9584abddfe775ec9126ced383`.
- User approval supplied by task owner: 2026-10-12 05:01:30 UTC; D1 delayed GOAWAY and D2 fixed Go 1.25.9 synthetic GET scope accepted.
- Main revision read from GitHub and fetched: `98fc6ce404d683e80b86f86e5c817b36658dcde1`.
- Main tree: `907b2b068f4189ae8c727a5be5dbfad45b596855`.
- Target worktree: `opensandbox-h2-admission`, branch `feat/osep0023-h2-admission`.
- Egress source, OSEP-0023, and root AGENTS have no changes between approved source baseline `b57f7db` and fetched main.
- Dependencies inspected/executed: mitmproxy 11.0.2, h2 4.1.0, hyperframe 6.0.1; Python 3.12 in existing cloud venv.

## Command

```sh
/workspace/scratch/1982e08ae44a/osep0023-venv/bin/python \
  /workspace/shared/h2-p0-admission-proof/test_admission_seams.py
```

11 tests pass. The fixture exercises ordinary HttpLayer/HttpStream/Http2Server and real requestheaders hook commands using a per-instance test adapter. It preserves the dependency parser's stop result, captures raw pseudo-header bytes before transparent rewriting, and uses one-shot exact Request identity. It covers normal flow kill to exact REFUSED_STREAM with no upstream command, separate 400/413 abnormal close, repeated refusal table cleanup, body flow-control credit, reset during a paused hook, disconnect, configured NextLayer selector/instance preservation, and parser error followed by a valid stream in the same batch.

These tests prove only the specified fixed internal seams. In particular, their no-origin assertion means no upstream OpenConnection or SendData command, not a live origin observation. Hook/callback scheduling is explicit test scaffolding. The raw trace lists are test evidence only and are not proposed production lifetime-growing state.

## Independent-review correction retained

The initial test adapter iterated the dependency's RequestReceived generator with a for-loop and unconditionally returned False. Independent review found that this discarded a True protocol-stop return: malformed stream 1 and valid stream 3 in one batch could continue into a later hook/upstream connection. The final fixture preserves StopIteration.value and adds an explicit two-stream regression. No production file ever contained this bug.

## Baseline regression evidence

- `baseline-registry.log`: 69 existing TLS registry tests pass.
- `baseline-publication.log`: 22 existing joint-publication/race tests pass.
- Authenticated Unix IPC and runtime tests were not attempted; this cloud environment's AF_UNIX denial is preserved.

## Remaining gate

Overall P0 depends on the separately recorded upstream ownership, queue, orphan, and transport termination proof. This directory alone does not authorize a P0 pass or P1 implementation.
