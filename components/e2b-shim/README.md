# OpenSandbox E2B Shim (Scaffold)

`components/e2b-shim` is the optional component proposed by [OSEP-0027](https://github.com/opensandbox-group/OpenSandbox/blob/main/oseps/0027-optional-e2b-compatibility.md). This README describes the current development scaffold only. It stays out of the docs site until the proof of concept works end to end.

> **Scaffold only.** Gate 0 of OSEP-0027 is pending. The binary loads and validates configuration, starts an HTTP server, and answers a liveness check; `pkg/rules` contains pure, network-independent helpers for token derivation, template resolution, metadata encoding, timeout evaluation, and create-option validation. It does not register any E2B HTTP route, implement any command or file operation, or call the native OpenSandbox API or envd. No E2B SDK, envd, or Fast Sandbox combination has been tested. Do not treat this module as a deployment recipe or a compatibility commitment.

Development commands and dependency guidelines: [DEVELOPMENT.md](DEVELOPMENT.md)

## What the scaffold does

The binary has two service subcommands that share the same skeleton, plus `version` (build information) and `help`:

| Subcommand | Planned role (not implemented) | Current behavior |
|---|---|---|
| `adapter` | Translate E2B lifecycle requests to the native lifecycle API | Validate configuration, serve `/healthz` |
| `router` | Forward E2B command and file traffic to upstream envd | Validate configuration, serve `/healthz` |

HTTP behavior:

- `GET /healthz` and `HEAD /healthz` return `200`. The check needs no API key and its body contains no configuration. It only reports that the process is running; it does not check the native backend, envd readiness, or E2B compatibility. There is no `/readyz`.
- Other methods on `/healthz` return `405`.
- Every other path returns `404`, including `/`, `/v2/sandboxes`, `/sandboxes`, and the same paths under the compatibility prefix. No E2B route is registered at the root or under the prefix.

All configuration errors are reported before the server starts listening. Errors name the field or category only; they never echo secret values, raw configuration, or URLs.

## Build and run

```bash
make build
./bin/e2b-shim --help
./bin/e2b-shim adapter --config ./e2b-shim.json
```

`--listen` overrides the listen address from the environment and the file. An explicitly empty `--config` is a usage error (exit code `2`). `SIGINT` and `SIGTERM` stop the server with a bounded graceful shutdown.

## Configuration file

The file must contain a JSON object. The loader rejects unknown fields, trailing data, and `null` for top-level fields. Secret fields accept references only. The loader decodes file-based secret references even when an environment override is present. Scalar settings are decoded after applying overrides. Decode and secret-resolution errors precede semantic validation errors.

```json
{
  "listen": "127.0.0.1:8080",
  "compat_prefix": "/compat/e2b",
  "native_api_url": "https://opensandbox.example.internal/v1",
  "adapter_id": "e2b-shim-dev",
  "domain": "sandbox.example.internal",
  "hmac_key_version": "v1",
  "timeout_default_seconds": 300,
  "timeout_min_seconds": 60,
  "timeout_max_seconds": 3600,
  "templates": [
    {
      "template_id": "base",
      "aliases": ["base-envd"],
      "native_template_id": "envd-only-base",
      "revision": "envd-only-base.rev-1",
      "expected_envd_version": "0.8.0"
    }
  ],
  "adapter_api_key": { "env": "MY_ADAPTER_API_KEY" },
  "native_api_key": { "file": "/run/secrets/native-api-key" },
  "hmac_key": { "file": "/run/secrets/hmac-key" }
}
```

| Field | Required | Default | Rules |
|---|---|---|---|
| `listen` | No | `127.0.0.1:8080` | `host:port` with a decimal port `0`–`65535`. The host may contain letters, digits, and `.-_:[]`. An empty host listens on all interfaces. |
| `compat_prefix` | No | `/compat/e2b` | Absolute path below `/`. One trailing `/` is removed. Disallows queries, fragments, `%`, `\`, whitespace, control characters, and empty, `.` or `..` segments. Must not be `/healthz` or start with `/healthz/`. |
| `native_api_url` | Yes | — | Hierarchical `http` or `https` URL with a host. A base path such as `/v1` is allowed. An explicit port must be `1`–`65535`. No user info, query, or fragment. The scaffold does not connect to it. |
| `adapter_id` | Yes | — | Deployment identity for the future E2B `clientID`, persisted as a native sandbox metadata label value. Must match Fast Sandbox label-value syntax `^[A-Za-z0-9]([-_.A-Za-z0-9]*[A-Za-z0-9])?$` (1–63 ASCII characters; no whitespace, control characters, or `@`). |
| `domain` | No | empty | Bare host name. Disallows `/`, `?`, `#`, `@`, `:`, whitespace, and control characters. |
| `hmac_key_version` | Yes | — | HMAC key configuration label, persisted as a native sandbox metadata label value. Must match Fast Sandbox label-value syntax `^[A-Za-z0-9]([-_.A-Za-z0-9]*[A-Za-z0-9])?$` (1–63 ASCII characters; no whitespace, control characters, or `@`). |
| `timeout_default_seconds` | No | `300` | Integer. Omitted-timeout default for create and connect policy evaluation. |
| `timeout_min_seconds` | No | `60` | Integer, at least `1`. |
| `timeout_max_seconds` | Yes | — | Integer. Copy it explicitly from the native deployment; the scaffold does not verify it against the native server. |
| `templates` | No | `[]` | See below. An empty list means no template is available. |
| `adapter_api_key`, `native_api_key`, `hmac_key` | Yes | — | Secret reference: exactly one of `{"env": "NAME"}` or `{"file": "/path"}`. |

Timeouts must be integer seconds and satisfy `timeout_min_seconds` ≤ `timeout_default_seconds` ≤ `timeout_max_seconds`. Each value must fit in a Go `time.Duration` after conversion to nanoseconds (at most `9223372036` seconds). Request-level timeout evaluation is implemented as pure functions in `pkg/rules` and is not yet wired to HTTP endpoints.

Each element of `templates` must be an object with a non-empty `template_id`, `native_template_id`, `revision`, and `expected_envd_version`. `revision` is persisted as a native sandbox metadata label value and must match Fast Sandbox label-value syntax `^[A-Za-z0-9]([-_.A-Za-z0-9]*[A-Za-z0-9])?$` (1–63 ASCII characters; `@` is disallowed). Omitting `aliases` or setting it to `null` means an empty list, and each alias must be non-empty. Whitespace and control characters are disallowed in the four required fields and in aliases. Template IDs and aliases share one selector namespace and must be unique across all mappings, and each `revision` must be unique. Three optional per-template fields are also supported (explicit JSON `null` is rejected on all three): `ready` (boolean, default `true`; `false` blocks new creates while keeping `revision` lookup available for existing owned instances), `profile_compatible` (boolean, default `true`; `false` blocks new creates for incompatible mappings), and `timeout_max_seconds` (integer tightening the per-template ceiling within `timeout_min_seconds`..`timeout_max_seconds`). The configuration loader does not query native template readiness over the network.

## Gate 1a Create Options Inventory

`pkg/rules.ValidateCreateRequest` evaluates every field of the pinned `e2b==2.62.1` `NewSandboxV2` and legacy `NewSandbox` models before any allocation or side effect:

| Field | Gate 1a disposition | Rationale & validation rule |
|---|---|---|
| `templateID` | Accept | Required non-empty JSON string; resolved against approved, ready, profile-compatible `templates` (`template_id` or `aliases`) and recorded by canonical `revision`. |
| `timeout` | Accept | Optional JSON integer seconds (`timeout_default_seconds` = `300` when omitted); must satisfy `timeout_min_seconds`..effective template/profile max without clamping or rounding; `null`, booleans, floats (including `60.0`), scientific notation, strings, and overflow are rejected. |
| `metadata` | Accept | Optional `map[string]string` (`{}` or omitted accepted; `null`, non-object, duplicate keys, or non-string values rejected); keys must be 1–63 character Fast Sandbox DNS labels (`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`) outside reserved `opensandbox.io/` and `e2b-shim-` prefixes, and values must be 1–63 character label values (`^[A-Za-z0-9]([-_.A-Za-z0-9]*[A-Za-z0-9])?$`). |
| `envVars` | Accept | Optional `map[string]string` (`{}` or omitted accepted; `null`, non-object, duplicate keys, or non-string values rejected); keys must be non-empty without `=` or NUL bytes, and values must contain no NUL bytes. Planned for private envd `POST /init` rather than native template-mode `env` overrides; untested against real envd and Fast Sandbox until E8/E10. |
| `autoPause` | Accept default only | Omitted or `false` accepted; `true` rejected (`ErrUnsupportedOption`) because automatic pause on timeout is excluded from Gate 1a; `null` or non-boolean rejected. |
| `autoPauseMemory` | Reject | Omitted only; any explicit value (`true`, `false`, `null`, etc.) rejected (`ErrUnsupportedOption`) because auto-pause snapshot modes are excluded. |
| `autoResume` | Reject | Omitted only; any explicit value rejected (`ErrUnsupportedOption`) because automatic resume is excluded. |
| `secure` | Accept default only | Legacy `NewSandbox` field; omitted or `true` accepted because envd communication is always authenticated; `false` rejected (`ErrUnsupportedOption`); `null` or non-boolean rejected. |
| `allow_internet_access` | Accept default only | Omitted or `true` accepted; `false` rejected (`ErrUnsupportedOption`) rather than ignoring requested internet egress denial; `null` or non-boolean rejected. |
| `network` | Reject | Omitted only; any explicit value rejected (`ErrUnsupportedOption`) rather than ignoring per-sandbox network policy rules. |
| `mcp` | Reject | Omitted only; any explicit value rejected (`ErrUnsupportedOption`) because E2B MCP server configuration is unsupported. |
| `iam` | Reject | Omitted only; any explicit value rejected (`ErrUnsupportedOption`) because E2B workload identity is unsupported. |
| `volumeMounts` | Reject | Omitted only; any explicit value rejected (`ErrUnsupportedOption`) because E2B volume mounts are unsupported and rejected in native template mode. |
| Unknown fields | Reject | Any unrecognized field (`ErrUnknownField`), duplicate JSON key (`ErrDuplicateField`), non-object body, or trailing token is rejected before side effects. |

## Environment variables

Environment variables override the file. An explicit empty value is used as the override and checked against the field rules.

| Variable | Overrides |
|---|---|
| `E2B_SHIM_LISTEN` | `listen` (the `--listen` flag overrides this variable) |
| `E2B_SHIM_COMPAT_PREFIX` | `compat_prefix` |
| `E2B_SHIM_NATIVE_API_URL` | `native_api_url` |
| `E2B_SHIM_ADAPTER_ID` | `adapter_id` |
| `E2B_SHIM_DOMAIN` | `domain` |
| `E2B_SHIM_HMAC_KEY_VERSION` | `hmac_key_version` |
| `E2B_SHIM_TIMEOUT_DEFAULT_SECONDS` | `timeout_default_seconds` |
| `E2B_SHIM_TIMEOUT_MIN_SECONDS` | `timeout_min_seconds` |
| `E2B_SHIM_TIMEOUT_MAX_SECONDS` | `timeout_max_seconds` |
| `E2B_SHIM_TEMPLATES` | `templates`, as a JSON array with the same schema |
| `E2B_SHIM_ADAPTER_API_KEY` or `E2B_SHIM_ADAPTER_API_KEY_FILE` | `adapter_api_key` |
| `E2B_SHIM_NATIVE_API_KEY` or `E2B_SHIM_NATIVE_API_KEY_FILE` | `native_api_key` |
| `E2B_SHIM_HMAC_KEY` or `E2B_SHIM_HMAC_KEY_FILE` | `hmac_key` |

Precedence, highest first: `--listen` flag, environment variable, configuration file, default. `--config` is optional; without it, all required settings must come from the environment.

## Secrets

- A secret comes from one source. Setting both `E2B_SHIM_X` and `E2B_SHIM_X_FILE` for the same secret is an error.
- Missing, empty, or unreadable secrets are errors.
- For file sources, one trailing `\n` or `\r\n` is removed. No other trimming is applied. Environment values are used as is.
- Loaded secrets are redacted in every formatted, JSON, and log output of the configuration.

## Limitations

- No E2B API, command, or file operation is implemented. The pinned SDK candidate `e2b==2.62.1`, envd `0.8.0`, and Fast Sandbox backends are not tested.
- `/healthz` is liveness only.
- `timeout_max_seconds` is not checked against the native server.
- Template mappings are not checked against native templates.
