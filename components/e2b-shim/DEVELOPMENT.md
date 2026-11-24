# Development Guide (Quick)

## Prerequisites

- Go 1.26+

## Build & Run

```bash
make build          # binary at bin/e2b-shim with ldflags version info
./bin/e2b-shim --help
./bin/e2b-shim adapter --config ./e2b-shim.json
./build.sh          # same local build without make
```

## Tests & Lint

```bash
make test           # go vet && go test ./...
make race           # go test -race ./...
go vet ./...
make golint         # golangci-lint (install-golint target included)
```

## Dependencies

The component currently uses only the standard library. The router uses `httputil.ReverseProxy` and Go `http.Protocols` for HTTP/1.1 and h2c. For future work, prefer maintained community packages over hand-rolled equivalents, and justify each new dependency in its PR:

- Routing: `net/http.ServeMux` while it is enough; otherwise a maintained router such as `chi`, or `gin`, which `execd` already uses.
- Request validation for the pinned SDK models: `go-playground/validator` or an equivalent, not hand-written field checks.
- envd passthrough in `router`: `httputil.ReverseProxy`, as in `ingress`, so streaming responses and WebSocket upgrades keep working.
- Error envelopes and middleware: existing packages where they fit, with tests against the error shapes of the pinned SDK.
