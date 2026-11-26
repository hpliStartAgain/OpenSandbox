// Copyright 2026 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package router implements stateless token admission and thin envd forwarding.
package router

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/adapter"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/service"
)

const DefaultCacheTTL = 2 * time.Second

type Backend interface {
	GetSandbox(context.Context, string) (*native.Sandbox, error)
	GetEndpoint(context.Context, string, int) (*native.Endpoint, error)
}

type Options struct {
	Config *config.Config
	Native Backend
	Logger *slog.Logger
	// CacheTTL defaults to two seconds and may only shorten that bound.
	CacheTTL time.Duration
}

type route struct {
	target  url.URL
	headers map[string]string
	expires time.Time
}

type Handler struct {
	native                        Backend
	tokens                        *rules.TokenDeriver
	catalog                       *rules.TemplateCatalog
	adapterID, keyVersion, domain string
	ttl                           time.Duration
	logger                        *slog.Logger
	transport                     *http.Transport
	health                        http.Handler
	mu                            sync.Mutex
	cache                         map[string]route
	epoch                         uint64
}

var _ adapter.AdmissionController = (*Handler)(nil)

func New(opts Options) (*Handler, error) {
	if opts.Config == nil || opts.Native == nil {
		return nil, errors.New("router: config and native client are required")
	}
	cfg := opts.Config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opts.CacheTTL < 0 || opts.CacheTTL > DefaultCacheTTL {
		return nil, errors.New("router: cache TTL must be within two seconds")
	}
	tokens, err := rules.NewTokenDeriver(cfg.HMACKey, cfg.HMACKeyVersion, cfg.AdapterID)
	if err != nil {
		return nil, err
	}
	catalog, err := rules.NewTemplateCatalog(cfg.Templates, rules.TimeoutPolicy{
		DefaultSeconds: cfg.TimeoutDefaultSeconds, MinSeconds: cfg.TimeoutMinSeconds, MaxSeconds: cfg.TimeoutMaxSeconds,
	})
	if err != nil {
		return nil, err
	}
	ttl := opts.CacheTTL
	if ttl == 0 {
		ttl = DefaultCacheTTL
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// No reused connections: net/http cannot retry on stale pooled connections.
	// Bodies have no GetBody, and neither redirects nor application retries run.
	transport.DisableKeepAlives = true
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	transport.Proxy = nil
	return &Handler{native: opts.Native, tokens: tokens, catalog: catalog,
		adapterID: cfg.AdapterID, keyVersion: cfg.HMACKeyVersion, domain: strings.ToLower(strings.TrimSuffix(cfg.Domain, ".")),
		ttl: ttl, logger: logger, transport: transport, health: service.NewHandler(), cache: make(map[string]route)}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	out := &responseWriter{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		h.logger.Info("router request", "status", out.status, "duration_ms", time.Since(start).Milliseconds())
	}()
	if r.URL.Path == config.HealthPath {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			out.Header().Set("Allow", "GET, HEAD")
			writeError(out, http.StatusMethodNotAllowed)
			return
		}
		h.health.ServeHTTP(out, r)
		return
	}
	id, status := h.resolve(r)
	if status != 0 {
		writeError(out, status)
		return
	}
	token, ok := singleHeader(r.Header, "X-Access-Token")
	verified, err := h.tokens.Verify(id, token)
	if !ok || err != nil || !verified {
		writeError(out, http.StatusUnauthorized)
		return
	}
	if managementPath(r.URL.Path) {
		writeError(out, http.StatusForbidden)
		return
	}
	// Token possession stands in for initialization: adapter only releases it in
	// the 201 after private /init succeeds, and destroys failed-init instances.
	// This assumes the OSEP's trusted native administrative scope and stable key.
	ep, status := h.lookup(r.Context(), id)
	if status != 0 {
		writeError(out, status)
		return
	}
	proxy := &httputil.ReverseProxy{
		Transport: h.transport, FlushInterval: -1,
		ErrorLog:     log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { writeError(w, http.StatusBadGateway) },
		Rewrite: func(p *httputil.ProxyRequest) {
			// Defense in depth: the transport never reuses connections, so net/http has
			// no retry path today. If keep-alives are ever enabled, Request.isReplayable
			// would treat empty-body requests carrying these headers as replayable, so
			// strip them; envd does not consume them. GetBody is cleared below.
			p.Out.Header.Del("Idempotency-Key")
			p.Out.Header.Del("X-Idempotency-Key")
			// ReverseProxy has already removed hop-by-hop headers. Restore the raw
			// query (including encodings) and append the envd path to the native base.
			p.SetURL(&ep.target)
			p.Out.URL.RawQuery = p.In.URL.RawQuery
			if ep.target.RawQuery != "" {
				p.Out.URL.RawQuery = ep.target.RawQuery
				if p.In.URL.RawQuery != "" {
					p.Out.URL.RawQuery += "&" + p.In.URL.RawQuery
				}
			}
			p.Out.GetBody = nil
			deleteHeader(p.Out.Header, "OpenSandbox-Ingress-To")
			for k := range ep.headers {
				deleteHeader(p.Out.Header, k)
			}
			for k, v := range ep.headers {
				if strings.EqualFold(k, "Host") {
					p.Out.Host = v
				} else {
					p.Out.Header.Set(k, v)
				}
			}
			// Retain SDK selectors alongside the token instead of assuming envd
			// file/RPC handlers do not use them.
			p.Out.Header.Set("X-Access-Token", token)
		},
	}
	proxy.ServeHTTP(out, r)
}

func (h *Handler) resolve(r *http.Request) (string, int) {
	id, idOK := singleHeader(r.Header, "E2b-Sandbox-Id")
	port, portOK := singleHeader(r.Header, "E2b-Sandbox-Port")
	hasHeaders := len(values(r.Header, "E2b-Sandbox-Id")) != 0 || len(values(r.Header, "E2b-Sandbox-Port")) != 0
	if hasHeaders && (!idOK || !portOK) {
		return "", http.StatusBadRequest
	}
	host := r.Host
	if strings.Contains(host, ":") {
		var err error
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return "", http.StatusBadRequest
		}
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	suffix := "." + h.domain
	if h.domain != "" && strings.HasSuffix(host, suffix) {
		label := strings.TrimSuffix(host, suffix)
		hostPort, hostID, found := strings.Cut(label, "-")
		if !found || strings.Contains(label, ".") {
			return "", http.StatusBadRequest
		}
		if hasHeaders && (id != hostID || port != hostPort) {
			return "", http.StatusBadRequest
		}
		id, port = hostID, hostPort
	} else if !hasHeaders {
		return "", http.StatusNotFound
	}
	if !rules.ValidSandboxID(id) {
		return "", http.StatusBadRequest
	}
	if port != "49983" {
		return "", http.StatusForbidden
	}
	return id, 0
}

func managementPath(p string) bool {
	// Match normalized aliases without rewriting any forwarded request path.
	p = path.Clean(strings.ReplaceAll(p, "\\", "/"))
	first := strings.Split(strings.TrimPrefix(p, "/"), "/")[0]
	// envs and metrics are envd data routes never called by the pinned SDK
	// (e2b 2.62.1, 9301cd84), blocked as defense in depth.
	// Other entries follow api.gen.go and main.go's /upgrade registration.
	switch first {
	case "envs", "metrics", "init", "upgrade", "freeze", "unfreeze", "collapse", "fsfreeze", "fsthaw":
		return true
	}
	return false
}

func (h *Handler) lookup(ctx context.Context, id string) (route, int) {
	started := time.Now()
	h.mu.Lock()
	ep, ok := h.cache[id]
	epoch := h.epoch
	if ok && started.Before(ep.expires) {
		h.mu.Unlock()
		return ep, 0
	}
	delete(h.cache, id)
	h.mu.Unlock()
	sbx, err := h.native.GetSandbox(ctx, id)
	if native.IsNotFound(err) {
		return route{}, http.StatusNotFound
	}
	if err != nil || sbx == nil || sbx.ID != id {
		return route{}, http.StatusServiceUnavailable
	}
	if !rules.DecodeSandboxOwnership(sbx.Metadata, h.adapterID, h.keyVersion, h.catalog).Owned {
		return route{}, http.StatusNotFound
	}
	if sbx.Status.State != native.StateRunning {
		return route{}, http.StatusServiceUnavailable
	}
	if sbx.ExpiresAt == nil || !started.Before(*sbx.ExpiresAt) {
		return route{}, http.StatusServiceUnavailable
	}
	endpoint, err := h.native.GetEndpoint(ctx, id, adapter.EnvdPort)
	if err != nil || endpoint == nil {
		return route{}, http.StatusServiceUnavailable
	}
	target, err := url.Parse(endpoint.URL)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") || target.User != nil || target.Fragment != "" || target.Opaque != "" {
		return route{}, http.StatusServiceUnavailable
	}
	ep = route{target: *target, headers: maps.Clone(endpoint.Headers), expires: minTime(started.Add(h.ttl), *sbx.ExpiresAt)}
	h.mu.Lock()
	defer h.mu.Unlock()
	// An invalidation racing a native read must not repopulate stale routing.
	if epoch != h.epoch || !time.Now().Before(ep.expires) || ctx.Err() != nil {
		return route{}, http.StatusServiceUnavailable
	}
	for key, entry := range h.cache {
		if !time.Now().Before(entry.expires) {
			delete(h.cache, key)
		}
	}
	h.cache[id] = ep
	return ep, 0
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Invalidate drops the positive route and fences in-flight cache refreshes.
// Separate processes converge within CacheTTL after native state changes.
// Existing streams are not interrupted; native/runtime teardown may end them.
func (h *Handler) Invalidate(id string) {
	h.mu.Lock()
	delete(h.cache, id)
	h.epoch++
	h.mu.Unlock()
}

// Open validates initialized adapter evidence, then resolves native admission.
// No admission registry is required or shared between processes.
func (h *Handler) Open(ctx context.Context, rec adapter.AdmissionRecord) error {
	if !rec.Initialized {
		return adapter.ErrAdmissionUninitialized
	}
	if !rules.ValidSandboxID(rec.SandboxID) || rec.TemplateRevision == "" || rec.EnvdVersion == "" {
		return adapter.ErrInvalidAdmissionRecord
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	h.Invalidate(rec.SandboxID)
	_, status := h.lookup(ctx, rec.SandboxID)
	if status != 0 {
		return errors.New("router: admission unavailable")
	}
	return nil
}

// Close invalidates locally; it does not cut existing streams or retain a
// tombstone. The adapter follows Close with native deletion; failed deletion
// while native still reports Running can admit a later authenticated refresh.
func (h *Handler) Close(ctx context.Context, id string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !rules.ValidSandboxID(id) {
		return adapter.ErrInvalidAdmissionRecord
	}
	h.Invalidate(id)
	return nil
}

func (h *Handler) IsOpen(ctx context.Context, id string) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if !rules.ValidSandboxID(id) {
		return false, adapter.ErrInvalidAdmissionRecord
	}
	_, status := h.lookup(ctx, id)
	if status == http.StatusNotFound {
		return false, nil
	}
	if status != 0 {
		return false, errors.New("router: admission unavailable")
	}
	return true, nil
}

func values(h http.Header, key string) []string {
	var out []string
	for k, v := range h {
		if strings.EqualFold(k, key) {
			out = append(out, v...)
		}
	}
	return out
}
func singleHeader(h http.Header, key string) (string, bool) {
	v := values(h, key)
	if len(v) != 1 || v[0] == "" {
		return "", false
	}
	return v[0], true
}
func deleteHeader(h http.Header, key string) {
	for k := range h {
		if strings.EqualFold(k, key) {
			delete(h, k)
		}
	}
}

func writeError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{status, http.StatusText(status)})
}

type responseWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *responseWriter) WriteHeader(status int) {
	if !w.wrote {
		w.status = status
		w.wrote = status >= 200 || status == 101
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}
