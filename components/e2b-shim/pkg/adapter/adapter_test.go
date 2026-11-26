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

package adapter_test

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/e2b-shim/internal/fakenative"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/adapter"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/service"
)

const (
	testAdapterAPIKey = "fake-e2b-adapter-key-SECRET-DO-NOT-LEAK"
	testNativeAPIKey  = "fake-native-api-key-SECRET-DO-NOT-LEAK"
	testHMACKey       = "fake-hmac-signing-key-SECRET-DO-NOT-LEAK"
	testIngressToken  = "fake-ingress-route-secret-DO-NOT-LEAK"
	testEnvSecretVal  = "super-secret-env-var-value-DO-NOT-LEAK"
	testMetaUserVal   = "tenant-private-tag-DO-NOT-LEAK"
	testAdapterID     = "e2b-shim-gate1a"
	testKeyVersion    = "v1"
)

type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type fakeInitializer struct {
	mu    sync.Mutex
	calls []adapter.EnvdInitRequest
	fn    func(ctx context.Context, req adapter.EnvdInitRequest) (*adapter.EnvdInitResult, error)
}

func (f *fakeInitializer) Initialize(ctx context.Context, req adapter.EnvdInitRequest) (*adapter.EnvdInitResult, error) {
	cloned := req
	if req.Endpoint != nil {
		cloned.Endpoint = &native.Endpoint{URL: req.Endpoint.URL, Headers: maps.Clone(req.Endpoint.Headers)}
	}
	cloned.EnvVars = maps.Clone(req.EnvVars)
	f.mu.Lock()
	f.calls = append(f.calls, cloned)
	fn := f.fn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, cloned)
	}
	return &adapter.EnvdInitResult{EnvdVersion: req.ExpectedEnvdVersion}, nil
}

func (f *fakeInitializer) Calls() []adapter.EnvdInitRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

type hookAdmission struct {
	inner   *adapter.MemoryAdmissionController
	onOpen  func(ctx context.Context, rec adapter.AdmissionRecord) error
	onClose func(ctx context.Context, sandboxID string) error
	mu      sync.Mutex
	events  []string
}

func newHookAdmission() *hookAdmission {
	return &hookAdmission{inner: adapter.NewMemoryAdmissionController()}
}
func (a *hookAdmission) IsOpen(ctx context.Context, sandboxID string) (bool, error) {
	return a.inner.IsOpen(ctx, sandboxID)
}
func (a *hookAdmission) Events() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.events)
}

func (a *hookAdmission) Open(ctx context.Context, rec adapter.AdmissionRecord) error {
	a.mu.Lock()
	a.events = append(a.events, "open:"+rec.SandboxID)
	a.mu.Unlock()
	if a.onOpen != nil {
		if err := a.onOpen(ctx, rec); err != nil {
			return err
		}
	}
	return a.inner.Open(ctx, rec)
}

func (a *hookAdmission) Close(ctx context.Context, sandboxID string) error {
	a.mu.Lock()
	a.events = append(a.events, "close:"+sandboxID)
	a.mu.Unlock()
	if a.onClose != nil {
		if err := a.onClose(ctx, sandboxID); err != nil {
			return err
		}
	}
	return a.inner.Close(ctx, sandboxID)
}

type harness struct {
	fakeNative *fakenative.Server
	shimHTTP   *httptest.Server
	init       *fakeInitializer
	admission  *hookAdmission
	logs       *syncLogBuffer
	cfg        *config.Config
	handler    *adapter.Handler
}

type harnessOpts struct {
	compatPrefix, domain                    string
	retainTerminated                        *bool
	readinessTimeout, readinessPollInterval time.Duration
	maxBodyBytes                            int64
}

func newHarness(t *testing.T, ho harnessOpts) *harness {
	t.Helper()
	fn := fakenative.New(fakenative.Config{
		APIKey: testNativeAPIKey, BasePath: "/v1", RetainTerminated: ho.retainTerminated,
		DefaultTemplates: []fakenative.TemplateSpec{
			{ID: "native-tpl-base", Ready: true, InitialState: native.StateRunning},
			{ID: "native-tpl-capped", Ready: true, InitialState: native.StateRunning},
		},
	})
	fn.SetEndpoint("*", adapter.EnvdPort, native.Endpoint{
		URL: "http://127.0.0.1:49983", Headers: map[string]string{"OpenSandbox-Ingress-To": testIngressToken},
	})
	nativeSrv := httptest.NewServer(fn.Handler())
	t.Cleanup(nativeSrv.Close)

	readyFalse, compatFalse, cappedMax := false, false, int64(600)
	templatesJSON, err := json.Marshal([]config.TemplateMapping{
		{TemplateID: "tpl-base", Aliases: []string{"base"}, NativeTemplateID: "native-tpl-base", Revision: "tpl-base.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.1.4"},
		{TemplateID: "tpl-capped", NativeTemplateID: "native-tpl-capped", Revision: "tpl-capped.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.1.4", TimeoutMaxSeconds: &cappedMax},
		{TemplateID: "tpl-unready", NativeTemplateID: "native-tpl-base", Revision: "tpl-unready.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.1.4", Ready: &readyFalse},
		{TemplateID: "tpl-incompat", NativeTemplateID: "native-tpl-base", Revision: "tpl-incompat.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.1.4", ProfileCompatible: &compatFalse},
	})
	if err != nil {
		t.Fatalf("marshal templates: %v", err)
	}
	env := map[string]string{
		"E2B_SHIM_NATIVE_API_URL": nativeSrv.URL + "/v1", "E2B_SHIM_ADAPTER_ID": testAdapterID,
		"E2B_SHIM_HMAC_KEY_VERSION": testKeyVersion, "E2B_SHIM_TIMEOUT_MAX_SECONDS": "3600",
		"E2B_SHIM_ADAPTER_API_KEY": testAdapterAPIKey, "E2B_SHIM_NATIVE_API_KEY": testNativeAPIKey,
		"E2B_SHIM_HMAC_KEY": testHMACKey, "E2B_SHIM_TEMPLATES": string(templatesJSON),
	}
	if ho.domain != "" {
		env["E2B_SHIM_DOMAIN"] = ho.domain
	}
	cfg, err := config.Load(config.Source{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if ho.compatPrefix != "" {
		cfg.CompatPrefix = ho.compatPrefix
	}
	nc, err := native.NewClient(native.ClientConfig{
		BaseURL: cfg.NativeAPIURL, APIKey: cfg.NativeAPIKey, ReadMaxAttempts: 2, ReadRetryBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("native.NewClient: %v", err)
	}

	init, adm, logs := &fakeInitializer{}, newHookAdmission(), &syncLogBuffer{}
	h, err := adapter.New(adapter.Options{
		Config: cfg, Native: nc, Initializer: init, Admission: adm,
		Logger:                slog.New(slog.NewJSONHandler(logs, nil)),
		ReadinessTimeout:      cmp.Or(ho.readinessTimeout, 2*time.Second),
		ReadinessPollInterval: cmp.Or(ho.readinessPollInterval, 10*time.Millisecond),
		CleanupTimeout:        2 * time.Second,
		MaxBodyBytes:          ho.maxBodyBytes,
	})
	if err != nil {
		t.Fatalf("adapter.New: %v", err)
	}
	shimSrv := httptest.NewServer(service.NewHandlerWithExtra(h.Mount))
	t.Cleanup(shimSrv.Close)
	return &harness{fakeNative: fn, shimHTTP: shimSrv, init: init, admission: adm, logs: logs, cfg: cfg, handler: h}
}

func (h *harness) do(t *testing.T, method, path, apiKey, body string) (*http.Response, []byte) {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, h.shimHTTP.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("NewRequest(%s %s): %v", method, path, err)
	}
	if apiKey != "" {
		req.Header.Set("X-API-KEY", apiKey)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatalf("Do(%s %s): %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

type apiErrorBody struct {
	Code      int    `json:"code"`
	Message   string `json:"message"`
	ErrorCode string `json:"error_code"`
}

func assertAPIError(t *testing.T, resp *http.Response, raw []byte, wantStatus int, wantCode string, wantNoRetry bool) apiErrorBody {
	t.Helper()
	if resp.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, wantStatus, string(raw))
	}
	var out apiErrorBody
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal error body %q: %v", string(raw), err)
	}
	if out.Code != wantStatus || (wantCode != "" && out.ErrorCode != wantCode) {
		t.Fatalf("error body = %+v, want status=%d code=%q", out, wantStatus, wantCode)
	}
	if wantNoRetry && resp.Header.Get("Should-Retry") != "false" {
		t.Fatalf("Should-Retry = %q, want false", resp.Header.Get("Should-Retry"))
	}
	return out
}

type nilSandboxLifecycle struct {
	native.Lifecycle
	events   []string
	onDelete func(context.Context) error
}

func (n *nilSandboxLifecycle) CreateTemplateSandbox(context.Context, native.CreateTemplateSandboxRequest) (*native.CreateSandboxResult, error) {
	n.events = append(n.events, "create")
	return &native.CreateSandboxResult{ID: "sbx-1", Status: native.SandboxStatus{State: native.StatePending}}, nil
}
func (n *nilSandboxLifecycle) GetSandbox(context.Context, string) (*native.Sandbox, error) {
	n.events = append(n.events, "get")
	return nil, nil
}
func (n *nilSandboxLifecycle) DeleteSandbox(ctx context.Context, _ string) error {
	n.events = append(n.events, "delete")
	return n.onDelete(ctx)
}

func TestNilSandboxAndIndependentCleanupContexts(t *testing.T) {
	for _, scenario := range []string{"create", "delete", "create_slow_close"} {
		t.Run(scenario, func(t *testing.T) {
			base := newHarness(t, harnessOpts{})
			n := &nilSandboxLifecycle{}
			base.admission.onClose = func(ctx context.Context, _ string) error {
				n.events = append(n.events, "close")
				if scenario == "create_slow_close" {
					<-ctx.Done()
					return ctx.Err()
				}
				return nil
			}
			n.onDelete = func(ctx context.Context) error {
				deadline, ok := ctx.Deadline()
				if ctx.Err() != nil || !ok || !deadline.After(time.Now()) {
					t.Fatalf("delete must receive its own live timeout: err=%v deadline=%v", ctx.Err(), deadline)
				}
				return nil
			}
			h, err := adapter.New(adapter.Options{Config: base.cfg, Native: n, Initializer: base.init, Admission: base.admission,
				ReadinessPollInterval: time.Millisecond, CleanupTimeout: 20 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			method, path, code := http.MethodPost, "/compat/e2b/v2/sandboxes", "sandbox_readiness_failed"
			wantEvents := []string{"create", "get", "close", "delete"}
			if scenario == "delete" {
				method, path, code = http.MethodDelete, "/compat/e2b/sandboxes/sbx-1", "backend_unavailable"
				wantEvents = []string{"get"}
			}
			r := httptest.NewRequest(method, path, strings.NewReader(`{"templateID":"tpl-base"}`))
			r.Header.Set("X-API-KEY", testAdapterAPIKey)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assertAPIError(t, w.Result(), w.Body.Bytes(), http.StatusServiceUnavailable, code, true)
			if !slices.Equal(n.events, wantEvents) || len(base.init.Calls()) != 0 {
				t.Fatalf("events=%v, want %v; initializer must not run", n.events, wantEvents)
			}
		})
	}
}

func TestZeroValueHandler(t *testing.T) {
	var h adapter.Handler
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/compat/e2b/v2/sandboxes", nil))
	out := assertAPIError(t, w.Result(), w.Body.Bytes(), http.StatusInternalServerError, "handler_not_initialized", false)
	if out.Message == "" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("uninitialized handler must return a JSON error envelope")
	}
}

func TestNewValidationAndPorts(t *testing.T) {
	base := newHarness(t, harnessOpts{})
	nc, err := native.NewClient(native.ClientConfig{BaseURL: base.cfg.NativeAPIURL, APIKey: base.cfg.NativeAPIKey})
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"/v1", "/v1/e2b", "/v2", "/v2/e2b", "/sandboxes", "/sandboxes/e2b", "/healthz", "/healthz/e2b", "/compat/e2b", "/V1/e2b", "/v10", "/compat/v2"} {
		cfg := *base.cfg
		cfg.CompatPrefix = prefix
		_, err := adapter.New(adapter.Options{Config: &cfg, Native: nc, Initializer: base.init, Admission: base.admission})
		wantErr := slices.Contains([]string{"v1", "v2", "sandboxes", "healthz"}, strings.Split(prefix, "/")[1])
		if (err != nil) != wantErr || (err != nil && strings.Contains(err.Error(), prefix)) {
			t.Fatalf("prefix %q: error = %v, wantErr=%v (value-free)", prefix, err, wantErr)
		}
	}
	for _, version := range []string{"latest", "0.0.9", "0.0.0", "v0.8.0", "0.8", "0.01.0", "0.1.0-rc.1", "0.1.0", "0.8.0", "1.0.0"} {
		cfg := *base.cfg
		cfg.Templates = slices.Clone(cfg.Templates)
		cfg.Templates[0].ExpectedEnvdVersion = version
		_, err := adapter.New(adapter.Options{Config: &cfg, Native: nc, Initializer: base.init, Admission: base.admission})
		wantErr := !slices.Contains([]string{"0.1.0", "0.8.0", "1.0.0"}, version)
		if (err != nil) != wantErr || (err != nil && strings.Contains(err.Error(), version)) {
			t.Fatalf("version %q: error = %v, wantErr=%v (value-free)", version, err, wantErr)
		}
	}
	for name, mutate := range map[string]func(*adapter.Options){
		"nil_config":      func(o *adapter.Options) { o.Config = nil },
		"nil_native":      func(o *adapter.Options) { o.Native = nil },
		"nil_initializer": func(o *adapter.Options) { o.Initializer = nil },
		"nil_admission":   func(o *adapter.Options) { o.Admission = nil },
		"empty_prefix":    func(o *adapter.Options) { o.Config.CompatPrefix = "" },
		"root_prefix":     func(o *adapter.Options) { o.Config.CompatPrefix = "/" },
		"double_slash":    func(o *adapter.Options) { o.Config.CompatPrefix = "/compat/e2b//" },
		"health_overlap":  func(o *adapter.Options) { o.Config.CompatPrefix = "/healthz" },
		"relative_prefix": func(o *adapter.Options) { o.Config.CompatPrefix = "compat/e2b" },
		"empty_api_key":   func(o *adapter.Options) { o.Config.AdapterAPIKey = config.Secret{} },
		"invalid_domain":  func(o *adapter.Options) { o.Config.Domain = "https://bad.example" },
	} {
		cfgCopy := *base.cfg
		opts := adapter.Options{Config: &cfgCopy, Native: nc, Initializer: adapter.UnconfiguredEnvdInitializer{}, Admission: adapter.NewMemoryAdmissionController()}
		mutate(&opts)
		if _, err := adapter.New(opts); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}

	mem := adapter.NewMemoryAdmissionController()
	if err := mem.Open(context.Background(), adapter.AdmissionRecord{SandboxID: "sbx-1", TemplateRevision: "r1", EnvdVersion: "0.1.4"}); !errors.Is(err, adapter.ErrAdmissionUninitialized) {
		t.Fatalf("Open(Initialized=false) = %v, want ErrAdmissionUninitialized", err)
	}
	if _, err := (adapter.UnconfiguredEnvdInitializer{}).Initialize(context.Background(), adapter.EnvdInitRequest{}); !errors.Is(err, adapter.ErrEnvdInitNotConfigured) {
		t.Fatalf("UnconfiguredEnvdInitializer = %v, want ErrEnvdInitNotConfigured", err)
	}
}

func TestRoutingPrefixesRoot404HealthzAndMethodNotAllowed(t *testing.T) {
	for _, configuredPrefix := range []string{"/compat/e2b", "/custom/e2b", "/custom/e2b/"} {
		t.Run(configuredPrefix, func(t *testing.T) {
			h := newHarness(t, harnessOpts{compatPrefix: configuredPrefix})
			normPrefix := strings.TrimSuffix(configuredPrefix, "/")
			if h.handler.Prefix() != normPrefix {
				t.Fatalf("Prefix() = %q, want %q", h.handler.Prefix(), normPrefix)
			}
			for _, m := range []string{http.MethodGet, http.MethodHead} {
				resp, raw := h.do(t, m, "/healthz", "", "")
				if resp.StatusCode != http.StatusOK || (m == http.MethodGet && string(raw) != "ok\n") {
					t.Fatalf("%s /healthz status=%d body=%q", m, resp.StatusCode, string(raw))
				}
			}

			for _, badPath := range []string{
				"/v2/sandboxes", "/v2/sandboxes/sbx-1/connect", "/sandboxes/sbx-1",
				"/sandboxes/sbx-1/pause", "/sandboxes/sbx-1/timeout",
				normPrefix, normPrefix + "/", normPrefix + "extra/v2/sandboxes",
				normPrefix + "/v2/sandboxes/", normPrefix + "/v2/../v2/sandboxes",
				normPrefix + "/sandboxes/a/../b", normPrefix + "//v2/sandboxes",
			} {
				for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
					resp, _ := h.do(t, m, badPath, testAdapterAPIKey, `{"templateID":"tpl-base"}`)
					if resp.StatusCode != http.StatusNotFound {
						t.Errorf("%s %s: status = %d, want 404", m, badPath, resp.StatusCode)
					}
				}
			}

			for _, mc := range []struct{ method, path, wantAllow string }{
				{http.MethodPut, normPrefix + "/v2/sandboxes", "GET, POST"},
				{http.MethodHead, normPrefix + "/v2/sandboxes", "GET, POST"},
				{http.MethodGet, normPrefix + "/v2/sandboxes/sbx-1/connect", "POST"},
				{http.MethodPost, normPrefix + "/sandboxes/sbx-1", "DELETE, GET"},
				{http.MethodHead, normPrefix + "/sandboxes/sbx-1", "DELETE, GET"},
				{http.MethodGet, normPrefix + "/sandboxes/sbx-1/pause", "POST"},
				{http.MethodDelete, normPrefix + "/sandboxes/sbx-1/timeout", "POST"},
			} {
				resp, raw := h.do(t, mc.method, mc.path, "", "")
				if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != mc.wantAllow {
					t.Errorf("%s %s: status=%d Allow=%q, want 405 %q", mc.method, mc.path, resp.StatusCode, resp.Header.Get("Allow"), mc.wantAllow)
				}
				if mc.method != http.MethodHead {
					assertAPIError(t, resp, raw, http.StatusMethodNotAllowed, "method_not_allowed", false)
				}
			}

			for _, p := range []string{normPrefix + "/v2/sandboxes", normPrefix + "/sandboxes/sbx-1"} {
				resp, raw := h.do(t, http.MethodGet, p, testAdapterAPIKey, "")
				assertAPIError(t, resp, raw, http.StatusNotImplemented, "operation_not_supported", false)
			}
		})
	}
}

func TestAuthenticationAndFiveUnsupportedRoutes(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	routes := []struct{ op, method, path, body string }{
		{"create", http.MethodPost, "/compat/e2b/v2/sandboxes", `{"templateID":"tpl-base"}`},
		{"delete", http.MethodDelete, "/compat/e2b/sandboxes/sbx-does-not-exist", ""},
		{"connect", http.MethodPost, "/compat/e2b/v2/sandboxes/sbx-1/connect", `{"timeout":300}`},
		{"pause", http.MethodPost, "/compat/e2b/sandboxes/sbx-1/pause", `{}`},
		{"get_info", http.MethodGet, "/compat/e2b/sandboxes/sbx-1", ""},
		{"list", http.MethodGet, "/compat/e2b/v2/sandboxes", ""},
		{"set_timeout", http.MethodPost, "/compat/e2b/sandboxes/sbx-1/timeout", `{"timeout":0}`},
	}

	for _, rt := range routes {
		for _, key := range []string{"", "wrong-key", testAdapterAPIKey + "-extra"} {
			resp, raw := h.do(t, rt.method, rt.path, key, rt.body)
			assertAPIError(t, resp, raw, http.StatusUnauthorized, "unauthorized", false)
			if resp.Header.Get("X-Request-ID") == "" {
				t.Errorf("%s %s: missing X-Request-ID", rt.method, rt.path)
			}
		}
		req, _ := http.NewRequest(rt.method, h.shimHTTP.URL+rt.path, strings.NewReader(rt.body))
		req.Header["X-API-KEY"] = []string{testAdapterAPIKey, testAdapterAPIKey}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s duplicate X-API-KEY: status = %d, want 401", rt.method, rt.path, resp.StatusCode)
		}
	}

	for _, rt := range routes[2:] {
		resp, raw := h.do(t, rt.method, rt.path, testAdapterAPIKey, rt.body)
		eb := assertAPIError(t, resp, raw, http.StatusNotImplemented, "operation_not_supported", false)
		if wantMsg := rt.op + " is not supported in the Gate 1a profile"; eb.Message != wantMsg {
			t.Fatalf("%s: message = %q, want %q", rt.op, eb.Message, wantMsg)
		}
	}

	if st := h.fakeNative.Stats(); st != (fakenative.Stats{}) {
		t.Fatalf("native stats = %+v, want all zero", st)
	}
	if len(h.init.Calls()) != 0 || len(h.admission.Events()) != 0 {
		t.Fatalf("expected zero init/admission side effects")
	}
}

func TestCreateRejectionsBeforeAllocation(t *testing.T) {
	h := newHarness(t, harnessOpts{maxBodyBytes: 512})

	for _, idemVal := range []string{"req-key-123", ""} {
		req, _ := http.NewRequest(http.MethodPost, h.shimHTTP.URL+"/compat/e2b/v2/sandboxes", strings.NewReader(`{"templateID":"tpl-base"}`))
		req.Header.Set("X-API-KEY", testAdapterAPIKey)
		req.Header["Idempotency-Key"] = []string{idemVal}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assertAPIError(t, resp, raw, http.StatusBadRequest, "idempotency_key_unsupported", false)
	}

	largeBody := `{"templateID":"tpl-base","envVars":{"A":"` + strings.Repeat("x", 600) + `"}}`
	resp, raw := h.do(t, http.MethodPost, "/compat/e2b/v2/sandboxes", testAdapterAPIKey, largeBody)
	assertAPIError(t, resp, raw, http.StatusBadRequest, "request_too_large", false)

	for _, tc := range []struct {
		name, body, wantCode string
		wantStatus           int
	}{
		{"empty_body", "", "invalid_request", http.StatusBadRequest},
		{"malformed_json", `{"templateID":`, "invalid_request", http.StatusBadRequest},
		{"duplicate_field", `{"templateID":"tpl-base","templateID":"tpl-base"}`, "duplicate_field", http.StatusBadRequest},
		{"unknown_field", `{"templateID":"tpl-base","extraField":true}`, "unknown_field", http.StatusBadRequest},
		{"missing_template", `{"timeout":120}`, "missing_template_id", http.StatusBadRequest},
		{"empty_template", `{"templateID":""}`, "missing_template_id", http.StatusBadRequest},
		{"unknown_template", `{"templateID":"does-not-exist"}`, "template_not_found", http.StatusNotFound},
		{"unready_template", `{"templateID":"tpl-unready"}`, "template_not_ready", http.StatusBadRequest},
		{"incompatible_template", `{"templateID":"tpl-incompat"}`, "template_profile_incompatible", http.StatusBadRequest},
		{"autoPause_true", `{"templateID":"tpl-base","autoPause":true}`, "unsupported_option", http.StatusBadRequest},
		{"autoPauseMemory", `{"templateID":"tpl-base","autoPauseMemory":true}`, "unsupported_option", http.StatusBadRequest},
		{"autoResume", `{"templateID":"tpl-base","autoResume":{"enabled":true}}`, "unsupported_option", http.StatusBadRequest},
		{"network", `{"templateID":"tpl-base","network":{"allowOut":["1.1.1.1"]}}`, "unsupported_option", http.StatusBadRequest},
		{"mcp", `{"templateID":"tpl-base","mcp":{}}`, "unsupported_option", http.StatusBadRequest},
		{"iam", `{"templateID":"tpl-base","iam":{}}`, "unsupported_option", http.StatusBadRequest},
		{"volumeMounts", `{"templateID":"tpl-base","volumeMounts":[]}`, "unsupported_option", http.StatusBadRequest},
		{"secure_false", `{"templateID":"tpl-base","secure":false}`, "unsupported_option", http.StatusBadRequest},
		{"allow_internet_false", `{"templateID":"tpl-base","allow_internet_access":false}`, "unsupported_option", http.StatusBadRequest},
		{"timeout_null", `{"templateID":"tpl-base","timeout":null}`, "invalid_timeout", http.StatusBadRequest},
		{"timeout_float", `{"templateID":"tpl-base","timeout":60.5}`, "invalid_timeout", http.StatusBadRequest},
		{"timeout_string", `{"templateID":"tpl-base","timeout":"120"}`, "invalid_timeout", http.StatusBadRequest},
		{"timeout_zero", `{"templateID":"tpl-base","timeout":0}`, "invalid_timeout", http.StatusBadRequest},
		{"timeout_negative", `{"templateID":"tpl-base","timeout":-10}`, "invalid_timeout", http.StatusBadRequest},
		{"timeout_below_60", `{"templateID":"tpl-base","timeout":59}`, "timeout_below_minimum", http.StatusBadRequest},
		{"timeout_above_profile_max", `{"templateID":"tpl-base","timeout":3601}`, "timeout_exceeds_maximum", http.StatusBadRequest},
		{"timeout_above_template_max", `{"templateID":"tpl-capped","timeout":601}`, "timeout_exceeds_maximum", http.StatusBadRequest},
		{"reserved_meta_shim", `{"templateID":"tpl-base","metadata":{"e2b-shim-managed":"true"}}`, "reserved_metadata_key", http.StatusBadRequest},
		{"reserved_meta_native", `{"templateID":"tpl-base","metadata":{"opensandbox.io/x":"v"}}`, "reserved_metadata_key", http.StatusBadRequest},
		{"invalid_meta_key", `{"templateID":"tpl-base","metadata":{"UPPERCASE":"v"}}`, "invalid_metadata_key", http.StatusBadRequest},
		{"invalid_meta_val", `{"templateID":"tpl-base","metadata":{"team":"bad space"}}`, "invalid_metadata_value", http.StatusBadRequest},
		{"invalid_env_key", `{"templateID":"tpl-base","envVars":{"A=B":"v"}}`, "invalid_env_var", http.StatusBadRequest},
		{"invalid_env_nul", "{\"templateID\":\"tpl-base\",\"envVars\":{\"A\":\"x\\u0000y\"}}", "invalid_env_var", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, raw := h.do(t, http.MethodPost, "/compat/e2b/v2/sandboxes", testAdapterAPIKey, tc.body)
			assertAPIError(t, resp, raw, tc.wantStatus, tc.wantCode, false)
		})
	}

	if st := h.fakeNative.Stats(); st.Create != 0 || st.TotalCreated != 0 {
		t.Fatalf("native Create stats = %+v, want 0 allocations across all rejected create cases", st)
	}
}

func TestCreateHappyPathReadinessPollingAndAdmissionOrdering(t *testing.T) {
	h := newHarness(t, harnessOpts{domain: "sandbox.example.internal"})
	h.fakeNative.SetTemplate(fakenative.TemplateSpec{ID: "native-tpl-base", Ready: true, InitialState: native.StatePending})

	var order []string
	var orderMu sync.Mutex
	pushOrder := func(step string) { orderMu.Lock(); order = append(order, step); orderMu.Unlock() }

	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := h.fakeNative.GetSandboxSnapshot("sbx-1"); ok {
				_ = h.fakeNative.ScheduleTransitions("sbx-1", []fakenative.TransitionStep{
					{State: native.StatePending}, {State: native.StateRunning},
				})
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	h.init.fn = func(ctx context.Context, req adapter.EnvdInitRequest) (*adapter.EnvdInitResult, error) {
		if openNow, err := h.admission.IsOpen(ctx, req.SandboxID); err != nil || openNow {
			t.Errorf("admission IsOpen during Initialize = (%v, %v), want (false, nil)", openNow, err)
		}
		pushOrder("init")
		return &adapter.EnvdInitResult{EnvdVersion: "0.1.4"}, nil
	}
	h.admission.onOpen = func(_ context.Context, rec adapter.AdmissionRecord) error {
		if !rec.Initialized {
			t.Error("AdmissionRecord.Initialized must be true")
		}
		pushOrder("admission_open")
		return nil
	}

	body := `{"templateID":"base","autoPause":false,"secure":true,"allow_internet_access":true,"envVars":{"APP_SECRET":"` + testEnvSecretVal + `"},"metadata":{"tenant":"` + testMetaUserVal + `"}}`
	resp, raw := h.do(t, http.MethodPost, "/compat/e2b/v2/sandboxes", testAdapterAPIKey, body)
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("Should-Retry") != "" {
		t.Fatalf("POST /v2/sandboxes status=%d Should-Retry=%q body=%s", resp.StatusCode, resp.Header.Get("Should-Retry"), string(raw))
	}

	var rawMap map[string]any
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		t.Fatalf("unmarshal 201 JSON: %v", err)
	}
	if _, hasTrafficToken := rawMap["trafficAccessToken"]; hasTrafficToken {
		t.Fatalf("201 response MUST NOT contain trafficAccessToken: %s", string(raw))
	}

	deriver, _ := rules.NewTokenDeriver(h.cfg.HMACKey, testKeyVersion, testAdapterID)
	wantToken, _ := deriver.Derive("sbx-1")
	for k, want := range map[string]string{
		"templateID": "tpl-base", "sandboxID": "sbx-1", "clientID": testAdapterID,
		"envdVersion": "0.1.4", "envdAccessToken": wantToken, "domain": "sandbox.example.internal",
	} {
		if got, _ := rawMap[k].(string); got != want {
			t.Errorf("field %q = %q, want %q", k, got, want)
		}
	}

	orderMu.Lock()
	gotOrder := strings.Join(order, "->")
	orderMu.Unlock()
	if gotOrder != "init->admission_open" {
		t.Fatalf("initialization/admission order = %q, want init->admission_open", gotOrder)
	}
	if isOpen, err := h.admission.IsOpen(context.Background(), "sbx-1"); err != nil || !isOpen {
		t.Fatalf("admission IsOpen(sbx-1) = %v, %v; want true, nil", isOpen, err)
	}
	calls := h.init.Calls()
	if len(calls) != 1 || calls[0].DefaultUser != "user" || calls[0].AccessToken != wantToken || calls[0].EnvVars["APP_SECRET"] != testEnvSecretVal ||
		calls[0].Endpoint == nil || calls[0].Endpoint.Headers["OpenSandbox-Ingress-To"] != testIngressToken {
		t.Fatalf("unexpected EnvdInitRequest received by initializer")
	}
	if snap, ok := h.fakeNative.GetSandboxSnapshot("sbx-1"); !ok || snap.Metadata[rules.MetaKeyRevision] != "tpl-base.rev-1" || snap.Metadata["tenant"] != testMetaUserVal {
		t.Fatalf("unexpected persisted native metadata: %v", snap.Metadata)
	}

	hNoDomain := newHarness(t, harnessOpts{})
	resp2, raw2 := hNoDomain.do(t, http.MethodPost, "/compat/e2b/v2/sandboxes", testAdapterAPIKey, `{"templateID":"tpl-base"}`)
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp2.StatusCode)
	}
	var noDomMap map[string]any
	_ = json.Unmarshal(raw2, &noDomMap)
	if _, present := noDomMap["domain"]; present {
		t.Errorf("expected domain omitted when empty, got %s", string(raw2))
	}
}

func TestCreateFailuresZeroReplayAndPostAllocationCleanup(t *testing.T) {
	t.Run("ambiguous_create_drop_after_execute_zero_replay", func(t *testing.T) {
		h := newHarness(t, harnessOpts{})
		h.fakeNative.AddFault(fakenative.FaultRule{Operation: "create", Remaining: 1, DropAfterExecute: true})
		resp, raw := h.do(t, http.MethodPost, "/compat/e2b/v2/sandboxes", testAdapterAPIKey, `{"templateID":"tpl-base"}`)
		assertAPIError(t, resp, raw, http.StatusServiceUnavailable, "create_outcome_ambiguous", true)
		if st := h.fakeNative.Stats(); st.Create != 1 {
			t.Fatalf("native Create calls = %d, want strictly 1 (zero replay)", st.Create)
		}
	})

	t.Run("definite_native_create_errors", func(t *testing.T) {
		for _, tc := range []struct {
			nativeStatus, wantStatus int
			wantNoRetry              bool
		}{
			{http.StatusNotFound, http.StatusNotFound, false},
			{http.StatusConflict, http.StatusConflict, false},
			{http.StatusTooManyRequests, http.StatusTooManyRequests, false},
			{http.StatusForbidden, http.StatusForbidden, false},
			{http.StatusUnauthorized, http.StatusServiceUnavailable, true},
		} {
			h := newHarness(t, harnessOpts{})
			h.fakeNative.AddFault(fakenative.FaultRule{Operation: "create", Remaining: 1, StatusCode: tc.nativeStatus})
			resp, raw := h.do(t, http.MethodPost, "/compat/e2b/v2/sandboxes", testAdapterAPIKey, `{"templateID":"tpl-base"}`)
			assertAPIError(t, resp, raw, tc.wantStatus, "", tc.wantNoRetry)
		}
	})

	for _, tc := range []struct {
		name, wantError string
		setup           func(*harness)
	}{
		{"readiness_timeout_independent_of_ttl", "sandbox_readiness_failed", func(h *harness) {
			h.fakeNative.SetTemplate(fakenative.TemplateSpec{ID: "native-tpl-base", Ready: true, InitialState: native.StatePending})
		}},
		{"readiness_transitions_to_failed", "sandbox_readiness_failed", func(h *harness) {
			h.fakeNative.SetTemplate(fakenative.TemplateSpec{ID: "native-tpl-base", Ready: true, InitialState: native.StateFailed})
		}},
		{"get_endpoint_fails", "endpoint_resolution_failed", func(h *harness) {
			h.fakeNative.AddFault(fakenative.FaultRule{Operation: "endpoint", Remaining: 1, StatusCode: http.StatusConflict})
		}},
		{"envd_initializer_error", "envd_init_failed", func(h *harness) {
			h.init.fn = func(context.Context, adapter.EnvdInitRequest) (*adapter.EnvdInitResult, error) {
				return nil, errors.New("envd /init failed: secret=" + testEnvSecretVal)
			}
		}},
		{"envd_version_mismatch", "envd_init_failed", func(h *harness) {
			h.init.fn = func(context.Context, adapter.EnvdInitRequest) (*adapter.EnvdInitResult, error) {
				return &adapter.EnvdInitResult{EnvdVersion: "0.1.99"}, nil
			}
		}},
		{"envd_version_empty", "envd_init_failed", func(h *harness) {
			h.init.fn = func(context.Context, adapter.EnvdInitRequest) (*adapter.EnvdInitResult, error) {
				return &adapter.EnvdInitResult{}, nil
			}
		}},
		{"admission_open_fails", "admission_open_failed", func(h *harness) {
			h.admission.onOpen = func(context.Context, adapter.AdmissionRecord) error { return errors.New("admission down") }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, harnessOpts{readinessTimeout: 60 * time.Millisecond, readinessPollInterval: 10 * time.Millisecond})
			tc.setup(h)
			resp, raw := h.do(t, http.MethodPost, "/compat/e2b/v2/sandboxes", testAdapterAPIKey, `{"templateID":"tpl-base","timeout":300,"envVars":{"S":"`+testEnvSecretVal+`"}}`)
			assertAPIError(t, resp, raw, http.StatusServiceUnavailable, tc.wantError, true)
			if st := h.fakeNative.Stats(); st.Create != 1 || st.Delete != 1 || st.ActiveSandboxes != 0 {
				t.Fatalf("cleanup verification failed: stats = %+v", st)
			}
			if openNow, err := h.admission.IsOpen(context.Background(), "sbx-1"); err != nil || openNow {
				t.Fatalf("admission must remain closed: open=%v err=%v", openNow, err)
			}
		})
	}
}

func createOneSandbox(t *testing.T, h *harness) string {
	t.Helper()
	resp, raw := h.do(t, http.MethodPost, "/compat/e2b/v2/sandboxes", testAdapterAPIKey, `{"templateID":"tpl-base"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("createOneSandbox failed: status=%d body=%s", resp.StatusCode, string(raw))
	}
	var out struct{ SandboxID string }
	if err := json.Unmarshal(raw, &out); err != nil || out.SandboxID == "" {
		t.Fatalf("unmarshal sandboxID: %v (%s)", err, string(raw))
	}
	return out.SandboxID
}

func TestDeleteTwoConditionMatrix(t *testing.T) {
	t.Run("invalid_sandbox_id_returns_400_zero_native_calls", func(t *testing.T) {
		h := newHarness(t, harnessOpts{})
		for _, rawSeg := range []string{".", "..", "%2e%2e", "a%2Fb", "a%5cb", "bad%20id"} {
			resp, raw := h.do(t, http.MethodDelete, "/compat/e2b/sandboxes/"+rawSeg, testAdapterAPIKey, "")
			assertAPIError(t, resp, raw, http.StatusBadRequest, "invalid_sandbox_id", false)
		}
		if st := h.fakeNative.Stats(); st != (fakenative.Stats{}) {
			t.Fatalf("native stats = %+v, want zero", st)
		}
	})

	t.Run("happy_delete_all_states_and_duplicate_delete_404", func(t *testing.T) {
		for _, retain := range []bool{true, false} {
			retainVal := retain
			for _, state := range []native.State{native.StatePending, native.StateRunning, native.StateFailed, native.StatePaused, native.StateStopping} {
				h := newHarness(t, harnessOpts{retainTerminated: &retainVal})
				id := createOneSandbox(t, h)
				if state != native.StateRunning {
					_ = h.fakeNative.SetState(id, state, "test", "transition")
				}
				var closedBeforeNativeDelete atomic.Bool
				h.admission.onClose = func(_ context.Context, sbxID string) error {
					if snap, ok := h.fakeNative.GetSandboxSnapshot(sbxID); ok && snap.Status.State == state {
						closedBeforeNativeDelete.Store(true)
					}
					return nil
				}

				resp, raw := h.do(t, http.MethodDelete, "/compat/e2b/sandboxes/"+id, testAdapterAPIKey, "")
				if resp.StatusCode != http.StatusNoContent || len(raw) != 0 || !closedBeforeNativeDelete.Load() {
					t.Fatalf("retain=%v state=%s: status=%d len=%d closedFirst=%v", retainVal, state, resp.StatusCode, len(raw), closedBeforeNativeDelete.Load())
				}
				if openNow, _ := h.admission.IsOpen(context.Background(), id); openNow {
					t.Fatalf("state %s: admission still open after DELETE", state)
				}

				h.admission.onClose = nil
				resp2, raw2 := h.do(t, http.MethodDelete, "/compat/e2b/sandboxes/"+id, testAdapterAPIKey, "")
				assertAPIError(t, resp2, raw2, http.StatusNotFound, "sandbox_not_found", false)
			}
		}
	})

	t.Run("unknown_and_unowned_sandboxes_return_404_without_deleting_native", func(t *testing.T) {
		h := newHarness(t, harnessOpts{})
		_ = h.admission.Open(context.Background(), adapter.AdmissionRecord{
			SandboxID: "sbx-ghost", TemplateRevision: "tpl-base.rev-1", EnvdVersion: "0.1.4", Initialized: true,
		})
		resp, raw := h.do(t, http.MethodDelete, "/compat/e2b/sandboxes/sbx-ghost", testAdapterAPIKey, "")
		assertAPIError(t, resp, raw, http.StatusNotFound, "sandbox_not_found", false)
		if openNow, _ := h.admission.IsOpen(context.Background(), "sbx-ghost"); openNow {
			t.Fatal("residual admission for sbx-ghost should have been closed")
		}

		nc, err := native.NewClient(native.ClientConfig{BaseURL: h.cfg.NativeAPIURL, APIKey: h.cfg.NativeAPIKey})
		if err != nil {
			t.Fatal(err)
		}
		unowned, err := nc.CreateTemplateSandbox(context.Background(), native.CreateTemplateSandboxRequest{
			TemplateID: "native-tpl-base", TimeoutSeconds: 300, Metadata: map[string]string{"owner": "native-team"},
		})
		if err != nil {
			t.Fatalf("direct native create: %v", err)
		}
		eventsBefore := len(h.admission.Events())
		resp, raw = h.do(t, http.MethodDelete, "/compat/e2b/sandboxes/"+unowned.ID, testAdapterAPIKey, "")
		assertAPIError(t, resp, raw, http.StatusNotFound, "sandbox_not_found", false)
		if len(h.admission.Events()) != eventsBefore || h.fakeNative.Stats().Delete != 0 {
			t.Fatalf("unowned sandbox touched! events=%v stats=%+v", h.admission.Events(), h.fakeNative.Stats())
		}
		if snap, ok := h.fakeNative.GetSandboxSnapshot(unowned.ID); !ok || snap.Status.State != native.StateRunning {
			t.Fatalf("unowned sandbox state = %+v, ok=%v; want Running", snap, ok)
		}
	})

	t.Run("admission_close_failure_blocks_204_and_skips_native_delete", func(t *testing.T) {
		h := newHarness(t, harnessOpts{})
		id := createOneSandbox(t, h)
		h.admission.onClose = func(context.Context, string) error { return errors.New("revocation failed") }
		resp, raw := h.do(t, http.MethodDelete, "/compat/e2b/sandboxes/"+id, testAdapterAPIKey, "")
		assertAPIError(t, resp, raw, http.StatusServiceUnavailable, "admission_close_failed", true)
		if st := h.fakeNative.Stats(); st.Delete != 0 {
			t.Fatalf("native Delete called despite Admission.Close failure: Delete=%d", st.Delete)
		}
	})

	t.Run("ambiguous_delete_drop_after_execute_reconciles_to_204_zero_replay", func(t *testing.T) {
		for _, retain := range []bool{true, false} {
			retainVal := retain
			h := newHarness(t, harnessOpts{retainTerminated: &retainVal})
			id := createOneSandbox(t, h)
			h.fakeNative.AddFault(fakenative.FaultRule{Operation: "delete", SandboxID: id, Remaining: 1, DropAfterExecute: true})
			resp, raw := h.do(t, http.MethodDelete, "/compat/e2b/sandboxes/"+id, testAdapterAPIKey, "")
			if resp.StatusCode != http.StatusNoContent || len(raw) != 0 {
				t.Fatalf("retain=%v: status=%d body=%q, want 204", retainVal, resp.StatusCode, string(raw))
			}
			if st := h.fakeNative.Stats(); st.Delete != 1 || st.Get != 2 {
				t.Fatalf("retain=%v: stats=%+v, want Delete=1 Get=2", retainVal, st)
			}
		}
	})

	t.Run("ambiguous_delete_drop_before_execute_still_running_returns_503_no_retry", func(t *testing.T) {
		h := newHarness(t, harnessOpts{})
		id := createOneSandbox(t, h)
		h.fakeNative.AddFault(fakenative.FaultRule{Operation: "delete", SandboxID: id, Remaining: 1, DropBeforeExecute: true})
		resp, raw := h.do(t, http.MethodDelete, "/compat/e2b/sandboxes/"+id, testAdapterAPIKey, "")
		assertAPIError(t, resp, raw, http.StatusServiceUnavailable, "delete_outcome_ambiguous", true)
		if st := h.fakeNative.Stats(); st.Delete != 0 || st.Get != 2 {
			t.Fatalf("stats = %+v, want Delete=0 Get=2 (zero replay)", st)
		}
		if openNow, _ := h.admission.IsOpen(context.Background(), id); openNow {
			t.Fatal("admission must stay closed after ambiguous delete")
		}
	})

	t.Run("native_delete_409_conflict_returns_409", func(t *testing.T) {
		h := newHarness(t, harnessOpts{})
		id := createOneSandbox(t, h)
		h.fakeNative.AddFault(fakenative.FaultRule{Operation: "delete", SandboxID: id, Remaining: 1, StatusCode: http.StatusConflict})
		resp, raw := h.do(t, http.MethodDelete, "/compat/e2b/sandboxes/"+id, testAdapterAPIKey, "")
		assertAPIError(t, resp, raw, http.StatusConflict, "lifecycle_conflict", false)
	})
}

func TestRedactionAndStructuredLogSafety(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	createBody := `{"templateID":"tpl-base","envVars":{"MY_SECRET":"` + testEnvSecretVal + `"},"metadata":{"team":"` + testMetaUserVal + `"}}`
	resp, rawCreate := h.do(t, http.MethodPost, "/compat/e2b/v2/sandboxes", testAdapterAPIKey, createBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	var created struct{ SandboxID, EnvdAccessToken string }
	if err := json.Unmarshal(rawCreate, &created); err != nil || created.EnvdAccessToken == "" {
		t.Fatalf("unmarshal create: %v", err)
	}
	_, errRaw1 := h.do(t, http.MethodGet, "/compat/e2b/v2/sandboxes", "wrong-secret-candidate-DO-NOT-LEAK", "")
	_, errRaw2 := h.do(t, http.MethodPost, "/compat/e2b/v2/sandboxes", testAdapterAPIKey, `{"templateID":"tpl-base","metadata":{"BAD_KEY":"`+testMetaUserVal+`"}}`)
	_, _ = h.do(t, http.MethodDelete, "/compat/e2b/sandboxes/"+created.SandboxID, testAdapterAPIKey, "")

	initReq := adapter.EnvdInitRequest{
		SandboxID: "sbx-1", DefaultUser: "user", ExpectedEnvdVersion: "0.1.4", AccessToken: created.EnvdAccessToken,
		Endpoint: &native.Endpoint{URL: "http://10.0.0.5:49983", Headers: map[string]string{"OpenSandbox-Ingress-To": testIngressToken}},
		EnvVars:  map[string]string{"MY_SECRET": testEnvSecretVal},
	}
	var fmtBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&fmtBuf, nil)).Info("dump", "handler", h.handler, "handler_val", *h.handler, "init_req", initReq)
	hJSON, _ := json.Marshal(h.handler)
	hText, _ := h.handler.MarshalText()
	rJSON, _ := json.Marshal(initReq)
	rText, _ := initReq.MarshalText()
	combined := strings.Join([]string{
		h.logs.String(), string(errRaw1), string(errRaw2),
		fmt.Sprintf("%s %v %+v %#v %q %x", h.handler, h.handler, *h.handler, *h.handler, h.handler, *h.handler),
		fmt.Sprintf("%s %v %+v %#v %q %x", initReq, initReq, initReq, initReq, initReq, initReq),
		string(hJSON), string(hText), string(rJSON), string(rText), fmtBuf.String(),
	}, "\n")
	for _, secret := range []string{
		testAdapterAPIKey, testNativeAPIKey, testHMACKey, testIngressToken,
		testEnvSecretVal, testMetaUserVal, created.EnvdAccessToken, "wrong-secret-candidate-DO-NOT-LEAK", "10.0.0.5",
	} {
		if strings.Contains(combined, secret) {
			t.Fatalf("redaction/log leak detected for %q in output:\n%s", secret, combined)
		}
	}

	allowedLogKeys := map[string]bool{
		"time": true, "level": true, "msg": true, "operation": true, "outcome": true,
		"status": true, "duration_ms": true, "request_id": true, "sandbox_id": true, "error_code": true,
	}
	for _, line := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("malformed JSON log line %q: %v", line, err)
		}
		for k := range entry {
			if !allowedLogKeys[k] {
				t.Fatalf("unexpected field %q in structured log line: %s", k, line)
			}
		}
	}
}
