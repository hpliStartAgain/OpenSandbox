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

package router

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/e2b-shim/internal/fakeenvd"
	"github.com/alibaba/opensandbox/e2b-shim/internal/fakenative"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/adapter"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/envdinit"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/service"
)

type fixture struct {
	h                   *Handler
	fn                  *fakenative.Server
	client              *native.Client
	cfg                 *config.Config
	id, token, upstream string
	logs                bytes.Buffer
}

func setup(t *testing.T, data http.Handler, ttl time.Duration) *fixture {
	t.Helper()
	env := map[string]string{
		"E2B_SHIM_NATIVE_API_URL": "http://127.0.0.1:1/v1", "E2B_SHIM_ADAPTER_ID": "adapter-test",
		"E2B_SHIM_HMAC_KEY_VERSION": "v1", "E2B_SHIM_DOMAIN": "sandbox.test", "E2B_SHIM_TIMEOUT_MAX_SECONDS": "3600",
		"E2B_SHIM_ADAPTER_API_KEY": "fake-adapter-key", "E2B_SHIM_NATIVE_API_KEY": "fake-native-key", "E2B_SHIM_HMAC_KEY": "fake-hmac-key",
		"E2B_SHIM_TEMPLATES": `[{"template_id":"base","native_template_id":"native-base","revision":"rev-1","expected_envd_version":"0.8.0"}]`,
	}
	cfg, err := config.Load(config.Source{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }})
	if err != nil {
		t.Fatal(err)
	}
	es := httptest.NewServer(fakeenvd.New(fakeenvd.Config{DataHandler: data}))
	t.Cleanup(es.Close)
	retain := false
	fn := fakenative.New(fakenative.Config{APIKey: env["E2B_SHIM_NATIVE_API_KEY"], BasePath: "/v1", RetainTerminated: &retain,
		DefaultTemplates: []fakenative.TemplateSpec{{ID: "native-base", Ready: true, InitialState: native.StateRunning}}})
	ns := httptest.NewServer(fn.Handler())
	t.Cleanup(ns.Close)
	cfg.NativeAPIURL = ns.URL + "/v1"
	client, err := native.NewClient(native.ClientConfig{BaseURL: cfg.NativeAPIURL, APIKey: cfg.NativeAPIKey, ReadMaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := rules.EncodeSandboxMetadata(rules.MetadataEncodeInput{AdapterID: cfg.AdapterID, Revision: "rev-1", HMACKeyVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	sbx, err := client.CreateTemplateSandbox(context.Background(), native.CreateTemplateSandboxRequest{TemplateID: "native-base", TimeoutSeconds: 300, Metadata: metadata})
	if err != nil {
		t.Fatal(err)
	}
	fn.SetEndpoint(sbx.ID, adapter.EnvdPort, native.Endpoint{URL: es.URL})
	deriver, _ := rules.NewTokenDeriver(cfg.HMACKey, cfg.HMACKeyVersion, cfg.AdapterID)
	token, _ := deriver.Derive(sbx.ID)
	if _, err := envdinit.New(nil).Initialize(context.Background(), adapter.EnvdInitRequest{
		SandboxID: sbx.ID, AccessToken: token, ExpectedEnvdVersion: "0.8.0", Endpoint: &native.Endpoint{URL: es.URL},
	}); err != nil {
		t.Fatal(err)
	}
	f := &fixture{fn: fn, client: client, cfg: cfg, id: sbx.ID, token: token, upstream: es.URL}
	f.h, err = New(Options{Config: cfg, Native: client, CacheTTL: ttl, Logger: slog.New(slog.NewJSONHandler(&f.logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) request(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.Header.Set("E2b-Sandbox-Id", f.id)
	r.Header.Set("E2b-Sandbox-Port", "49983")
	r.Header.Set("X-Access-Token", f.token)
	return r
}
func (f *fixture) status(r *http.Request) int {
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w.Code
}
func requireStatus(t *testing.T, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("status %d, want %d", got, want)
	}
}
func okHandler(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

func TestAdmissionBeforeNative(t *testing.T) {
	f := setup(t, http.HandlerFunc(okHandler), 0)
	other, _ := f.h.tokens.Derive("another-sandbox")
	tests := []struct {
		name   string
		edit   func(*http.Request)
		status int
	}{
		{"missing token", func(r *http.Request) { r.Header.Del("X-Access-Token") }, 401},
		{"wrong token", func(r *http.Request) { r.Header.Set("X-Access-Token", "wrong") }, 401},
		{"another token", func(r *http.Request) { r.Header.Set("X-Access-Token", other) }, 401},
		{"duplicate token", func(r *http.Request) { r.Header.Add("X-Access-Token", f.token) }, 401},
		{"duplicate selector", func(r *http.Request) { r.Header.Add("E2b-Sandbox-Id", f.id) }, 400},
		{"partial selectors", func(r *http.Request) { r.Header.Del("E2b-Sandbox-Port") }, 400},
		{"invalid id", func(r *http.Request) { r.Header.Set("E2b-Sandbox-Id", "a/b") }, 400},
		{"wrong port", func(r *http.Request) { r.Header.Set("E2b-Sandbox-Port", "80") }, 403},
		{"host conflict", func(r *http.Request) { r.Host = "49983-another.sandbox.test" }, 400},
		{"host port conflict", func(r *http.Request) { r.Host = "80-" + f.id + ".sandbox.test" }, 400},
		{"domain boundary", func(r *http.Request) {
			r.Header.Del("E2b-Sandbox-Id")
			r.Header.Del("E2b-Sandbox-Port")
			r.Host = "49983-" + f.id + ".sandbox.test.attacker.test"
		}, 404},
	}
	for _, name := range []string{"init", "upgrade", "freeze", "unfreeze", "collapse", "fsfreeze", "fsthaw"} {
		for _, p := range []string{"/" + name, "/" + name + "/", "//" + name, "/files/../" + name} {
			tests = append(tests, struct {
				name   string
				edit   func(*http.Request)
				status int
			}{p, func(r *http.Request) { r.URL.Path = p }, 403})
		}
	}
	tests = append(tests, struct {
		name   string
		edit   func(*http.Request)
		status int
	}{"escaped init", func(r *http.Request) { r.URL.Path = "/init"; r.URL.RawPath = "/%69nit" }, 403})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := f.fn.Stats()
			r := f.request("POST", "/process.Process/Start", nil)
			tt.edit(r)
			w := httptest.NewRecorder()
			f.h.ServeHTTP(w, r)
			requireStatus(t, w.Code, tt.status)
			var body struct {
				Code    int
				Message string
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Code != tt.status || body.Message != http.StatusText(tt.status) {
				t.Fatalf("invalid error envelope: %s", w.Body)
			}
			if after := f.fn.Stats(); after.Get != before.Get || after.Endpoint != before.Endpoint {
				t.Fatal("rejected request called native")
			}
		})
	}
	if strings.Contains(f.logs.String(), f.token) || strings.Contains(f.logs.String(), f.id) || strings.Contains(f.logs.String(), "attacker") {
		t.Fatal("unsafe request log")
	}
	if got := len(strings.Split(strings.TrimSpace(f.logs.String()), "\n")); got != len(tests) {
		t.Fatalf("log count %d, want %d", got, len(tests))
	}
}

func TestHostAndHeaderRouting(t *testing.T) {
	f := setup(t, http.HandlerFunc(okHandler), 0)
	for _, hostOnly := range []bool{false, true} {
		r := f.request("POST", "/process.Process/UntestedMethod", nil)
		r.Host = "49983-" + f.id + ".sandbox.test:8080"
		if hostOnly {
			r.Header.Del("E2b-Sandbox-Id")
			r.Header.Del("E2b-Sandbox-Port")
		}
		requireStatus(t, f.status(r), 204)
	}
	requireStatus(t, f.status(httptest.NewRequest("GET", "/healthz", nil)), 200)
	requireStatus(t, f.status(httptest.NewRequest("HEAD", "/healthz", nil)), 200)
	requireStatus(t, f.status(httptest.NewRequest("POST", "/healthz", nil)), 405)
}

func TestNativeStateAndFailures(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *fixture)
		status int
	}{
		{"unowned", func(t *testing.T, f *fixture) {
			v := "other"
			_, e := f.client.PatchMetadata(context.Background(), f.id, native.MetadataPatch{rules.MetaKeyAdapterID: &v})
			if e != nil {
				t.Fatal(e)
			}
		}, 404},
		{"unknown revision", func(t *testing.T, f *fixture) {
			v := "other"
			_, e := f.client.PatchMetadata(context.Background(), f.id, native.MetadataPatch{rules.MetaKeyRevision: &v})
			if e != nil {
				t.Fatal(e)
			}
		}, 404},
		{"missing", func(t *testing.T, f *fixture) {
			if e := f.client.DeleteSandbox(context.Background(), f.id); e != nil {
				t.Fatal(e)
			}
		}, 404},
		{"backend", func(_ *testing.T, f *fixture) { f.fn.AddFault(fakenative.FaultRule{Operation: "get", StatusCode: 503}) }, 503},
		{"ambiguous", func(_ *testing.T, f *fixture) {
			f.fn.AddFault(fakenative.FaultRule{Operation: "get", MalformedBody: true})
		}, 503},
		{"endpoint", func(_ *testing.T, f *fixture) {
			f.fn.AddFault(fakenative.FaultRule{Operation: "endpoint", StatusCode: 503})
		}, 503},
		{"invalid endpoint", func(_ *testing.T, f *fixture) {
			f.fn.SetEndpoint(f.id, adapter.EnvdPort, native.Endpoint{URL: "file:///private"})
		}, 503},
	}
	for _, state := range []native.State{native.StatePending, native.StatePaused, native.StateFailed, native.StateStopping, native.StateTerminated, native.StateUnknown} {
		tests = append(tests, struct {
			name   string
			change func(*testing.T, *fixture)
			status int
		}{string(state), func(t *testing.T, f *fixture) {
			if e := f.fn.SetState(f.id, state, "", ""); e != nil {
				t.Fatal(e)
			}
		}, 503})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := setup(t, http.HandlerFunc(okHandler), 0)
			tt.change(t, f)
			before := f.fn.Stats()
			requireStatus(t, f.status(f.request("POST", "/process.Process/Start", nil)), tt.status)
			requireStatus(t, f.status(f.request("POST", "/process.Process/Start", nil)), tt.status)
			after := f.fn.Stats()
			if after.Get-before.Get != 2 {
				t.Fatal("failure was cached")
			}
			if tt.name != "endpoint" && tt.name != "invalid endpoint" && after.Endpoint != before.Endpoint {
				t.Fatal("endpoint queried before sandbox admission")
			}
		})
	}
}

func TestPassthrough(t *testing.T) {
	var calls atomic.Int32
	f := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || r.URL.EscapedPath() != "/native/process.Process/SendInput" || r.URL.RawQuery != "scope=trusted&x=%2F&x=two+words&semi=a;b" || string(body) != "raw body" {
			t.Error("request changed")
		}
		if r.Host != "native.test" || r.Header.Get("OpenSandbox-Ingress-To") != "trusted-route" || r.Header.Get("X-Native-Scope") != "trusted-scope" || r.Header.Get("X-Hop") != "" || r.Header.Get("Connection") != "close" {
			t.Error("routing/hop headers incorrect")
		}
		if r.Header.Get("X-Access-Token") == "" || r.Header.Get("Connect-Timeout-Ms") != "8000" {
			t.Error("protocol headers lost")
		}
		w.Header().Set("X-Upstream", "unchanged")
		w.Header().Set("Trailer", "X-Final")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte("upstream error\x00\xff"))
		w.Header().Set("X-Final", "complete")
	}), 0)
	f.fn.SetEndpoint(f.id, adapter.EnvdPort, native.Endpoint{URL: f.upstream + "/native?scope=trusted", Headers: map[string]string{"Host": "native.test", "OpenSandbox-Ingress-To": "trusted-route", "X-Native-Scope": "trusted-scope"}})
	r := f.request("POST", "/process.Process/SendInput?x=%2F&x=two+words&semi=a;b", strings.NewReader("raw body"))
	r.Header.Set("OpenSandbox-Ingress-To", "forged")
	r.Header.Set("X-Native-Scope", "forged")
	r.Header.Set("Connection", "X-Hop, X-Native-Scope")
	r.Header.Set("X-Hop", "forged")
	r.Header.Set("Connect-Timeout-Ms", "8000")
	r.Header.Set("Content-Type", "application/connect+json")
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	requireStatus(t, w.Code, 422)
	resp := w.Result()
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != "upstream error\x00\xff" || resp.Header.Get("X-Upstream") != "unchanged" || resp.Trailer.Get("X-Final") != "complete" || calls.Load() != 1 {
		t.Fatal("upstream response changed or replayed")
	}
}

func TestForgedIngressHeaderStrippedWithoutEndpointValue(t *testing.T) {
	var got atomic.Value
	f := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Values("OpenSandbox-Ingress-To"))
		w.WriteHeader(http.StatusOK)
	}), 0)
	// A non-empty header set without OpenSandbox-Ingress-To keeps the fake from
	// adding its default, so only the explicit strip can remove the forged value.
	f.fn.SetEndpoint(f.id, adapter.EnvdPort, native.Endpoint{URL: f.upstream, Headers: map[string]string{"X-Native-Scope": "trusted-scope"}})
	r := f.request("GET", "/files?path=%2Ftmp%2Fa", nil)
	r.Header.Set("OpenSandbox-Ingress-To", "forged")
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	requireStatus(t, w.Code, 200)
	if v, _ := got.Load().([]string); len(v) != 0 {
		t.Fatalf("client-supplied OpenSandbox-Ingress-To reached upstream: %q", v)
	}
}

func TestBinaryFiles(t *testing.T) {
	payload := make([]byte, 3<<20)
	for i := range payload {
		payload[i] = byte(i)
	}
	var uploaded []byte
	f := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/files" || r.URL.RawQuery != "path=%2Ftmp%2Fbinary" {
			t.Error("file target changed")
		}
		if r.Method == "POST" {
			mr, err := r.MultipartReader()
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			part, err := mr.NextPart()
			if err != nil {
				t.Error(err)
				return
			}
			uploaded, err = io.ReadAll(part)
			if err != nil {
				t.Error(err)
			}
			w.WriteHeader(201)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	}), 0)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "binary")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(payload)
	_ = mw.Close()
	r := f.request("POST", "/files?path=%2Ftmp%2Fbinary", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	requireStatus(t, f.status(r), 201)
	if !bytes.Equal(uploaded, payload) {
		t.Fatal("binary upload changed")
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, f.request("GET", "/files?path=%2Ftmp%2Fbinary", nil))
	requireStatus(t, w.Code, 200)
	if !bytes.Equal(w.Body.Bytes(), payload) {
		t.Fatal("binary download changed")
	}
}

func TestStreamingAndClientDisconnect(t *testing.T) {
	first := []byte{0, 0, 0, 0, 3, 'o', 'n', 'e'}
	second := []byte{0, 0, 0, 0, 3, 't', 'w', 'o'}
	release := make(chan struct{})
	canceled := make(chan struct{})
	completed := make(chan struct{})
	f := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/connect+json")
		_, _ = w.Write(first)
		_ = http.NewResponseController(w).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			close(canceled)
			return
		}
		_, _ = w.Write(second)
		_ = http.NewResponseController(w).Flush()
		close(completed)
		<-r.Context().Done()
		close(canceled)
	}), 0)
	// Discard logs while a real listener writes concurrently with assertions.
	f.h.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	rs := httptest.NewServer(f.h)
	defer rs.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := f.request("POST", rs.URL+"/process.Process/Start", strings.NewReader(`{}`))
	r.RequestURI = ""
	r = r.WithContext(ctx)
	r.Header.Set("Content-Type", "application/connect+json")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	frame := make([]byte, len(first))
	if _, err := io.ReadFull(resp.Body, frame); err != nil || !bytes.Equal(frame, first) {
		t.Fatalf("first frame: %v", err)
	}
	select {
	case <-completed:
		t.Fatal("buffered until upstream finished")
	default:
	}
	// Close invalidates only new requests and does not terminate this stream.
	if err := f.h.Close(context.Background(), f.id); err != nil {
		t.Fatal(err)
	}
	close(release)
	if _, err := io.ReadFull(resp.Body, frame); err != nil || !bytes.Equal(frame, second) {
		t.Fatalf("second frame: %v", err)
	}
	cancel()
	resp.Body.Close()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream context not canceled")
	}
}

func TestCacheDeletionAndRefresh(t *testing.T) {
	for _, invalidate := range []bool{false, true} {
		t.Run(map[bool]string{false: "TTL", true: "Close"}[invalidate], func(t *testing.T) {
			const ttl = 35 * time.Millisecond
			f := setup(t, http.HandlerFunc(okHandler), ttl)
			requireStatus(t, f.status(f.request("GET", "/files", nil)), 204)
			stats := f.fn.Stats()
			requireStatus(t, f.status(f.request("GET", "/files", nil)), 204)
			if f.fn.Stats().Get != stats.Get {
				t.Fatal("positive result not cached")
			}
			if err := f.client.DeleteSandbox(context.Background(), f.id); err != nil {
				t.Fatal(err)
			}
			if invalidate {
				if err := f.h.Close(context.Background(), f.id); err != nil {
					t.Fatal(err)
				}
			} else {
				time.Sleep(ttl + 5*time.Millisecond)
			}
			requireStatus(t, f.status(f.request("GET", "/files", nil)), 404)
		})
	}
	f := setup(t, http.HandlerFunc(okHandler), 25*time.Millisecond)
	requireStatus(t, f.status(f.request("GET", "/files", nil)), 204)
	f.fn.AddFault(fakenative.FaultRule{Operation: "get", StatusCode: 503})
	time.Sleep(30 * time.Millisecond)
	requireStatus(t, f.status(f.request("GET", "/files", nil)), 503)
}

func TestH2C(t *testing.T) {
	f := setup(t, http.HandlerFunc(okHandler), 0)
	f.h.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.ServeRouter(ctx, ln, f.h, time.Second) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Protocols = protocols
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	r := f.request("POST", "http://"+ln.Addr().String()+"/process.Process/CloseStdin", nil)
	r.RequestURI = ""
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	requireStatus(t, resp.StatusCode, 204)
	if resp.ProtoMajor != 2 {
		t.Fatalf("protocol %s", resp.Proto)
	}
}

type blockedEndpoint struct {
	Backend
	entered, release chan struct{}
}

func (b *blockedEndpoint) GetEndpoint(ctx context.Context, id string, port int) (*native.Endpoint, error) {
	ep, err := b.Backend.GetEndpoint(ctx, id, port)
	close(b.entered)
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return ep, err
}

func TestInvalidateFencesRefresh(t *testing.T) {
	f := setup(t, http.HandlerFunc(okHandler), 0)
	blocked := &blockedEndpoint{Backend: f.client, entered: make(chan struct{}), release: make(chan struct{})}
	f.h.native = blocked
	result := make(chan int, 1)
	go func() { result <- f.status(f.request("GET", "/files", nil)) }()
	select {
	case <-blocked.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("endpoint not queried")
	}
	f.h.Invalidate(f.id)
	close(blocked.release)
	select {
	case status := <-result:
		requireStatus(t, status, 503)
	case <-time.After(3 * time.Second):
		t.Fatal("refresh blocked")
	}
	f.h.native = f.client
	requireStatus(t, f.status(f.request("GET", "/files", nil)), 204)
}

func TestSharedAdapterInvalidatesOnDelete(t *testing.T) {
	f := setup(t, http.HandlerFunc(okHandler), 0)
	ctx := context.Background()
	if err := f.h.Open(ctx, adapter.AdmissionRecord{SandboxID: f.id, Initialized: true, TemplateRevision: "rev-1", EnvdVersion: "0.8.0"}); err != nil {
		t.Fatal(err)
	}
	if open, err := f.h.IsOpen(ctx, f.id); err != nil || !open {
		t.Fatalf("admission open=%t error=%v", open, err)
	}
	requireStatus(t, f.status(f.request("GET", "/files", nil)), 204)
	a, err := adapter.New(adapter.Options{Config: f.cfg, Native: f.client, Admission: f.h, Initializer: envdinit.New(nil)})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("DELETE", f.cfg.CompatPrefix+"/sandboxes/"+f.id, nil)
	r.Header.Set("X-API-KEY", f.cfg.AdapterAPIKey.Reveal())
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	requireStatus(t, w.Code, 204)
	requireStatus(t, f.status(f.request("GET", "/files", nil)), 404)
	if open, err := f.h.IsOpen(ctx, f.id); err != nil || open {
		t.Fatalf("admission open=%t error=%v", open, err)
	}
}

func TestUpstreamTransportFailure(t *testing.T) {
	f := setup(t, http.HandlerFunc(okHandler), 0)
	upstream := httptest.NewServer(http.HandlerFunc(okHandler))
	target := upstream.URL
	upstream.Close()
	f.fn.SetEndpoint(f.id, adapter.EnvdPort, native.Endpoint{URL: target})
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, f.request("POST", "/process.Process/Start", strings.NewReader("payload")))
	requireStatus(t, w.Code, 502)
	if strings.Contains(w.Body.String(), target) || strings.Contains(f.logs.String(), target) {
		t.Fatal("upstream target leaked")
	}
}

func TestUpstreamDisconnectDoesNotReplay(t *testing.T) {
	var calls atomic.Int32
	f := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}), 0)
	r := f.request("POST", "/process.Process/Start", strings.NewReader("non-idempotent"))
	r.Header.Set("Idempotency-Key", "client-replay-bait")
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("non-idempotent")), nil }
	requireStatus(t, f.status(r), 502)
	if calls.Load() != 1 {
		t.Fatalf("upstream call count %d", calls.Load())
	}
}

type sandboxObservation struct {
	Backend
	change func(*native.Sandbox)
}

func (b sandboxObservation) GetSandbox(ctx context.Context, id string) (*native.Sandbox, error) {
	sbx, err := b.Backend.GetSandbox(ctx, id)
	if sbx != nil {
		b.change(sbx)
	}
	return sbx, err
}

func TestAmbiguousAndExpiredObservations(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*native.Sandbox)
	}{
		{"identity mismatch", func(s *native.Sandbox) { s.ID = "another" }},
		{"unknown expiry", func(s *native.Sandbox) { s.ExpiresAt = nil }},
		{"expired", func(s *native.Sandbox) { expired := time.Now().Add(-time.Second); s.ExpiresAt = &expired }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := setup(t, http.HandlerFunc(okHandler), 0)
			f.h.native = sandboxObservation{Backend: f.client, change: tt.change}
			before := f.fn.Stats().Endpoint
			requireStatus(t, f.status(f.request("GET", "/files", nil)), 503)
			if f.fn.Stats().Endpoint != before {
				t.Fatal("queried endpoint for ambiguous observation")
			}
		})
	}
}
