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

package fakenative_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/e2b-shim/internal/fakenative"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
)

const testNativeSecret = "fake-native-secret-DO-NOT-LEAK"

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func newManualClock(t0 time.Time) *manualClock { return &manualClock{now: t0.UTC()} }
func (c *manualClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *manualClock) Advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

type okResult[T any] struct {
	v   T
	err error
}

func ok[T any](v T, err error) okResult[T] { return okResult[T]{v: v, err: err} }

func (r okResult[T]) must(t *testing.T) T {
	t.Helper()
	if r.err != nil {
		t.Fatalf("unexpected error: %v", r.err)
	}
	return r.v
}

func mustNativeClient(t *testing.T, baseURL, apiKey string, mod func(*native.ClientConfig)) *native.Client {
	t.Helper()
	env := map[string]string{
		"E2B_SHIM_NATIVE_API_URL": "https://native.example.internal/v1", "E2B_SHIM_ADAPTER_ID": "e2b-shim-test",
		"E2B_SHIM_HMAC_KEY_VERSION": "v1", "E2B_SHIM_TIMEOUT_MAX_SECONDS": "3600",
		"E2B_SHIM_ADAPTER_API_KEY": "adapter-key-placeholder", "E2B_SHIM_NATIVE_API_KEY": apiKey,
		"E2B_SHIM_HMAC_KEY": "hmac-key-placeholder",
	}
	cfg := ok(config.Load(config.Source{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }})).must(t)
	cc := native.ClientConfig{BaseURL: baseURL, APIKey: cfg.NativeAPIKey}
	if mod != nil {
		mod(&cc)
	}
	return ok(native.NewClient(cc)).must(t)
}

func rawJSONRequest(t *testing.T, method, url, apiKey, body string) (*http.Response, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := ok(http.NewRequest(method, url, rdr)).must(t)
	if apiKey != "" {
		req.Header.Set("OPEN-SANDBOX-API-KEY", apiKey)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp := ok(http.DefaultClient.Do(req)).must(t)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

func TestAuthenticationBasePathAndSecretRedaction(t *testing.T) {
	cfg := fakenative.Config{
		APIKey: testNativeSecret, BasePath: "custom/v1///",
		DefaultTemplates: []fakenative.TemplateSpec{{ID: "tpl-auth", Ready: true}}, MaxTimeoutSeconds: 3600,
	}
	fake := fakenative.New(cfg)
	ts := httptest.NewServer(fake.Handler())
	defer ts.Close()

	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("dump", "cfg", cfg, "srv", fake)
	cfgJSON := ok(json.Marshal(cfg)).must(t)
	srvJSON := ok(json.Marshal(fake)).must(t)
	cfgText := ok(cfg.MarshalText()).must(t)
	srvText := ok(fake.MarshalText()).must(t)
	if dumped := fmt.Sprintf("%s|%+v|%#v|%s|%+v|%#v|%s|%s|%s|%s|%s",
		cfg, cfg, cfg, fake, fake, fake, cfgJSON, srvJSON, cfgText, srvText, logBuf.String()); strings.Contains(dumped, testNativeSecret) {
		t.Fatalf("secret leaked in formatted/logged output: %s", dumped)
	}
	for _, key := range []string{"", "wrong-key", testNativeSecret + "-extra"} {
		resp, raw := rawJSONRequest(t, http.MethodPost, ts.URL+"/custom/v1/sandboxes", key, `{"templateId":"tpl-auth","timeout":60}`)
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("X-Request-ID") == "" ||
			strings.Contains(raw, testNativeSecret) || (key != "" && strings.Contains(raw, key)) {
			t.Fatalf("key=%q: status=%d body=%s", key, resp.StatusCode, raw)
		}
	}
	cli := mustNativeClient(t, ts.URL+"/custom/v1", testNativeSecret, nil)
	res := ok(cli.CreateTemplateSandbox(context.Background(), native.CreateTemplateSandboxRequest{TemplateID: "tpl-auth", TimeoutSeconds: 60})).must(t)
	if res.ID != "sbx-1" {
		t.Fatalf("got ID %q, want sbx-1", res.ID)
	}
}

func TestTemplateModeCreateValidationMatrix(t *testing.T) {
	fake := fakenative.New(fakenative.Config{
		APIKey: testNativeSecret, MaxTimeoutSeconds: 3600,
		DefaultTemplates: []fakenative.TemplateSpec{
			{ID: "tpl-ready", Ready: true, Entrypoint: []string{"/usr/bin/envd", "--port", "49983"}},
			{ID: "tpl-unready", Ready: false},
		},
	})
	ts := httptest.NewServer(fake.Handler())
	defer ts.Close()

	validShimMeta := ok(rules.EncodeSandboxMetadata(rules.MetadataEncodeInput{
		AdapterID: "e2b-shim-dev", Revision: "tpl-ready.rev-1", HMACKeyVersion: "v1",
		UserMetadata: map[string]string{"team": "core-1"},
	})).must(t)
	validMetaJSON, _ := json.Marshal(validShimMeta)

	for _, tc := range []struct {
		name, body string
		wantStatus int
		wantCode   string
	}{
		{"valid_minimal_min_timeout", `{"templateId":"tpl-ready","timeout":60}`, http.StatusAccepted, ""},
		{"valid_max_timeout_and_shim_meta", fmt.Sprintf(`{"templateId":"tpl-ready","timeout":3600,"secureAccess":false,"metadata":%s,"extensions":{"trace.id":"t1"}}`, validMetaJSON), http.StatusAccepted, ""},
		{"missing_templateId", `{"timeout":300}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"empty_templateId", `{"templateId":"","timeout":300}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"whitespace_templateId", `{"templateId":"tpl ready","timeout":300}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"non_string_templateId", `{"templateId":123,"timeout":300}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"unknown_field_templateID", `{"templateID":"tpl-ready","timeout":300}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"unknown_template", `{"templateId":"tpl-missing","timeout":300}`, http.StatusNotFound, "NOT_FOUND"},
		{"unready_template", `{"templateId":"tpl-unready","timeout":300}`, http.StatusNotFound, "NOT_FOUND"},
		{"missing_timeout", `{"templateId":"tpl-ready"}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"null_timeout", `{"templateId":"tpl-ready","timeout":null}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"float_timeout", `{"templateId":"tpl-ready","timeout":60.0}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"string_timeout", `{"templateId":"tpl-ready","timeout":"60"}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"leading_zero_timeout", `{"templateId":"tpl-ready","timeout":060}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"timeout_below_60", `{"templateId":"tpl-ready","timeout":59}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"timeout_above_max", `{"templateId":"tpl-ready","timeout":3601}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_image", `{"templateId":"tpl-ready","timeout":300,"image":{"uri":"alpine:3"}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_snapshotId", `{"templateId":"tpl-ready","timeout":300,"snapshotId":"snap-1"}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_entrypoint", `{"templateId":"tpl-ready","timeout":300,"entrypoint":["/bin/sh"]}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_env", `{"templateId":"tpl-ready","timeout":300,"env":{"FOO":"bar"}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_resourceLimits", `{"templateId":"tpl-ready","timeout":300,"resourceLimits":{"cpu":"1"}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_resourceRequests", `{"templateId":"tpl-ready","timeout":300,"resourceRequests":{"memory":"512Mi"}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_volumes", `{"templateId":"tpl-ready","timeout":300,"volumes":[]}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_platform", `{"templateId":"tpl-ready","timeout":300,"platform":{"os":"linux","arch":"amd64"}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_secureAccess_true", `{"templateId":"tpl-ready","timeout":300,"secureAccess":true}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_secureAccess_bad_type", `{"templateId":"tpl-ready","timeout":300,"secureAccess":"false"}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_lifecycle", `{"templateId":"tpl-ready","timeout":300,"lifecycle":{"idlePolicy":{}}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"override_poolRef", `{"templateId":"tpl-ready","timeout":300,"extensions":{"poolRef":"pool-a"}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"meta_opensandbox_reserved", `{"templateId":"tpl-ready","timeout":300,"metadata":{"opensandbox.io/owner":"x"}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"meta_bare_e2b_prefix", `{"templateId":"tpl-ready","timeout":300,"metadata":{"e2b-shim-":"x"}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"meta_uppercase_e2b_key", `{"templateId":"tpl-ready","timeout":300,"metadata":{"e2b-shim-BAD":"x"}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"meta_uppercase_key", `{"templateId":"tpl-ready","timeout":300,"metadata":{"BadKey":"x"}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"meta_oversize_e2b_key", fmt.Sprintf(`{"templateId":"tpl-ready","timeout":300,"metadata":{"e2b-shim-%s":"x"}}`, strings.Repeat("a", 56)), http.StatusBadRequest, "INVALID_REQUEST"},
		{"meta_invalid_value", `{"templateId":"tpl-ready","timeout":300,"metadata":{"team":"bad value"}}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"meta_null", `{"templateId":"tpl-ready","timeout":300,"metadata":null}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"duplicate_json_key", `{"templateId":"tpl-ready","templateId":"tpl-ready","timeout":300}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"trailing_json", `{"templateId":"tpl-ready","timeout":300}{}`, http.StatusBadRequest, "INVALID_REQUEST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, raw := rawJSONRequest(t, http.MethodPost, ts.URL+"/v1/sandboxes", testNativeSecret, tc.body)
			if resp.StatusCode != tc.wantStatus || resp.Header.Get("X-Request-ID") == "" ||
				resp.Header.Get("Content-Type") != "application/json" ||
				(tc.wantCode != "" && !strings.Contains(raw, `"code":"`+tc.wantCode+`"`)) {
				t.Fatalf("status=%d (want %d) hdr=%v body=%s", resp.StatusCode, tc.wantStatus, resp.Header, raw)
			}
		})
	}
	if st := fake.Stats(); st.TotalCreated != 2 || st.ActiveSandboxes != 2 {
		t.Fatalf("Stats = %+v, want 2 created/active", st)
	}
}

func TestFullLifecycleEndpointsMetadataAndRetainModes(t *testing.T) {
	clk := newManualClock(time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC))
	fake := fakenative.New(fakenative.Config{
		APIKey: testNativeSecret, MaxTimeoutSeconds: 7200, Clock: clk.Now,
		DefaultTemplates: []fakenative.TemplateSpec{{ID: "tpl-base", Ready: true, Entrypoint: []string{"/bin/envd"}}},
	})
	ts := httptest.NewServer(fake.Handler())
	defer ts.Close()
	cli := mustNativeClient(t, ts.URL+"/v1", testNativeSecret, nil)
	ctx := context.Background()

	meta := ok(rules.EncodeSandboxMetadata(rules.MetadataEncodeInput{
		AdapterID: "e2b-shim-dev", Revision: "tpl-base.rev-1", HMACKeyVersion: "v1",
		UserMetadata: map[string]string{"env": "dev", "obsolete": "yes"},
	})).must(t)
	created := ok(cli.CreateTemplateSandbox(ctx, native.CreateTemplateSandboxRequest{
		TemplateID: "tpl-base", TimeoutSeconds: 300, Metadata: meta,
	})).must(t)
	if created.ID != "sbx-1" || created.Status.State != native.StateRunning ||
		!created.CreatedAt.Equal(clk.Now()) || created.ExpiresAt == nil || !created.ExpiresAt.Equal(clk.Now().Add(300*time.Second)) ||
		!slices.Equal(created.Entrypoint, []string{"/bin/envd"}) {
		t.Fatalf("CreateTemplateSandbox: got=%+v", created)
	}
	if got := ok(cli.GetSandbox(ctx, created.ID)).must(t); got.Metadata["env"] != "dev" || got.Metadata[rules.MetaKeyManaged] != "true" {
		t.Fatalf("GetSandbox: got=%+v", got)
	}
	if ep := ok(cli.GetEndpoint(ctx, created.ID, 49983)).must(t); ep.URL != "http://127.0.0.1:49983" || ep.Headers["OpenSandbox-Ingress-To"] != "sbx-1:49983" {
		t.Fatalf("default GetEndpoint: ep=%v", ep)
	}
	fake.SetEndpoint(created.ID, 49983, native.Endpoint{URL: "http://127.0.0.1:59999", Headers: map[string]string{"OpenSandbox-Ingress-To": "custom-route"}})
	if ep := ok(cli.GetEndpoint(ctx, created.ID, 49983)).must(t); ep.URL != "http://127.0.0.1:59999" || ep.Headers["OpenSandbox-Ingress-To"] != "custom-route" {
		t.Fatalf("overridden GetEndpoint: ep=%v", ep)
	}
	for _, badPath := range []string{
		"/v1/sandboxes/sbx-1/endpoints/49983?expires=1700000000", "/v1/sandboxes/sbx-1/endpoints/49983?expires=",
		"/v1/sandboxes/sbx-1/endpoints/0", "/v1/sandboxes/sbx-1/endpoints/65536",
		"/v1/sandboxes/sbx-1/endpoints/080", "/v1/sandboxes/sbx-1/endpoints/notaport",
	} {
		if resp, _ := rawJSONRequest(t, http.MethodGet, ts.URL+badPath, testNativeSecret, ""); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET %s: status=%d, want 400", badPath, resp.StatusCode)
		}
	}
	_ = fake.SetState(created.ID, native.StatePaused, "paused", "test pause")
	if _, err := cli.GetEndpoint(ctx, created.ID, 49983); !native.IsConflict(err) {
		t.Fatalf("GetEndpoint while Paused: err=%v, want 409", err)
	}
	_ = fake.SetState(created.ID, native.StateRunning, "resumed", "back to running")

	for _, badPatch := range []string{`{"opensandbox.io/x":"1"}`, `{"env":123}`, `{"env":"ok","BAD":"v"}`} {
		if resp, _ := rawJSONRequest(t, http.MethodPatch, ts.URL+"/v1/sandboxes/sbx-1/metadata", testNativeSecret, badPatch); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("PATCH %s: status=%d, want 400", badPatch, resp.StatusCode)
		}
	}
	if snap, ok := fake.GetSandboxSnapshot(created.ID); !ok || snap.Metadata["env"] != "dev" {
		t.Fatalf("failed patch mutated metadata: %+v", snap)
	}
	patched := ok(cli.PatchMetadata(ctx, created.ID, native.MetadataPatch{
		"env": strPtr("prod"), "team": strPtr("infra"), "e2b-shim-deleting": strPtr("true"),
		"obsolete": nil, "nonexistent": nil,
	})).must(t)
	if _, hasObsolete := patched.Metadata["obsolete"]; hasObsolete || patched.Metadata["env"] != "prod" ||
		patched.Metadata["team"] != "infra" || patched.Metadata["e2b-shim-deleting"] != "true" {
		t.Fatalf("PatchMetadata: got=%+v", patched.Metadata)
	}

	if err := cli.DeleteSandbox(ctx, created.ID); err != nil {
		t.Fatalf("first DeleteSandbox: %v", err)
	}
	if err := cli.DeleteSandbox(ctx, created.ID); !native.IsNotFound(err) {
		t.Fatalf("second DeleteSandbox: err=%v, want 404", err)
	}
	if _, err := cli.PatchMetadata(ctx, created.ID, native.MetadataPatch{"env": strPtr("x")}); !native.IsNotFound(err) {
		t.Fatalf("PatchMetadata after delete: err=%v, want 404", err)
	}
	if termSbx := ok(cli.GetSandbox(ctx, created.ID)).must(t); termSbx.Status.State != native.StateTerminated || termSbx.Status.Reason != "user_delete" {
		t.Fatalf("GetSandbox after delete (RetainTerminated=true): got=%+v", termSbx)
	}

	fakeNoRetain := fakenative.New(fakenative.Config{
		APIKey: testNativeSecret, DefaultTemplates: []fakenative.TemplateSpec{{ID: "tpl-base", Ready: true}},
		RetainTerminated: boolPtr(false), Clock: clk.Now,
	})
	tsNoRetain := httptest.NewServer(fakeNoRetain.Handler())
	defer tsNoRetain.Close()
	cliNoRetain := mustNativeClient(t, tsNoRetain.URL+"/v1", testNativeSecret, nil)
	c1 := ok(cliNoRetain.CreateTemplateSandbox(ctx, native.CreateTemplateSandboxRequest{TemplateID: "tpl-base", TimeoutSeconds: 60})).must(t)
	c2 := ok(cliNoRetain.CreateTemplateSandbox(ctx, native.CreateTemplateSandboxRequest{TemplateID: "tpl-base", TimeoutSeconds: 60})).must(t)
	if err := cliNoRetain.DeleteSandbox(ctx, c1.ID); err != nil {
		t.Fatalf("DeleteSandbox no-retain: %v", err)
	}
	if _, err := cliNoRetain.GetSandbox(ctx, c1.ID); !native.IsNotFound(err) {
		t.Fatalf("GetSandbox after delete (RetainTerminated=false): err=%v, want 404", err)
	}
	clk.Advance(61 * time.Second)
	if _, err := cliNoRetain.GetSandbox(ctx, c2.ID); !native.IsNotFound(err) {
		t.Fatalf("GetSandbox after TTL expiry (RetainTerminated=false): err=%v, want 404", err)
	}
}

func TestTTLExpiryAndScheduledTransitions(t *testing.T) {
	clk := newManualClock(time.Date(2026, 11, 22, 15, 0, 0, 0, time.UTC))
	fake := fakenative.New(fakenative.Config{
		APIKey: testNativeSecret, Clock: clk.Now,
		DefaultTemplates: []fakenative.TemplateSpec{{ID: "tpl-pending", Ready: true, InitialState: native.StatePending}},
	})
	ts := httptest.NewServer(fake.Handler())
	defer ts.Close()
	cli := mustNativeClient(t, ts.URL+"/v1", testNativeSecret, nil)
	ctx := context.Background()

	sbx := ok(cli.CreateTemplateSandbox(ctx, native.CreateTemplateSandboxRequest{TemplateID: "tpl-pending", TimeoutSeconds: 60})).must(t)
	if sbx.Status.State != native.StatePending {
		t.Fatalf("Create pending: got=%+v", sbx)
	}
	_ = fake.ScheduleTransitions(sbx.ID, []fakenative.TransitionStep{
		{State: native.StatePending, Reason: "booting"}, {State: native.StateRunning, Reason: "ready"},
	})
	if _, err := cli.GetEndpoint(ctx, sbx.ID, 49983); !native.IsConflict(err) {
		t.Fatalf("GetEndpoint while Pending: err=%v, want 409", err)
	}
	if p1 := ok(cli.GetSandbox(ctx, sbx.ID)).must(t); p1.Status.State != native.StatePending || p1.Status.Reason != "booting" {
		t.Fatalf("poll 1: got=%+v", p1)
	}
	if p2 := ok(cli.GetSandbox(ctx, sbx.ID)).must(t); p2.Status.State != native.StateRunning || p2.Status.Reason != "ready" {
		t.Fatalf("poll 2: got=%+v", p2)
	}
	_ = ok(cli.GetEndpoint(ctx, sbx.ID, 49983)).must(t)

	clk.Advance(59 * time.Second)
	if s59 := ok(cli.GetSandbox(ctx, sbx.ID)).must(t); s59.Status.State != native.StateRunning {
		t.Fatalf("at +59s: got=%+v", s59)
	}
	clk.Advance(1 * time.Second)
	if exp := ok(cli.GetSandbox(ctx, sbx.ID)).must(t); exp.Status.State != native.StateTerminated || exp.Status.Reason != "ttl_expiry" || fake.Stats().ActiveSandboxes != 0 {
		t.Fatalf("at +60s: got=%+v stats=%+v", exp, fake.Stats())
	}

	sbxTimed := ok(cli.CreateTemplateSandbox(ctx, native.CreateTemplateSandboxRequest{TemplateID: "tpl-pending", TimeoutSeconds: 120})).must(t)
	_ = fake.ScheduleTransitions(sbxTimed.ID, []fakenative.TransitionStep{{State: native.StateRunning, Reason: "vm_booted", After: 5 * time.Second}})
	clk.Advance(4 * time.Second)
	if s4 := ok(cli.GetSandbox(ctx, sbxTimed.ID)).must(t); s4.Status.State != native.StatePending {
		t.Fatalf("at +4s: got=%+v", s4)
	}
	clk.Advance(1 * time.Second)
	if s5 := ok(cli.GetSandbox(ctx, sbxTimed.ID)).must(t); s5.Status.State != native.StateRunning {
		t.Fatalf("at +5s: got=%+v", s5)
	}
}

func TestStandaloneControlSecurityAndFaultInjectionZeroReplay(t *testing.T) {
	for _, badCtrl := range []string{"0.0.0.0:0", ":0", "[::]:0", "192.0.2.1:0", "invalid-addr"} {
		if inst, err := fakenative.StartStandalone("127.0.0.1:0", badCtrl); err == nil || !errors.Is(err, fakenative.ErrNonLoopbackControl) {
			if inst != nil {
				_ = inst.Close(context.Background())
			}
			t.Fatalf("StartStandalone(%q) err=%v, want ErrNonLoopbackControl", badCtrl, err)
		}
	}
	ctrlSrv := fakenative.New(fakenative.Config{})
	for _, remoteAddr := range []string{"192.0.2.1:1234", "10.1.2.3:9000", "8.8.8.8:443", "malformed"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/control/stats", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("X-Real-IP", "127.0.0.1")
		ctrlSrv.ControlHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("RemoteAddr=%q: got %d, want 403", remoteAddr, rec.Code)
		}
	}
	if err := ok(fakenative.StartStandalone("127.0.0.1:0", "localhost:0")).must(t).Close(context.Background()); err != nil {
		t.Fatalf("Close localhost:0: %v", err)
	}

	inst := ok(fakenative.New(fakenative.Config{APIKey: testNativeSecret}).StartStandalone("127.0.0.1:0", "127.0.0.1:0")).must(t)
	defer func() { _ = inst.Close(context.Background()) }()
	ctrlBase, apiBase := "http://"+inst.ControlAddr(), "http://"+inst.APIAddr()+"/v1"
	mustCtrl := func(method, path, body string, wantStatus int) string {
		t.Helper()
		resp, raw := rawJSONRequest(t, method, ctrlBase+path, "", body)
		if resp.StatusCode != wantStatus {
			t.Fatalf("control %s %s: status=%d want=%d body=%s", method, path, resp.StatusCode, wantStatus, raw)
		}
		return raw
	}
	readStats := func() (st fakenative.Stats) {
		t.Helper()
		_ = json.Unmarshal([]byte(mustCtrl(http.MethodGet, "/control/stats", "", http.StatusOK)), &st)
		return st
	}

	mustCtrl(http.MethodPost, "/control/templates", `{"id":"tpl-e2e","ready":true,"entrypoint":["/bin/envd"]}`, http.StatusOK)
	cli := mustNativeClient(t, apiBase, testNativeSecret, func(cc *native.ClientConfig) {
		cc.ReadMaxAttempts, cc.ReadRetryBackoff, cc.RequestTimeout = 3, 5*time.Millisecond, 80*time.Millisecond
	})
	ctx := context.Background()

	mustCtrl(http.MethodPost, "/control/faults", `{"operation":"create","remaining":1,"dropBeforeExecute":true}`, http.StatusCreated)
	if _, err := cli.CreateTemplateSandbox(ctx, native.CreateTemplateSandboxRequest{TemplateID: "tpl-e2e", TimeoutSeconds: 120}); !native.IsAmbiguous(err) || native.IsDefiniteFailure(err) {
		t.Fatalf("DropBeforeExecute Create: err=%v, want OutcomeAmbiguous", err)
	}
	if st := readStats(); st.Create != 0 || st.TotalCreated != 0 {
		t.Fatalf("Stats after DropBeforeExecute Create = %+v, want 0", st)
	}

	mustCtrl(http.MethodPost, "/control/faults", `{"operation":"create","remaining":1,"dropAfterExecute":true}`, http.StatusCreated)
	if _, err := cli.CreateTemplateSandbox(ctx, native.CreateTemplateSandboxRequest{
		TemplateID: "tpl-e2e", TimeoutSeconds: 120, Metadata: map[string]string{"phase": "init"},
	}); !native.IsAmbiguous(err) || native.IsDefiniteFailure(err) {
		t.Fatalf("DropAfterExecute Create: err=%v, want OutcomeAmbiguous", err)
	}
	if st := readStats(); st.Create != 1 || st.TotalCreated != 1 || st.ActiveSandboxes != 1 {
		t.Fatalf("Stats after DropAfterExecute Create = %+v, want strictly 1 execution", st)
	}
	if sbx1 := ok(cli.GetSandbox(ctx, "sbx-1")).must(t); sbx1.Metadata["phase"] != "init" {
		t.Fatalf("GetSandbox(sbx-1) after DropAfterExecute Create: got=%+v", sbx1)
	}

	beforeGet := readStats().Get
	mustCtrl(http.MethodPost, "/control/faults", `{"operation":"get","sandboxId":"sbx-1","remaining":1,"statusCode":503}`, http.StatusCreated)
	if got := ok(cli.GetSandbox(ctx, "sbx-1")).must(t); got.ID != "sbx-1" || readStats().Get-beforeGet != 2 {
		t.Fatalf("GetSandbox 503 recovery: got=%+v", got)
	}

	mustCtrl(http.MethodPost, "/control/endpoints", `{"sandboxId":"sbx-1","port":49983,"endpoint":"http://127.0.0.1:49999","headers":{"OpenSandbox-Ingress-To":"tok-1"}}`, http.StatusOK)
	mustCtrl(http.MethodPost, "/control/faults", `{"operation":"endpoint","sandboxId":"sbx-1","remaining":1,"dropBeforeExecute":true}`, http.StatusCreated)
	if ep := ok(cli.GetEndpoint(ctx, "sbx-1", 49983)).must(t); ep.URL != "http://127.0.0.1:49999" || ep.Headers["OpenSandbox-Ingress-To"] != "tok-1" {
		t.Fatalf("GetEndpoint recovery: ep=%v", ep)
	}

	beforePatch := readStats().PatchMetadata
	mustCtrl(http.MethodPost, "/control/faults", `{"operation":"patch_metadata","sandboxId":"sbx-1","remaining":1,"dropAfterExecute":true}`, http.StatusCreated)
	if _, err := cli.PatchMetadata(ctx, "sbx-1", native.MetadataPatch{"phase": strPtr("patched")}); !native.IsAmbiguous(err) || readStats().PatchMetadata-beforePatch != 1 {
		t.Fatalf("DropAfterExecute PatchMetadata: err=%v", err)
	}
	if sbxAfterPatch := ok(cli.GetSandbox(ctx, "sbx-1")).must(t); sbxAfterPatch.Metadata["phase"] != "patched" {
		t.Fatalf("PatchMetadata state check: got=%+v", sbxAfterPatch)
	}

	mustCtrl(http.MethodPost, "/control/sandboxes/sbx-missing/state", `{"state":"Running"}`, http.StatusNotFound)
	mustCtrl(http.MethodPost, "/control/sandboxes/sbx-1/state", `{"state":"Stopping","reason":"draining"}`, http.StatusOK)
	if _, err := cli.GetEndpoint(ctx, "sbx-1", 49983); !native.IsConflict(err) {
		t.Fatalf("GetEndpoint while Stopping: err=%v, want 409", err)
	}
	mustCtrl(http.MethodPost, "/control/sandboxes/sbx-1/state", `{"state":"Running","reason":"ready"}`, http.StatusOK)

	mustCtrl(http.MethodPost, "/control/faults", `{"operation":"get","sandboxId":"sbx-1","delayMs":400}`, http.StatusCreated)
	shortCtx, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
	_, err := cli.GetSandbox(shortCtx, "sbx-1")
	cancel()
	if !native.IsAmbiguous(err) {
		t.Fatalf("DelayMs context timeout: err=%v, want OutcomeAmbiguous", err)
	}
	mustCtrl(http.MethodDelete, "/control/faults", "", http.StatusNoContent)

	mustCtrl(http.MethodPost, "/control/faults", `{"operation":"get","sandboxId":"sbx-1","remaining":1,"malformedBody":true}`, http.StatusCreated)
	if _, err := cli.GetSandbox(ctx, "sbx-1"); !native.IsAmbiguous(err) {
		t.Fatalf("MalformedBody GetSandbox: err=%v, want OutcomeAmbiguous", err)
	}

	beforeDel := readStats().Delete
	mustCtrl(http.MethodPost, "/control/faults", `{"operation":"delete","sandboxId":"sbx-1","remaining":1,"dropAfterExecute":true}`, http.StatusCreated)
	if err := cli.DeleteSandbox(ctx, "sbx-1"); !native.IsAmbiguous(err) || native.IsDefiniteFailure(err) {
		t.Fatalf("DropAfterExecute DeleteSandbox: err=%v, want OutcomeAmbiguous", err)
	}
	if st := readStats(); st.Delete-beforeDel != 1 || st.ActiveSandboxes != 0 {
		t.Fatalf("Stats after DropAfterExecute Delete = %+v, want strictly 1 execution and 0 active", st)
	}
	if err := cli.DeleteSandbox(ctx, "sbx-1"); !native.IsNotFound(err) {
		t.Fatalf("follow-up DeleteSandbox: err=%v, want 404", err)
	}
}

func TestConcurrentOperationsRaceSafety(t *testing.T) {
	fake := fakenative.New(fakenative.Config{
		APIKey: testNativeSecret, DefaultTemplates: []fakenative.TemplateSpec{{ID: "tpl-race", Ready: true}},
	})
	ts := httptest.NewServer(fake.Handler())
	defer ts.Close()
	cli := mustNativeClient(t, ts.URL+"/v1", testNativeSecret, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			res, err := cli.CreateTemplateSandbox(ctx, native.CreateTemplateSandboxRequest{
				TemplateID: "tpl-race", TimeoutSeconds: 120, Metadata: map[string]string{"worker": fmt.Sprintf("w-%d", w)},
			})
			if err != nil {
				t.Errorf("worker %d create: %v", w, err)
				return
			}
			_, _ = cli.GetSandbox(ctx, res.ID)
			_, _ = cli.GetEndpoint(ctx, res.ID, 49983)
			_, _ = cli.PatchMetadata(ctx, res.ID, native.MetadataPatch{"step": strPtr("done")})
			_, _ = fake.GetSandboxSnapshot(res.ID)
			_ = fake.Stats()
			_ = cli.DeleteSandbox(ctx, res.ID)
		}(worker)
	}
	wg.Wait()
	if st := fake.Stats(); st.TotalCreated != 8 || st.ActiveSandboxes != 0 {
		t.Fatalf("final Stats = %+v, want TotalCreated=8 ActiveSandboxes=0", st)
	}
}
