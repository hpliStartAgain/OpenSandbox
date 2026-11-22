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

package native_test

import (
	"bytes"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
)

const (
	fakeNativeAPIKey   = "fake-native-api-key-SECRET-DO-NOT-LEAK"
	fakeIngressSecret  = "fake-ingress-route-token-SECRET-DO-NOT-LEAK"
	fakeSecondaryToken = "fake-signed-header-token-SECRET-DO-NOT-LEAK"
)

func testAPIKey(t *testing.T, val string) config.Secret {
	t.Helper()
	if val == "" {
		return config.Secret{}
	}
	env := map[string]string{
		"E2B_SHIM_NATIVE_API_URL": "https://native.example.internal/v1", "E2B_SHIM_ADAPTER_ID": "e2b-shim-test",
		"E2B_SHIM_HMAC_KEY_VERSION": "v1", "E2B_SHIM_TIMEOUT_MAX_SECONDS": "3600",
		"E2B_SHIM_ADAPTER_API_KEY": "fake-adapter-key-DO-NOT-USE", "E2B_SHIM_NATIVE_API_KEY": val,
		"E2B_SHIM_HMAC_KEY": "fake-hmac-key-DO-NOT-USE",
	}
	cfg, err := config.Load(config.Source{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }})
	if err != nil {
		t.Fatalf("load test secret: %v", err)
	}
	return cfg.NativeAPIKey
}

func mustNewClient(t *testing.T, baseURL string, modify func(*native.ClientConfig)) *native.Client {
	t.Helper()
	cfg := native.ClientConfig{BaseURL: baseURL, APIKey: testAPIKey(t, fakeNativeAPIKey)}
	if modify != nil {
		modify(&cfg)
	}
	c, err := native.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient(%q): %v", baseURL, err)
	}
	return c
}

func hijackAndDrop(t *testing.T, w http.ResponseWriter, rawHead string) {
	t.Helper()
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Fatalf("Hijack: %v", err)
	}
	if rawHead != "" {
		_, _ = rw.WriteString(rawHead)
		_ = rw.Flush()
	}
	_ = conn.Close()
}

func strPtr(s string) *string { return &s }

func TestHappyPathsAllOperations(t *testing.T) {
	createdAt := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	expiresAt := createdAt.Add(5 * time.Minute)
	transAt := createdAt.Add(2 * time.Second)
	encodedMeta, err := rules.EncodeSandboxMetadata(rules.MetadataEncodeInput{
		AdapterID: "e2b-shim-dev", Revision: "tpl-base.rev-1", HMACKeyVersion: "v1",
		UserMetadata: map[string]string{"team": "infra"},
	})
	if err != nil {
		t.Fatalf("EncodeSandboxMetadata: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("OPEN-SANDBOX-API-KEY") != fakeNativeAPIKey || r.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected headers: key=%q accept=%q", r.Header.Get("OPEN-SANDBOX-API-KEY"), r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "req-happy-1")

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes":
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			if r.Header.Get("Content-Type") != "application/json" ||
				!slices.Equal(slices.Sorted(maps.Keys(body)), []string{"metadata", "templateId", "timeout"}) ||
				body["templateId"] != "tpl_123" || body["timeout"] != float64(300) {
				t.Errorf("unexpected create request: ct=%q body=%v", r.Header.Get("Content-Type"), body)
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sbx-101",
				"status": map[string]any{
					"state": "Running", "reason": "ready", "message": "provisioned",
					"lastTransitionAt": transAt.Format(time.RFC3339),
				},
				"metadata": encodedMeta, "extensions": map[string]string{"ext.key": "v1"},
				"expiresAt": expiresAt.Format(time.RFC3339), "createdAt": createdAt.Format(time.RFC3339),
				"entrypoint": []string{"/bin/envd"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sbx-101":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sbx-101", "image": map[string]any{"uri": "envd:0.8.0"},
				"status": map[string]any{"state": "Running", "reason": "ok"}, "metadata": encodedMeta,
				"expiresAt": expiresAt.Format(time.RFC3339), "createdAt": createdAt.Format(time.RFC3339),
				"entrypoint": []string{"/bin/envd"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sbx-101/endpoints/49983":
			if r.URL.RawQuery != "" {
				t.Errorf("GetEndpoint sent forbidden query string: %q", r.URL.RawQuery)
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"endpoint": "https://ingress.example.internal/sandboxes/sbx-101/port/49983",
				"headers":  map[string]string{"OpenSandbox-Ingress-To": fakeIngressSecret, "X-Route-Signature": fakeSecondaryToken},
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/sandboxes/sbx-101/metadata":
			raw, _ := io.ReadAll(r.Body)
			var rawPatch map[string]json.RawMessage
			_ = json.Unmarshal(raw, &rawPatch)
			if string(rawPatch["team"]) != `"platform"` || string(rawPatch["obsolete"]) != "null" ||
				string(rawPatch["e2b-shim-deleting"]) != `"true"` {
				t.Errorf("unexpected RFC 7396 patch payload: %s", string(raw))
			}
			patchedMeta := maps.Clone(encodedMeta)
			patchedMeta["team"], patchedMeta["e2b-shim-deleting"] = "platform", "true"
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sbx-101", "status": map[string]any{"state": "Running"},
				"metadata": patchedMeta, "createdAt": createdAt.Format(time.RFC3339), "entrypoint": []string{"/bin/envd"},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sbx-101":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	client := mustNewClient(t, srv.URL+"/v1///", nil)
	ctx := context.Background()

	created, err := client.CreateTemplateSandbox(ctx, native.CreateTemplateSandboxRequest{
		TemplateID: "tpl_123", TimeoutSeconds: 300, Metadata: encodedMeta,
	})
	if err != nil || native.ClassifyError(err) != native.OutcomeSuccess || created.ID != "sbx-101" ||
		created.Status.State != native.StateRunning || created.Status.RawState != "Running" ||
		created.Status.LastTransitionAt == nil || !created.Status.LastTransitionAt.Equal(transAt) ||
		created.ExpiresAt == nil || !created.ExpiresAt.Equal(expiresAt) || !created.CreatedAt.Equal(createdAt) ||
		!slices.Equal(created.Entrypoint, []string{"/bin/envd"}) || created.Metadata["team"] != "infra" {
		t.Fatalf("CreateTemplateSandbox: got=%+v err=%v", created, err)
	}
	if got, err := client.GetSandbox(ctx, "sbx-101"); err != nil || got.ID != "sbx-101" || got.Metadata[rules.MetaKeyManaged] != "true" {
		t.Fatalf("GetSandbox: got=%+v err=%v", got, err)
	}
	if ep, err := client.GetEndpoint(ctx, "sbx-101", 49983); err != nil ||
		ep.URL != "https://ingress.example.internal/sandboxes/sbx-101/port/49983" ||
		ep.Headers["OpenSandbox-Ingress-To"] != fakeIngressSecret || ep.Headers["X-Route-Signature"] != fakeSecondaryToken {
		t.Fatalf("GetEndpoint: err=%v", err)
	}
	patched, err := client.PatchMetadata(ctx, "sbx-101", native.MetadataPatch{
		"team": strPtr("platform"), "obsolete": nil, "e2b-shim-deleting": strPtr("true"),
	})
	if err != nil || patched.Metadata["team"] != "platform" || patched.Metadata["e2b-shim-deleting"] != "true" {
		t.Fatalf("PatchMetadata: got=%+v err=%v", patched, err)
	}
	if err := client.DeleteSandbox(ctx, "sbx-101"); err != nil {
		t.Fatalf("DeleteSandbox: %v", err)
	}
}

func TestNativeStatesPreservedVerbatimAndUnknown(t *testing.T) {
	var currentRaw atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "sbx-state", "status": map[string]any{"state": currentRaw.Load().(string)},
			"createdAt": "2026-11-21T10:00:00Z", "entrypoint": []string{"/bin/envd"},
		})
	}))
	defer srv.Close()

	client := mustNewClient(t, srv.URL+"/v1", nil)
	for _, tc := range []struct {
		raw  string
		want native.State
	}{
		{"Pending", native.StatePending}, {"Running", native.StateRunning},
		{"Pausing", native.StatePausing}, {"Paused", native.StatePaused},
		{"Resuming", native.StateResuming}, {"Stopping", native.StateStopping},
		{"Terminated", native.StateTerminated}, {"Failed", native.StateFailed},
		{"Migrating", native.StateUnknown}, {"running", native.StateUnknown}, {"Unknown", native.StateUnknown},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			if got := native.ParseState(tc.raw); got != tc.want {
				t.Fatalf("ParseState(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			currentRaw.Store(tc.raw)
			sbx, err := client.GetSandbox(context.Background(), "sbx-state")
			if err != nil || sbx.Status.State != tc.want || sbx.Status.RawState != tc.raw {
				t.Fatalf("got=%+v err=%v, want State=%q RawState=%q", sbx, err, tc.want, tc.raw)
			}
		})
	}
}

func TestMutationsLostResponseAfterExecutionZeroReplay(t *testing.T) {
	req := native.CreateTemplateSandboxRequest{TemplateID: "tpl_1", TimeoutSeconds: 60}
	for _, tc := range []struct {
		name, rawHead string
		call          func(*native.Client) error
	}{
		{"CreateTemplateSandbox_hijack_drop", "", func(c *native.Client) error { _, err := c.CreateTemplateSandbox(context.Background(), req); return err }},
		{"CreateTemplateSandbox_mid_body_drop", "HTTP/1.1 202 Accepted\r\nContent-Length: 120\r\n\r\n{\"id\":\"sbx-1\"", func(c *native.Client) error { _, err := c.CreateTemplateSandbox(context.Background(), req); return err }},
		{"DeleteSandbox_hijack_drop", "", func(c *native.Client) error { return c.DeleteSandbox(context.Background(), "sbx-del-1") }},
		{"PatchMetadata_hijack_drop", "", func(c *native.Client) error {
			_, err := c.PatchMetadata(context.Background(), "sbx-patch-1", native.MetadataPatch{"env": strPtr("prod")})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mutationHits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"id":"sbx-warm","status":{"state":"Running"}}`))
					return
				}
				mutationHits.Add(1)
				hijackAndDrop(t, w, tc.rawHead)
			}))
			defer srv.Close()

			client := mustNewClient(t, srv.URL+"/v1", func(cfg *native.ClientConfig) { cfg.ReadMaxAttempts = 3 })
			if _, err := client.GetSandbox(context.Background(), "sbx-warm"); err != nil {
				t.Fatalf("warm-up GetSandbox: %v", err)
			}
			if err := tc.call(client); !native.IsAmbiguous(err) || native.IsDefiniteFailure(err) {
				t.Fatalf("err = %v, want OutcomeAmbiguous", err)
			}
			if got := mutationHits.Load(); got != 1 {
				t.Fatalf("mutation server executions = %d, want strictly 1 (zero replay)", got)
			}
		})
	}
}

func TestOutcomeClassificationMatrix(t *testing.T) {
	type mockSpec struct {
		status int
		body   string
		delay  time.Duration
	}
	var spec atomic.Value
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		s := spec.Load().(mockSpec)
		if s.delay > 0 {
			select {
			case <-r.Context().Done():
			case <-time.After(s.delay):
			}
		}
		w.Header().Set("X-Request-ID", "req-matrix-42")
		w.WriteHeader(s.status)
		_, _ = io.WriteString(w, s.body)
	}))
	defer srv.Close()

	client := mustNewClient(t, srv.URL+"/v1", func(cfg *native.ClientConfig) { cfg.RequestTimeout = 35 * time.Millisecond })
	createReq := native.CreateTemplateSandboxRequest{TemplateID: "tpl_1", TimeoutSeconds: 60}

	for _, tc := range []struct {
		status                     int
		code                       string
		wantNotFound, wantConflict bool
	}{
		{http.StatusBadRequest, "INVALID_REQUEST", false, false}, {http.StatusUnauthorized, "UNAUTHORIZED", false, false},
		{http.StatusForbidden, "KUBERNETES::QUOTA_EXCEEDED", false, false}, {http.StatusNotFound, "NOT_FOUND", true, false},
		{http.StatusConflict, "CONFLICT", false, true}, {http.StatusTooManyRequests, "RATE_LIMITED", false, false},
	} {
		t.Run(fmt.Sprintf("definite_%d", tc.status), func(t *testing.T) {
			hits.Store(0)
			spec.Store(mockSpec{status: tc.status, body: `{"code":"` + tc.code + `","message":"rejected"}`})
			_, err := client.CreateTemplateSandbox(context.Background(), createReq)
			if !native.IsDefiniteFailure(err) || native.IsAmbiguous(err) ||
				native.IsNotFound(err) != tc.wantNotFound || native.IsConflict(err) != tc.wantConflict {
				t.Fatalf("status %d: err=%v", tc.status, err)
			}
			var ce *native.CallError
			if !errors.As(err, &ce) || ce.HTTPStatus != tc.status || ce.NativeCode != tc.code ||
				ce.RequestID != "req-matrix-42" || hits.Load() != 1 {
				t.Fatalf("ce=%+v hits=%d", ce, hits.Load())
			}
		})
	}

	for _, tc := range []struct {
		name string
		s    mockSpec
	}{
		{"ambiguous_408", mockSpec{status: http.StatusRequestTimeout, body: `{"code":"TIMEOUT","message":"slow"}`}},
		{"ambiguous_500", mockSpec{status: http.StatusInternalServerError, body: `{"code":"INTERNAL","message":"boom"}`}},
		{"ambiguous_502", mockSpec{status: http.StatusBadGateway}},
		{"ambiguous_503", mockSpec{status: http.StatusServiceUnavailable}},
		{"ambiguous_504", mockSpec{status: http.StatusGatewayTimeout}},
		{"unexpected_200_on_create", mockSpec{status: http.StatusOK, body: `{"id":"sbx-1","status":{"state":"Running"}}`}},
		{"truncated_json", mockSpec{status: http.StatusAccepted, body: `{"id":"sbx-1"`}},
		{"json_null", mockSpec{status: http.StatusAccepted, body: `null`}},
		{"missing_id", mockSpec{status: http.StatusAccepted, body: `{"status":{"state":"Running"}}`}},
		{"missing_state", mockSpec{status: http.StatusAccepted, body: `{"id":"sbx-1","status":{}}`}},
		{"oversized_body", mockSpec{status: http.StatusAccepted, body: `{"id":"sbx-1","status":{"state":"Running"},"p":"` + strings.Repeat("x", (1<<20)+64) + `"}`}},
		{"client_timeout", mockSpec{status: http.StatusAccepted, delay: 200 * time.Millisecond}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			spec.Store(tc.s)
			_, err := client.CreateTemplateSandbox(context.Background(), createReq)
			if !native.IsAmbiguous(err) || native.IsDefiniteFailure(err) || hits.Load() != 1 {
				t.Fatalf("err=%v hits=%d, want OutcomeAmbiguous + 1 hit", err, hits.Load())
			}
		})
	}

	if native.ClassifyError(errors.New("unrecognized")) != native.OutcomeAmbiguous ||
		native.ClassifyError(fmt.Errorf("wrap: %w", native.ErrInvalidArgument)) != native.OutcomeDefiniteFailure {
		t.Fatal("ClassifyError fallback mismatch")
	}
}

func TestReadOnlyBoundedRetry(t *testing.T) {
	for _, st := range []int{http.StatusRequestTimeout, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(fmt.Sprintf("GetSandbox_recovers_%d", st), func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if hits.Add(1) == 1 {
					w.WriteHeader(st)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"id":"sbx-r1","status":{"state":"Running"},"createdAt":"2026-11-21T10:00:00Z","entrypoint":["/bin/envd"]}`))
			}))
			defer srv.Close()

			client := mustNewClient(t, srv.URL+"/v1", func(cfg *native.ClientConfig) {
				cfg.ReadMaxAttempts, cfg.ReadRetryBackoff = 2, 5*time.Millisecond
			})
			if sbx, err := client.GetSandbox(context.Background(), "sbx-r1"); err != nil || sbx.ID != "sbx-r1" || hits.Load() != 2 {
				t.Fatalf("sbx=%v err=%v hits=%d", sbx, err, hits.Load())
			}
		})
	}

	t.Run("GetEndpoint dropped connection exhausts and recovers", func(t *testing.T) {
		var failCount, hits atomic.Int32
		failCount.Store(5)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if hits.Add(1) <= failCount.Load() {
				hijackAndDrop(t, w, "")
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"endpoint":"http://127.0.0.1:49983","headers":{"OpenSandbox-Ingress-To":"tok"}}`))
		}))
		defer srv.Close()

		client := mustNewClient(t, srv.URL+"/v1", func(cfg *native.ClientConfig) { cfg.ReadMaxAttempts = 2 })
		if _, err := client.GetEndpoint(context.Background(), "sbx-ep", 49983); !native.IsAmbiguous(err) || hits.Load() != 2 {
			t.Fatalf("exhaust: err=%v hits=%d, want OutcomeAmbiguous + 2 attempts", err, hits.Load())
		}
		hits.Store(0)
		failCount.Store(1)
		if ep, err := client.GetEndpoint(context.Background(), "sbx-ep", 49983); err != nil || ep.URL != "http://127.0.0.1:49983" || hits.Load() != 2 {
			t.Fatalf("recover: ep=%v err=%v hits=%d", ep, err, hits.Load())
		}
	})

	t.Run("Read 404, 500, and malformed 200 never retry", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			switch r.URL.Path {
			case "/v1/sandboxes/sbx-404", "/v1/sandboxes/sbx-404/endpoints/49983":
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"code":"NOT_FOUND","message":"missing"}`))
			case "/v1/sandboxes/sbx-500":
				w.WriteHeader(http.StatusInternalServerError)
			case "/v1/sandboxes/sbx-bad-state":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"id":"sbx-bad-state","status":{}}`))
			default:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"endpoint":""}`))
			}
		}))
		defer srv.Close()

		client := mustNewClient(t, srv.URL+"/v1", func(cfg *native.ClientConfig) { cfg.ReadMaxAttempts = 3 })
		if _, err := client.GetSandbox(context.Background(), "sbx-404"); !native.IsNotFound(err) || hits.Load() != 1 {
			t.Fatalf("GetSandbox 404: err=%v hits=%d", err, hits.Load())
		}
		if _, err := client.GetEndpoint(context.Background(), "sbx-404", 49983); !native.IsNotFound(err) || hits.Load() != 2 {
			t.Fatalf("GetEndpoint 404: err=%v hits=%d", err, hits.Load())
		}
		if _, err := client.GetSandbox(context.Background(), "sbx-500"); !native.IsAmbiguous(err) || hits.Load() != 3 {
			t.Fatalf("GetSandbox 500: err=%v hits=%d", err, hits.Load())
		}
		if _, err := client.GetSandbox(context.Background(), "sbx-bad-state"); !native.IsAmbiguous(err) || hits.Load() != 4 {
			t.Fatalf("GetSandbox missing state: err=%v hits=%d", err, hits.Load())
		}
		if _, err := client.GetEndpoint(context.Background(), "sbx-bad", 8080); !native.IsAmbiguous(err) || hits.Load() != 5 {
			t.Fatalf("GetEndpoint malformed: err=%v hits=%d", err, hits.Load())
		}
		//nolint:staticcheck // intentionally verify nil context returns OutcomeAmbiguous without panic
		if _, err := client.GetSandbox(nil, "sbx-404"); !native.IsAmbiguous(err) || hits.Load() != 5 {
			t.Fatalf("GetSandbox nil ctx: err=%v hits=%d", err, hits.Load())
		}
	})

	t.Run("Canceled context aborts retry", func(t *testing.T) {
		var hits atomic.Int32
		ctx, cancel := context.WithCancel(context.Background())
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			go func() { time.Sleep(10 * time.Millisecond); cancel() }()
		}))
		defer srv.Close()

		client := mustNewClient(t, srv.URL+"/v1", func(cfg *native.ClientConfig) {
			cfg.ReadMaxAttempts, cfg.ReadRetryBackoff = 3, 500*time.Millisecond
		})
		if _, err := client.GetSandbox(ctx, "sbx-cancel"); !native.IsAmbiguous(err) || !errors.Is(err, context.Canceled) || hits.Load() != 1 {
			t.Fatalf("err=%v hits=%d", err, hits.Load())
		}
	})
}

func TestRedirectRefusalNeverForwardsAPIKey(t *testing.T) {
	var targetHits, primaryHits atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if r.Header.Get("OPEN-SANDBOX-API-KEY") != "" {
			t.Error("OPEN-SANDBOX-API-KEY leaked to redirect target")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits.Add(1)
		http.Redirect(w, r, redirectTarget.URL+"/hijack", http.StatusFound)
	}))
	defer primary.Close()

	callerFollowed := false
	callerHTTP := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { callerFollowed = true; return nil }}
	client := mustNewClient(t, primary.URL+"/v1", func(cfg *native.ClientConfig) {
		cfg.HTTPClient, cfg.ReadMaxAttempts = callerHTTP, 3
	})

	ctx := context.Background()
	_, errCreate := client.CreateTemplateSandbox(ctx, native.CreateTemplateSandboxRequest{TemplateID: "tpl_1", TimeoutSeconds: 60})
	_, errGet := client.GetSandbox(ctx, "sbx-1")
	_, errEp := client.GetEndpoint(ctx, "sbx-1", 49983)
	_, errPatch := client.PatchMetadata(ctx, "sbx-1", native.MetadataPatch{"k": strPtr("v")})
	for name, err := range map[string]error{
		"create": errCreate, "get": errGet, "delete": client.DeleteSandbox(ctx, "sbx-1"), "endpoint": errEp, "patch": errPatch,
	} {
		if !native.IsAmbiguous(err) {
			t.Errorf("%s: err=%v, want OutcomeAmbiguous on 302", name, err)
		}
	}
	if targetHits.Load() != 0 || primaryHits.Load() != 5 || callerFollowed || callerHTTP.CheckRedirect == nil {
		t.Fatalf("targetHits=%d primaryHits=%d callerFollowed=%v", targetHits.Load(), primaryHits.Load(), callerFollowed)
	}
}

func TestInvalidArgumentsSendZeroRequestsAndUnimplementedMethods(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()

	validKey := testAPIKey(t, fakeNativeAPIKey)
	for _, badURL := range []string{
		"", "ftp://example.internal/v1", "https://user:" + fakeNativeAPIKey + "@example.internal/v1",
		"https://example.internal/v1?x=1", "https://example.internal/v1#frag", "https://example.internal:0/v1",
		"https://example.internal/v1/../v2", "https://example.internal/v1\\bad", "https://", "://bad-" + fakeNativeAPIKey,
	} {
		if _, err := native.NewClient(native.ClientConfig{BaseURL: badURL, APIKey: validKey}); !errors.Is(err, native.ErrInvalidArgument) || strings.Contains(err.Error(), fakeNativeAPIKey) {
			t.Fatalf("NewClient(%q): err=%v", badURL, err)
		}
	}
	if _, err := native.NewClient(native.ClientConfig{BaseURL: srv.URL, APIKey: config.Secret{}}); !errors.Is(err, native.ErrInvalidArgument) {
		t.Errorf("zero APIKey err=%v", err)
	}
	if _, err := native.NewClient(native.ClientConfig{BaseURL: srv.URL, APIKey: validKey, ReadMaxAttempts: 6}); !errors.Is(err, native.ErrInvalidArgument) {
		t.Errorf("ReadMaxAttempts=6 err=%v", err)
	}

	client := mustNewClient(t, srv.URL+"/v1", nil)
	ctx := context.Background()
	assertErr := func(label string, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s: err=%v, want %v", label, err, want)
		}
	}
	for _, badID := range []string{"", ".", "..", "../etc", "a/b", `a\b`, "a?b", "a#b", "sbx 1", "sbx\n1", "sbx\x001", "\xff"} {
		_, errGet := client.GetSandbox(ctx, badID)
		_, errEp := client.GetEndpoint(ctx, badID, 8080)
		_, errPatch := client.PatchMetadata(ctx, badID, native.MetadataPatch{})
		if !errors.Is(errGet, native.ErrInvalidArgument) || !native.IsDefiniteFailure(errGet) {
			t.Errorf("GetSandbox(%q): err=%v", badID, errGet)
		}
		assertErr("Delete("+badID+")", client.DeleteSandbox(ctx, badID), native.ErrInvalidArgument)
		assertErr("Endpoint("+badID+")", errEp, native.ErrInvalidArgument)
		assertErr("Patch("+badID+")", errPatch, native.ErrInvalidArgument)
	}
	for _, badPort := range []int{-1, 0, 65536} {
		_, err := client.GetEndpoint(ctx, "sbx-1", badPort)
		assertErr(fmt.Sprintf("port %d", badPort), err, native.ErrInvalidArgument)
	}
	for _, req := range []native.CreateTemplateSandboxRequest{
		{TemplateID: "", TimeoutSeconds: 60}, {TemplateID: "tpl 1", TimeoutSeconds: 60}, {TemplateID: "tpl_1", TimeoutSeconds: 59},
	} {
		_, err := client.CreateTemplateSandbox(ctx, req)
		assertErr("badCreate("+req.TemplateID+")", err, native.ErrInvalidArgument)
	}
	for _, kv := range [][2]string{
		{"opensandbox.io/id", "x"}, {"BadUpper", "x"}, {"e2b-shim-", "x"}, {"e2b-shim-Bad", "x"},
		{"e2b-shim-" + strings.Repeat("a", 55), "x"}, {"team", ""}, {"team", "bad value"},
	} {
		_, err := client.CreateTemplateSandbox(ctx, native.CreateTemplateSandboxRequest{
			TemplateID: "tpl_1", TimeoutSeconds: 60, Metadata: map[string]string{kv[0]: kv[1]},
		})
		assertErr("badCreateMeta("+kv[0]+")", err, native.ErrInvalidArgument)
	}
	for i, p := range []native.MetadataPatch{
		nil, {"opensandbox.io/sys": strPtr("v")}, {"opensandbox.io/sys": nil},
		{"BadKey": strPtr("v")}, {"e2b-shim-": strPtr("v")}, {"team": strPtr("")}, {"team": strPtr("bad@val")},
	} {
		_, err := client.PatchMetadata(ctx, "sbx-1", p)
		assertErr(fmt.Sprintf("badPatch[%d]", i), err, native.ErrInvalidArgument)
	}
	var zeroClient native.Client
	for _, tc := range []struct {
		label     string
		err, want error
	}{
		{"zeroClient", func() error { _, e := (&zeroClient).GetSandbox(ctx, "sbx-1"); return e }(), native.ErrInvalidArgument},
		{"nilClient", func() error { _, e := (*native.Client)(nil).GetSandbox(ctx, "sbx-1"); return e }(), native.ErrInvalidArgument},
		{"Pause", client.PauseSandbox(ctx, "sbx-1"), native.ErrNotImplemented},
		{"Resume", client.ResumeSandbox(ctx, "sbx-1"), native.ErrNotImplemented},
		{"Renew", func() error { _, e := client.RenewExpiration(ctx, "sbx-1", time.Now().Add(time.Minute)); return e }(), native.ErrNotImplemented},
		{"List", func() error { _, e := client.ListSandboxes(ctx, native.ListSandboxesRequest{}); return e }(), native.ErrNotImplemented},
	} {
		assertErr(tc.label, tc.err, tc.want)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server received %d requests, want 0", got)
	}
}

func TestRedactionAcrossClientEndpointAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/endpoints/") {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"endpoint": "https://ingress.example.internal/sbx-1/49983",
				"headers":  map[string]string{"OpenSandbox-Ingress-To": fakeIngressSecret, "Authorization": fakeSecondaryToken},
			})
			return
		}
		w.Header().Set("X-Request-ID", "req-redact-1")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "UNAUTHORIZED", "message": "bad key: " + fakeNativeAPIKey})
	}))
	defer srv.Close()

	client := mustNewClient(t, srv.URL+"/v1", nil)
	ep, err := client.GetEndpoint(context.Background(), "sbx-1", 49983)
	if err != nil {
		t.Fatalf("GetEndpoint: %v", err)
	}
	_, callErr := client.GetSandbox(context.Background(), "sbx-1")
	if callErr == nil {
		t.Fatal("expected 401 error")
	}

	var ce *native.CallError
	if !errors.As(callErr, &ce) || ce == nil {
		t.Fatalf("expected *native.CallError, got %T", callErr)
	}
	var nilCE *native.CallError

	var logText, logJSON bytes.Buffer
	slog.New(slog.NewTextHandler(&logText, nil)).Info("audit", "c_ptr", client, "c_val", *client, "ep_ptr", ep, "ep_val", *ep, "err_str", callErr.Error(), "err_iface", callErr, "err_ptr", ce, "err_val", *ce, "err_nil", nilCE)
	slog.New(slog.NewJSONHandler(&logJSON, nil)).Info("audit", "c_ptr", client, "c_val", *client, "ep_ptr", ep, "ep_val", *ep, "err_iface", callErr, "err_ptr", ce, "err_val", *ce, "err_nil", nilCE)

	clientJSON, _ := json.Marshal(client)
	clientText, _ := client.MarshalText()
	epJSON, _ := json.Marshal(ep)
	epText, _ := ep.MarshalText()
	cePtrJSON, err := json.Marshal(ce)
	if err != nil {
		t.Fatalf("json.Marshal(ce): %v", err)
	}
	ceValJSON, err := json.Marshal(*ce)
	if err != nil {
		t.Fatalf("json.Marshal(*ce): %v", err)
	}
	ceNilJSON, err := json.Marshal(nilCE)
	if err != nil || string(ceNilJSON) != "null" {
		t.Fatalf("json.Marshal(nilCE) = %q, err=%v", ceNilJSON, err)
	}
	ceText, _ := ce.MarshalText()

	for i, out := range []string{
		client.String(), client.GoString(), client.LogValue().String(),
		fmt.Sprintf("%v", client), fmt.Sprintf("%+v", client), fmt.Sprintf("%#v", client),
		fmt.Sprintf("%v", *client), fmt.Sprintf("%+v", *client), fmt.Sprintf("%#v", *client),
		fmt.Sprintf("%q", any(client)), fmt.Sprintf("%x", client), string(clientJSON), string(clientText),
		ep.String(), ep.GoString(), ep.LogValue().String(),
		fmt.Sprintf("%v", ep), fmt.Sprintf("%+v", ep), fmt.Sprintf("%#v", ep),
		fmt.Sprintf("%v", *ep), fmt.Sprintf("%+v", *ep), fmt.Sprintf("%#v", *ep),
		fmt.Sprintf("%q", any(ep)), fmt.Sprintf("%x", ep), string(epJSON), string(epText),
		logText.String(), logJSON.String(),
	} {
		for _, secret := range []string{fakeNativeAPIKey, fakeIngressSecret, fakeSecondaryToken} {
			if strings.Contains(out, secret) {
				t.Fatalf("output[%d] leaked secret %q: %s", i, secret, out)
			}
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Fatalf("output[%d] missing [REDACTED] marker: %s", i, out)
		}
	}
	for i, errOut := range []string{
		callErr.Error(), ce.GoString(), ce.LogValue().String(), string(cePtrJSON), string(ceValJSON), string(ceText),
		fmt.Sprintf("%v", callErr), fmt.Sprintf("%+v", callErr), fmt.Sprintf("%#v", callErr),
		fmt.Sprintf("%v", *ce), fmt.Sprintf("%+v", *ce), fmt.Sprintf("%#v", *ce),
		fmt.Sprintf("%q", any(ce)), fmt.Sprintf("%x", ce), fmt.Sprintf("%v %#v", nilCE, nilCE),
	} {
		if strings.Contains(errOut, fakeNativeAPIKey) || strings.Contains(errOut, srv.URL) {
			t.Fatalf("CallError output[%d] leaked key or raw URL: %q", i, errOut)
		}
	}
	for _, structured := range []string{string(cePtrJSON), string(ceValJSON), ce.LogValue().String(), logJSON.String()} {
		if !strings.Contains(structured, "[REDACTED]") {
			t.Fatalf("structured CallError output missing [REDACTED]: %s", structured)
		}
	}
}
