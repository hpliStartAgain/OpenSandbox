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

package envdinit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alibaba/opensandbox/e2b-shim/internal/fakeenvd"
	"github.com/alibaba/opensandbox/e2b-shim/internal/fakenative"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/adapter"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/service"
)

func TestAdapterInitialization(t *testing.T) {
	for _, tt := range []struct {
		name    string
		faults  fakeenvd.Faults
		preinit bool
		want    int
	}{
		{"success and instance isolation", fakeenvd.Faults{}, false, 201},
		{"restart fails closed", fakeenvd.Faults{RestartBeforeProbe: true}, false, 503},
		{"dropped response cleaned up", fakeenvd.Faults{DropInitResponse: true}, false, 503},
		{"wrong version cleaned up", fakeenvd.Faults{InitVersion: "wrong"}, false, 503},
		{"different token cleaned up", fakeenvd.Faults{}, true, 503},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			adm := adapter.NewMemoryAdmissionController()
			fn := fakenative.New(fakenative.Config{APIKey: "test-native-key", BasePath: "/v1", DefaultTemplates: []fakenative.TemplateSpec{{ID: "native-base", Ready: true, InitialState: native.StateRunning}}})
			envds := []*fakeenvd.Server{fakeenvd.New(fakeenvd.Config{}), fakeenvd.New(fakeenvd.Config{})}
			ids := []string{"sbx-1", "sbx-2"}
			for n, fake := range envds {
				if tt.preinit {
					fake.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/init", strings.NewReader(`{"accessToken":"old-test-token"}`)))
				}
				fake.SetFaults(tt.faults)
				es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// The adapter must not admit traffic while trusted bootstrap runs.
					if fake.Stats().Metrics < 2 {
						if open, _ := adm.IsOpen(ctx, ids[n]); open {
							t.Error("admission opened before authentication proven")
						}
					}
					if r.Header.Get("OpenSandbox-Ingress-To") != "test-route-header" {
						t.Error("native routing header lost")
					}
					fake.ServeHTTP(w, r)
				}))
				t.Cleanup(es.Close)
				fn.SetEndpoint(ids[n], adapter.EnvdPort, native.Endpoint{URL: es.URL, Headers: map[string]string{"OpenSandbox-Ingress-To": "test-route-header"}})
			}
			ns := httptest.NewServer(fn.Handler())
			t.Cleanup(ns.Close)
			env := map[string]string{
				"E2B_SHIM_NATIVE_API_URL": ns.URL + "/v1", "E2B_SHIM_ADAPTER_ID": "e6-test", "E2B_SHIM_HMAC_KEY_VERSION": "v1",
				"E2B_SHIM_TIMEOUT_MAX_SECONDS": "3600", "E2B_SHIM_ADAPTER_API_KEY": "test-adapter-key", "E2B_SHIM_NATIVE_API_KEY": "test-native-key",
				"E2B_SHIM_HMAC_KEY": "test-hmac-key", "E2B_SHIM_TEMPLATES": `[{"template_id":"base","native_template_id":"native-base","revision":"base.rev-1","expected_envd_version":"0.8.0"}]`,
			}
			cfg, err := config.Load(config.Source{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }})
			if err != nil {
				t.Fatal(err)
			}
			nc, err := native.NewClient(native.ClientConfig{BaseURL: cfg.NativeAPIURL, APIKey: cfg.NativeAPIKey})
			if err != nil {
				t.Fatal(err)
			}
			var logs strings.Builder
			h, err := adapter.New(adapter.Options{Config: cfg, Native: nc, Initializer: New(nil), Admission: adm, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
			if err != nil {
				t.Fatal(err)
			}
			entry := service.NewHandlerWithExtra(h.Mount)
			create := func(id string) string {
				r := httptest.NewRequest("POST", cfg.CompatPrefix+"/v2/sandboxes", strings.NewReader(`{"templateID":"base","envVars":{"PRIVATE_ENV":"test-env-secret"}}`))
				r.Header.Set("X-API-KEY", "test-adapter-key")
				w := httptest.NewRecorder()
				entry.ServeHTTP(w, r)
				if w.Code != tt.want {
					t.Fatalf("create status %d, want %d; %s", w.Code, tt.want, w.Body.String())
				}
				open, err := adm.IsOpen(ctx, id)
				if err != nil || open != (tt.want == 201) {
					t.Fatal("incorrect admission state")
				}
				if tt.want != 201 {
					return ""
				}
				var result struct {
					SandboxID       string `json:"sandboxID"`
					EnvdAccessToken string `json:"envdAccessToken"`
					EnvdVersion     string `json:"envdVersion"`
				}
				if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.SandboxID != id || result.EnvdVersion != "0.8.0" {
					t.Fatal("wrong create result")
				}
				deriver, err := rules.NewTokenDeriver(cfg.HMACKey, cfg.HMACKeyVersion, cfg.AdapterID)
				if err != nil {
					t.Fatal(err)
				}
				expected, err := deriver.Derive(id)
				if err != nil || result.EnvdAccessToken != expected {
					t.Fatal("create returned an incorrect derived token")
				}
				return result.EnvdAccessToken
			}
			tokenA := create(ids[0])
			stats := fn.Stats()
			wantInit := 1
			if tt.preinit {
				wantInit++
			}
			if envds[0].Stats().Init != wantInit {
				t.Fatal("init retried")
			}
			if tt.want == 201 {
				tokenB := create(ids[1])
				if tokenA == "" || tokenB == "" || tokenA == tokenB {
					t.Fatal("same-template instances must have different tokens")
				}
				for _, pair := range []struct {
					server *fakeenvd.Server
					token  string
				}{{envds[0], tokenB}, {envds[1], tokenA}} {
					r := httptest.NewRequest("GET", "/metrics", nil)
					r.Header.Set("X-Access-Token", pair.token)
					w := httptest.NewRecorder()
					pair.server.ServeHTTP(w, r)
					if w.Code != 401 {
						t.Fatal("cross-instance token accepted")
					}
				}
				if stats.Delete != 0 || stats.ActiveSandboxes != 1 {
					t.Fatal("successful instance was deleted")
				}
				for _, fake := range envds {
					if fake.Stats().Init != 1 || fake.Stats().Health != 0 {
						t.Fatal("unexpected bootstrap requests")
					}
				}
			} else if stats.Delete != 1 || stats.ActiveSandboxes != 0 {
				t.Fatalf("failed instance not deleted: %+v", stats)
			}
			for _, secret := range []string{"test-env-secret", "test-route-header", tokenA, "old-test-token", "test-native-key"} {
				if secret != "" && strings.Contains(logs.String(), secret) {
					t.Fatal("adapter logs leaked private bootstrap values")
				}
			}
		})
	}
}
