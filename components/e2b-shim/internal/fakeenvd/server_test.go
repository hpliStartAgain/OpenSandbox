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

package fakeenvd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProtocol(t *testing.T) {
	s := New(Config{Version: "0.8.0"})
	for _, tt := range []struct {
		name, method, path, body, token string
		status                          int
	}{
		{"health before init", "GET", "/health", "", "", 204},
		{"unset token is open", "GET", "/metrics", "", "", 200},
		{"empty init leaves token unset", "POST", "/init", "", "", 204},
		{"first init", "POST", "/init", `{"accessToken":"test-token-a","envVars":{"SECRET":"test-env"}}`, "", 204},
		{"health remains public", "GET", "/health", "", "", 204},
		{"missing token", "GET", "/metrics", "", "", 401},
		{"wrong token", "GET", "/metrics", "", "test-token-b", 401},
		{"correct token", "GET", "/metrics", "", "test-token-a", 200},
		{"same token init", "POST", "/init", `{"accessToken":"test-token-a"}`, "", 204},
		{"different token init", "POST", "/init", `{"accessToken":"test-token-b"}`, "test-token-a", 401},
		{"cannot clear token", "POST", "/init", `{}`, "test-token-a", 401},
		{"original token remains", "GET", "/metrics", "", "test-token-a", 200},
		{"trailing JSON rejected", "POST", "/init", `{} {}`, "", 400},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			r.Header.Set("X-Access-Token", tt.token)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != tt.status {
				t.Fatalf("status %d, want %d", w.Code, tt.status)
			}
			if tt.path == "/init" && w.Header().Get("X-Envd-Version") != "0.8.0" {
				t.Fatal("version header missing")
			}
			if (tt.name == "first init" || tt.name == "same token init") && s.env["SECRET"] != "test-env" {
				t.Fatal("envVars not applied")
			}
		})
	}
	s.Restart()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != 200 || s.token != "" || s.env != nil {
		t.Fatal("restart did not restore unset-token state")
	}
	if s.Stats().Init != 6 {
		t.Fatalf("unexpected init count: %d", s.Stats().Init)
	}
}

func TestFaultsAndFormatting(t *testing.T) {
	s := New(Config{})
	s.SetFaults(Faults{InitVersion: "wrong-version"})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/init", strings.NewReader(`{"accessToken":"test-secret"}`)))
	if w.Header().Get("X-Envd-Version") != "wrong-version" {
		t.Fatal("wrong-version fault not applied")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if strings.Contains(fmt.Sprintf(verb, s)+fmt.Sprintf(verb, *s), "test-secret") {
			t.Fatal("formatted server leaked token")
		}
	}
}
