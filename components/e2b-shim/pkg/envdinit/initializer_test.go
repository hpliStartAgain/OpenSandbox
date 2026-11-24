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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/e2b-shim/internal/fakeenvd"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/adapter"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
)

func initRequest(target string) adapter.EnvdInitRequest {
	return adapter.EnvdInitRequest{
		SandboxID: "instance-a", AccessToken: "test-envd-secret-a", ExpectedEnvdVersion: "0.8.0",
		Endpoint: &native.Endpoint{URL: target}, EnvVars: map[string]string{"PRIVATE_ENV": "test-private-value"},
	}
}

func TestInitializeOutcomes(t *testing.T) {
	for _, tt := range []struct {
		name        string
		faults      fakeenvd.Faults
		preinit     bool
		class       native.OutcomeClass
		init, probe int
	}{
		{"happy", fakeenvd.Faults{}, false, native.OutcomeSuccess, 1, 2},
		{"token mismatch", fakeenvd.Faults{}, true, native.OutcomeDefiniteFailure, 2, 0},
		{"version mismatch", fakeenvd.Faults{InitVersion: "wrong"}, false, native.OutcomeDefiniteFailure, 1, 0},
		{"dropped response", fakeenvd.Faults{DropInitResponse: true}, false, native.OutcomeAmbiguous, 1, 0},
		{"restart before probe", fakeenvd.Faults{RestartBeforeProbe: true}, false, native.OutcomeDefiniteFailure, 1, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := fakeenvd.New(fakeenvd.Config{})
			if tt.preinit {
				s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/init", strings.NewReader(`{"accessToken":"other-token"}`)))
			}
			s.SetFaults(tt.faults)
			h := httptest.NewServer(s)
			defer h.Close()
			res, err := New(h.Client()).Initialize(context.Background(), initRequest(h.URL))
			if ClassifyError(err) != tt.class {
				t.Fatalf("classification %s, want %s; error: %v", ClassifyError(err), tt.class, err)
			}
			if tt.class == native.OutcomeSuccess {
				if err != nil || res == nil || res.EnvdVersion != "0.8.0" {
					t.Fatal("version not returned on success")
				}
			} else if res != nil || !errors.Is(err, map[native.OutcomeClass]error{
				native.OutcomeDefiniteFailure: ErrDefiniteFailure, native.OutcomeAmbiguous: ErrAmbiguous,
			}[tt.class]) {
				t.Fatal("failure must return no result and an inspectable sentinel")
			}
			stats := s.Stats()
			if stats.Init != tt.init || stats.Metrics != tt.probe || stats.Health != 0 {
				t.Fatalf("unexpected request counts: %+v", stats)
			}
		})
	}
}

func TestNativeRouteAndPayload(t *testing.T) {
	fake := fakeenvd.New(fakeenvd.Config{})
	var calls atomic.Int32
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.Host != "native-route.internal" || r.Header.Get("OpenSandbox-Ingress-To") != "test-native-header" || r.URL.RawQuery != "signed=test-signature" || !strings.HasPrefix(r.URL.EscapedPath(), "/route%2Fid/") {
			t.Error("native path/query/headers not preserved")
		}
		switch n {
		case 1:
			if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/init") || r.Header.Get("X-Access-Token") != "" || r.Header.Get("Content-Type") != "application/json" {
				t.Error("invalid private init request")
			}
			var payload map[string]json.RawMessage
			body, _ := io.ReadAll(r.Body)
			if json.Unmarshal(body, &payload) != nil || len(payload) != 2 || string(payload["accessToken"]) != `"test-envd-secret-a"` || string(payload["envVars"]) != `{"PRIVATE_ENV":"test-private-value"}` {
				t.Error("wrong init payload")
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
		case 2:
			if r.Header.Get("X-Access-Token") != "test-envd-secret-a" {
				t.Error("authenticated probe missing derived token")
			}
		case 3:
			if r.Header.Get("X-Access-Token") != "" {
				t.Error("unauthenticated probe inherited native header")
			}
		default:
			t.Error("unexpected extra request")
		}
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/route/id")
		fake.ServeHTTP(w, r)
	}))
	defer h.Close()
	req := initRequest(h.URL + "/route%2Fid/?signed=test-signature")
	req.Endpoint.Headers = map[string]string{"OpenSandbox-Ingress-To": "test-native-header", "x-access-token": "test-inherited-token", "Host": "native-route.internal"}
	if _, err := New(h.Client()).Initialize(context.Background(), req); err != nil || calls.Load() != 3 {
		t.Fatalf("initialize: %v; calls %d", err, calls.Load())
	}
}

func TestHTTPFailuresAndNoRedirects(t *testing.T) {
	for _, tt := range []struct {
		name         string
		step, status int
		class        native.OutcomeClass
	}{
		{"init unauthorized", 1, 401, native.OutcomeDefiniteFailure},
		{"missing version", 1, 204, native.OutcomeDefiniteFailure},
		{"init redirect", 1, 307, native.OutcomeDefiniteFailure},
		{"init timeout", 1, 408, native.OutcomeAmbiguous},
		{"init gateway error", 1, 502, native.OutcomeAmbiguous},
		{"auth rejected", 2, 401, native.OutcomeDefiniteFailure},
		{"auth redirect", 2, 302, native.OutcomeDefiniteFailure},
		{"auth service error", 2, 503, native.OutcomeAmbiguous},
		{"no-token redirect", 3, 302, native.OutcomeDefiniteFailure},
		{"no-token open", 3, 200, native.OutcomeDefiniteFailure},
		{"no-token forbidden", 3, 403, native.OutcomeDefiniteFailure},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var redirected atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
			defer target.Close()
			fake := fakeenvd.New(fakeenvd.Config{})
			var calls atomic.Int32
			h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if int(calls.Add(1)) == tt.step {
					w.Header().Set("Location", target.URL)
					w.WriteHeader(tt.status)
					return
				}
				fake.ServeHTTP(w, r)
			}))
			defer h.Close()
			client := h.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { t.Error("caller redirect policy used"); return nil }
			_, err := New(client).Initialize(context.Background(), initRequest(h.URL))
			if ClassifyError(err) != tt.class || calls.Load() != int32(tt.step) || redirected.Load() != 0 {
				t.Fatalf("error=%v calls=%d redirected=%d", err, calls.Load(), redirected.Load())
			}
		})
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type boundedBody struct {
	reads  int
	fail   bool
	closed bool
}

func (b *boundedBody) Read(p []byte) (int, error) {
	b.reads += len(p)
	if b.fail {
		return 0, errors.New("test-sensitive-body-error")
	}
	return len(p), nil
}
func (b *boundedBody) Close() error { b.closed = true; return nil }

func TestTransportRedactionAndBoundedReads(t *testing.T) {
	for _, mode := range []string{"transport", "body-error", "bounded-body", "missing-version"} {
		t.Run(mode, func(t *testing.T) {
			req := initRequest("http://test-private-url.invalid/path")
			req.Endpoint.Headers = map[string]string{"Private-Header": "test-private-header-value"}
			body := &boundedBody{fail: mode == "body-error"}
			calls := 0
			client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.GetBody != nil {
					t.Error("init request replayable")
				}
				if mode == "transport" {
					return nil, errors.New(req.AccessToken + req.Endpoint.URL + req.EnvVars["PRIVATE_ENV"] + req.Endpoint.Headers["Private-Header"])
				}
				hdr := make(http.Header)
				if mode != "missing-version" {
					hdr.Set("X-Envd-Version", "0.8.0")
				}
				// A 401 halts after one response, making the drain bound observable.
				return &http.Response{StatusCode: 401, Header: hdr, Body: body}, nil
			})}
			initializer := New(client)
			_, err := initializer.Initialize(context.Background(), req)
			if err == nil || calls != 1 {
				t.Fatal("failure did not stop after one request")
			}
			if mode != "transport" && (!body.closed || body.reads > maxDrainBytes) {
				t.Fatal("body read was unbounded or not closed")
			}
			for _, value := range []any{err, req, initializer, *initializer} {
				var logs strings.Builder
				slog.New(slog.NewJSONHandler(&logs, nil)).Info("test", "value", value)
				encoded, _ := json.Marshal(value)
				output := fmt.Sprintf("%v %+v %#v %s", value, value, value, value) + string(encoded) + logs.String()
				for _, secret := range []string{req.AccessToken, req.Endpoint.URL, "test-private-url", req.EnvVars["PRIVATE_ENV"], "PRIVATE_ENV", "Private-Header", "test-private-header-value", "test-sensitive-body-error"} {
					if strings.Contains(output, secret) {
						t.Fatal("sensitive value leaked")
					}
				}
			}
		})
	}
}

func TestContextAndInputFailures(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		<-r.Context().Done()
		return nil, r.Context().Err()
	}), Timeout: 20 * time.Millisecond}
	initializer := New(client)
	for _, target := range []string{"%", "ftp://private.invalid", "http://user:secret@private.invalid", "http://private.invalid/#fragment", ""} {
		_, err := initializer.Initialize(context.Background(), initRequest(target))
		if !errors.Is(err, ErrDefiniteFailure) {
			t.Fatal("invalid endpoint not rejected")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := initializer.Initialize(ctx, initRequest("http://private.invalid"))
	if !errors.Is(err, ErrDefiniteFailure) || !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatal("canceled request was sent")
	}
	_, err = initializer.Initialize(context.Background(), initRequest("http://private.invalid"))
	if !errors.Is(err, ErrAmbiguous) || calls.Load() != 1 {
		t.Fatal("timeout must be ambiguous with no retry")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = New(&http.Client{Transport: client.Transport}).Initialize(ctx, initRequest("http://private.invalid"))
	if !errors.Is(err, ErrAmbiguous) || calls.Load() != 2 {
		t.Fatal("context deadline must stop the request")
	}
	if New(nil).client.Timeout <= 0 {
		t.Fatal("default timeout missing")
	}
}
