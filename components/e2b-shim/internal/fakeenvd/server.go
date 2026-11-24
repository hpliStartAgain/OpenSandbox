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

// Package fakeenvd models the fresh, non-MMDS envd init/auth protocol for local
// development and tests. It deliberately preserves envd's insecure unset-token
// path. It is not an envd replacement and must never serve production traffic.
package fakeenvd

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

type Config struct{ Version string }

// Faults are persistent until replaced with SetFaults. RestartBeforeProbe
// simulates a single daemon restart on the next metrics request.
type Faults struct {
	DropInitResponse   bool
	InitVersion        string
	RestartBeforeProbe bool
}

type Stats struct{ Init, Metrics, Health int }

type Server struct{ *serverState }

type serverState struct {
	mu      sync.Mutex
	version string
	token   string
	env     map[string]string
	faults  Faults
	stats   Stats
}

func New(cfg Config) *Server {
	version := cfg.Version
	if version == "" {
		version = "0.8.0"
	}
	return &Server{serverState: &serverState{version: version}}
}

func (s *Server) Handler() http.Handler { return s }
func (s *Server) SetFaults(f Faults) {
	s.mu.Lock()
	s.faults = f
	s.mu.Unlock()
}

// Restart drops the daemon's in-memory auth and environment, retaining only
// the fake's configuration, fault controls and observation counters.
func (s *Server) Restart() {
	s.mu.Lock()
	s.token, s.env = "", nil
	s.mu.Unlock()
}

func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s Server) String() string             { return "fakeenvd.Server{[REDACTED]}" }
func (s Server) GoString() string           { return s.String() }
func (s Server) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/init" {
		s.init(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet && r.URL.Path == "/health" {
		s.stats.Health++
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/metrics" {
		s.stats.Metrics++
		if s.faults.RestartBeforeProbe {
			s.token, s.env = "", nil
			s.faults.RestartBeforeProbe = false
		}
	}
	if s.token != "" && subtle.ConstantTimeCompare([]byte(s.token), []byte(r.Header.Get("X-Access-Token"))) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/metrics" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}")
		return
	}
	http.NotFound(w, r)
}

func (s *Server) init(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req struct {
		AccessToken string            `json:"accessToken"`
		EnvVars     map[string]string `json:"envVars"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err == nil && len(body) != 0 {
		err = json.Unmarshal(body, &req)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Init++
	version := s.version
	if s.faults.InitVersion != "" {
		version = s.faults.InitVersion
	}
	w.Header().Set("X-Envd-Version", version)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if s.token != "" && subtle.ConstantTimeCompare([]byte(s.token), []byte(req.AccessToken)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	s.token = req.AccessToken
	if req.EnvVars != nil {
		s.env = req.EnvVars
	}
	if s.faults.DropInitResponse {
		if h, ok := w.(http.Hijacker); ok {
			if c, _, e := h.Hijack(); e == nil {
				_ = c.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	}
	w.WriteHeader(http.StatusNoContent)
}
