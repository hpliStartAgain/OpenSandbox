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

package fakenative

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
)

var ErrNonLoopbackControl = errors.New("fakenative: control listener address must be loopback")

type FaultRule struct {
	Operation         string `json:"operation"`
	SandboxID         string `json:"sandboxId,omitempty"`
	Remaining         int    `json:"remaining,omitempty"`
	DropAfterExecute  bool   `json:"dropAfterExecute,omitempty"`
	DropBeforeExecute bool   `json:"dropBeforeExecute,omitempty"`
	DelayMs           int64  `json:"delayMs,omitempty"`
	StatusCode        int    `json:"statusCode,omitempty"`
	ErrorCode         string `json:"errorCode,omitempty"`
	ErrorMessage      string `json:"errorMessage,omitempty"`
	MalformedBody     bool   `json:"malformedBody,omitempty"`
}

func (s *Server) AddFault(rule FaultRule) {
	rule.Operation = cmp.Or(rule.Operation, opAll)
	s.mu.Lock()
	s.faults = append(s.faults, rule)
	s.mu.Unlock()
}

func (s *Server) ClearFaults() {
	s.mu.Lock()
	s.faults = nil
	s.mu.Unlock()
}

func (s *Server) matchFault(op, sandboxID string) (FaultRule, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.faults {
		r := &s.faults[i]
		if (r.Operation != opAll && r.Operation != op) || (r.SandboxID != "" && r.SandboxID != sandboxID) {
			continue
		}
		matched := *r
		if r.Remaining > 0 {
			if r.Remaining--; r.Remaining == 0 {
				s.faults = slices.Delete(s.faults, i, i+1)
			}
		}
		return matched, true
	}
	return FaultRule{}, false
}

func hijackAndClose(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
		}
	}
}

func (s *Server) ControlHandler() http.Handler { return http.HandlerFunc(s.serveControl) }

func (s *Server) serveControl(w http.ResponseWriter, r *http.Request) {
	reqID := fmt.Sprintf("ctrl-%d", s.reqSeq.Add(1))
	// Strict RemoteAddr check: never trust X-Forwarded-For, X-Real-IP, or Forwarded.
	if !isLoopbackRemoteAddr(r.RemoteAddr) {
		writeResult(w, reqID, errResult(http.StatusForbidden, "FORBIDDEN", "control endpoint requires loopback RemoteAddr"))
		return
	}
	writeResult(w, reqID, s.dispatchControl(r))
}

func (s *Server) dispatchControl(r *http.Request) handlerResult {
	switch r.URL.Path {
	case "/control/faults":
		switch r.Method {
		case http.MethodPost:
			var rule FaultRule
			if err := decodeControlBody(r.Body, &rule); err != nil || !isValidFaultOp(rule.Operation) || rule.Remaining < 0 || rule.DelayMs < 0 {
				return badReq("invalid fault rule")
			}
			s.AddFault(rule)
			return handlerResult{status: http.StatusCreated, body: rule}
		case http.MethodDelete:
			s.ClearFaults()
			return handlerResult{status: http.StatusNoContent}
		default:
			return methodNotAllowedResult("POST, DELETE")
		}
	case "/control/templates":
		var spec TemplateSpec
		if failRes, ok := decodeControlPost(r, &spec); !ok {
			return failRes
		}
		if spec.ID == "" || hasWhitespaceOrControl(spec.ID) {
			return badReq("invalid template spec")
		}
		s.SetTemplate(spec)
		return handlerResult{status: http.StatusOK, body: spec}
	case "/control/endpoints":
		var req struct {
			SandboxID string            `json:"sandboxId"`
			Port      int               `json:"port"`
			Endpoint  string            `json:"endpoint"`
			Headers   map[string]string `json:"headers"`
		}
		if failRes, ok := decodeControlPost(r, &req); !ok {
			return failRes
		}
		if req.SandboxID == "" || hasWhitespaceOrControl(req.SandboxID) ||
			req.Port < 1 || req.Port > 65535 || req.Endpoint == "" || hasWhitespaceOrControl(req.Endpoint) {
			return badReq("invalid endpoint override")
		}
		s.SetEndpoint(req.SandboxID, req.Port, native.Endpoint{URL: req.Endpoint, Headers: req.Headers})
		return handlerResult{status: http.StatusOK, body: map[string]string{"status": "ok"}}
	case "/control/stats":
		if r.Method != http.MethodGet {
			return methodNotAllowedResult("GET")
		}
		return handlerResult{status: http.StatusOK, body: s.Stats()}
	}

	if rest, ok := strings.CutPrefix(r.URL.Path, "/control/sandboxes/"); ok {
		if parts := strings.Split(rest, "/"); len(parts) == 2 && parts[0] != "" && parts[1] == "state" {
			var req struct {
				State   string `json:"state"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
			}
			if failRes, ok := decodeControlPost(r, &req); !ok {
				return failRes
			}
			id, err := url.PathUnescape(parts[0])
			if err != nil || id == "" || hasWhitespaceOrControl(id) || req.State == "" || hasWhitespaceOrControl(req.State) {
				return badReq("invalid state payload")
			}
			if err := s.SetState(id, native.State(req.State), req.Reason, req.Message); err != nil {
				return notFoundRes("sandbox not found")
			}
			return handlerResult{status: http.StatusOK, body: map[string]string{"id": id, "state": req.State}}
		}
	}
	return notFoundRes("control route not found")
}

type StandaloneInstance struct {
	srv                  *Server
	apiAddr, controlAddr string
	apiHTTP, ctrlHTTP    *http.Server
	done                 chan struct{}
	closeOnce            sync.Once
	closeErr             error
}

func StartStandalone(apiListen, controlListen string) (*StandaloneInstance, error) {
	return New(Config{}).StartStandalone(apiListen, controlListen)
}

func (s *Server) StartStandalone(apiListen, controlListen string) (*StandaloneInstance, error) {
	if err := validateLoopbackControlListen(controlListen); err != nil {
		return nil, err
	}
	if _, portStr, err := net.SplitHostPort(apiListen); err != nil {
		return nil, fmt.Errorf("fakenative: invalid api listen address: %w", err)
	} else if _, pErr := parseStrictPort(portStr); pErr != nil {
		return nil, fmt.Errorf("fakenative: invalid api listen port: %w", pErr)
	}
	ctrlLn, err := net.Listen("tcp", controlListen)
	if err != nil {
		return nil, fmt.Errorf("fakenative: listen control: %w", err)
	}
	if tcpAddr, ok := ctrlLn.Addr().(*net.TCPAddr); !ok || !tcpAddr.IP.IsLoopback() {
		_ = ctrlLn.Close()
		return nil, ErrNonLoopbackControl
	}
	apiLn, err := net.Listen("tcp", apiListen)
	if err != nil {
		_ = ctrlLn.Close()
		return nil, fmt.Errorf("fakenative: listen api: %w", err)
	}

	apiHTTP := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	ctrlHTTP := &http.Server{Handler: s.ControlHandler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = apiHTTP.Serve(apiLn) }()
	go func() { defer wg.Done(); _ = ctrlHTTP.Serve(ctrlLn) }()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	return &StandaloneInstance{
		srv: s, apiAddr: apiLn.Addr().String(), controlAddr: ctrlLn.Addr().String(),
		apiHTTP: apiHTTP, ctrlHTTP: ctrlHTTP, done: done,
	}, nil
}

func (inst *StandaloneInstance) APIAddr() string     { return inst.apiAddr }
func (inst *StandaloneInstance) ControlAddr() string { return inst.controlAddr }
func (inst *StandaloneInstance) Server() *Server     { return inst.srv }

func (inst *StandaloneInstance) Close(ctx context.Context) error {
	inst.closeOnce.Do(func() {
		if ctx == nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
		}
		errAPI, errCtrl := shutdownHTTPServer(ctx, inst.apiHTTP), shutdownHTTPServer(ctx, inst.ctrlHTTP)
		<-inst.done
		inst.closeErr = errors.Join(errAPI, errCtrl)
	})
	return inst.closeErr
}

func shutdownHTTPServer(ctx context.Context, srv *http.Server) error {
	if err := srv.Shutdown(ctx); err != nil {
		_ = srv.Close()
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}

func validateLoopbackControlListen(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return ErrNonLoopbackControl
	}
	if _, err := parseStrictPort(portStr); err != nil {
		return fmt.Errorf("%w: invalid port", ErrNonLoopbackControl)
	}
	if strings.EqualFold(host, "localhost") || isLoopbackIPHost(host) {
		return nil
	}
	return ErrNonLoopbackControl
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	return err == nil && isLoopbackIPHost(host)
}

func isLoopbackIPHost(host string) bool {
	host, _, _ = strings.Cut(host, "%")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isValidFaultOp(op string) bool {
	switch op {
	case opCreate, opGet, opDelete, opEndpoint, opPatchMetadata, opAll:
		return true
	default:
		return false
	}
}

func decodeControlPost(r *http.Request, dst any) (handlerResult, bool) {
	if r.Method != http.MethodPost {
		return methodNotAllowedResult("POST"), false
	}
	if err := decodeControlBody(r.Body, dst); err != nil {
		return badReq(err.Error()), false
	}
	return handlerResult{}, true
}

func decodeControlBody(rc io.ReadCloser, dst any) error {
	raw, _, err := readRawUniqueObject(rc)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
