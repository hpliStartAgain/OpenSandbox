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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
)

const (
	defaultMaxTimeoutSeconds = int64(86400)
	defaultEndpointBase      = "http://127.0.0.1:49983"
	minTimeoutSeconds        = int64(60)
	maxDurationSeconds       = math.MaxInt64 / int64(time.Second)
	maxRequestBodyBytes      = 1 << 20
	apiKeyHeader             = "OPEN-SANDBOX-API-KEY" // #nosec G101 -- HTTP header name, not a credential
	opCreate, opGet          = "create", "get"
	opDelete, opEndpoint     = "delete", "endpoint"
	opPatchMetadata, opAll   = "patch_metadata", "*"
)

var ErrSandboxNotFound = errors.New("fakenative: sandbox not found")

type TemplateSpec struct {
	ID           string       `json:"id"`
	Ready        bool         `json:"ready"`
	Entrypoint   []string     `json:"entrypoint,omitempty"`
	InitialState native.State `json:"initialState,omitempty"`
}

type TransitionStep struct {
	State   native.State  `json:"state"`
	Reason  string        `json:"reason,omitempty"`
	Message string        `json:"message,omitempty"`
	After   time.Duration `json:"after,omitempty"`
}

type Stats struct {
	Create          int `json:"create"`
	Get             int `json:"get"`
	Delete          int `json:"delete"`
	Endpoint        int `json:"endpoint"`
	PatchMetadata   int `json:"patchMetadata"`
	ActiveSandboxes int `json:"activeSandboxes"`
	TotalCreated    int `json:"totalCreated"`
}

type Config struct {
	APIKey, BasePath, DefaultEndpointBase string
	MaxTimeoutSeconds                     int64
	DefaultTemplates                      []TemplateSpec
	RetainTerminated                      *bool
	Clock                                 func() time.Time
}

func (c Config) String() string {
	return fmt.Sprintf("Config{BasePath:%q,APIKey:[REDACTED]}", c.BasePath)
}
func (c Config) GoString() string             { return c.String() }
func (c Config) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, c.String()) }
func (c Config) MarshalText() ([]byte, error) { return []byte(c.String()), nil }
func (c Config) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }
func (c Config) LogValue() slog.Value         { return slog.StringValue(c.String()) }

type endpointKey struct {
	sandboxID string
	port      int
}

type sandboxRecord struct {
	id                   string
	status               native.SandboxStatus
	metadata, extensions map[string]string
	expiresAt, createdAt time.Time
	entrypoint           []string
	deleted              bool
	transitions          []TransitionStep
}

type Server struct {
	apiKey, basePath, defaultEndpointBase string
	maxTimeoutSeconds                     int64
	retainTerminated                      bool
	clock                                 func() time.Time
	reqSeq                                atomic.Uint64

	mu        sync.Mutex
	sbxSeq    uint64
	templates map[string]TemplateSpec
	sandboxes map[string]*sandboxRecord
	endpoints map[endpointKey]native.Endpoint
	faults    []FaultRule
	stats     Stats
}

func New(cfg Config) *Server {
	maxTimeout := cfg.MaxTimeoutSeconds
	if maxTimeout <= 0 {
		maxTimeout = defaultMaxTimeoutSeconds
	}
	clk := cfg.Clock
	if clk == nil {
		clk = time.Now
	}
	s := &Server{
		apiKey: strings.Clone(cfg.APIKey), basePath: normalizeBasePath(cfg.BasePath),
		maxTimeoutSeconds:   min(maxTimeout, maxDurationSeconds),
		defaultEndpointBase: cmp.Or(strings.TrimSpace(cfg.DefaultEndpointBase), defaultEndpointBase),
		retainTerminated:    cfg.RetainTerminated == nil || *cfg.RetainTerminated, clock: clk,
		templates: make(map[string]TemplateSpec, len(cfg.DefaultTemplates)),
		sandboxes: make(map[string]*sandboxRecord), endpoints: make(map[endpointKey]native.Endpoint),
	}
	for _, tpl := range cfg.DefaultTemplates {
		s.SetTemplate(tpl)
	}
	return s
}

func (s *Server) String() string {
	if s == nil {
		return "Server{<nil>}"
	}
	return fmt.Sprintf("Server{BasePath:%q,APIKey:[REDACTED]}", s.basePath)
}
func (s *Server) GoString() string             { return s.String() }
func (s *Server) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, s.String()) }
func (s *Server) MarshalText() ([]byte, error) { return []byte(s.String()), nil }
func (s *Server) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }
func (s *Server) LogValue() slog.Value         { return slog.StringValue(s.String()) }

func (s *Server) SetTemplate(spec TemplateSpec) {
	ep := slices.Clone(spec.Entrypoint)
	if len(ep) == 0 {
		ep = []string{"/bin/envd"}
	}
	s.mu.Lock()
	s.templates[spec.ID] = TemplateSpec{
		ID: spec.ID, Ready: spec.Ready, Entrypoint: ep,
		InitialState: cmp.Or(spec.InitialState, native.StateRunning),
	}
	s.mu.Unlock()
}

func (s *Server) SetState(sandboxID string, state native.State, reason, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		return ErrSandboxNotFound
	}
	setSandboxStatus(sbx, string(state), reason, message, s.now())
	return nil
}

func (s *Server) ScheduleTransitions(sandboxID string, steps []TransitionStep) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sbx, ok := s.sandboxes[sandboxID]
	if !ok || sbx.deleted {
		return ErrSandboxNotFound
	}
	sbx.transitions = slices.Clone(steps)
	return nil
}

func (s *Server) SetEndpoint(sandboxID string, port int, ep native.Endpoint) {
	s.mu.Lock()
	s.endpoints[endpointKey{sandboxID: sandboxID, port: port}] = native.Endpoint{URL: ep.URL, Headers: maps.Clone(ep.Headers)}
	s.mu.Unlock()
}

func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, active := s.now(), 0
	for id, sbx := range s.sandboxes {
		s.evaluateTTLLocked(id, sbx, now)
		if _, ok := s.sandboxes[id]; ok && !sbx.deleted &&
			sbx.status.State != native.StateTerminated && sbx.status.State != native.StateFailed {
			active++
		}
	}
	out := s.stats
	out.ActiveSandboxes = active
	return out
}

func (s *Server) GetSandboxSnapshot(sandboxID string) (native.Sandbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sbx, ok := s.resolveSandboxLocked(sandboxID, false, false)
	if !ok {
		return native.Sandbox{}, false
	}
	return snapshotSandbox(sbx), true
}

type handlerResult struct {
	status  int
	headers map[string]string
	body    any
}

func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveNative) }

func (s *Server) serveNative(w http.ResponseWriter, r *http.Request) {
	reqID := fmt.Sprintf("req-%d", s.reqSeq.Add(1))
	if !s.authenticate(r) {
		writeResult(w, reqID, errResult(http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid API key"))
		return
	}
	op, sandboxID, statPtr, fn, failRes := s.routeNative(r)
	if fn == nil {
		writeResult(w, reqID, failRes)
		return
	}
	fault, hasFault := s.matchFault(op, sandboxID)
	if hasFault && fault.DelayMs > 0 {
		t := time.NewTimer(time.Duration(fault.DelayMs) * time.Millisecond)
		select {
		case <-r.Context().Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	if hasFault && fault.DropBeforeExecute {
		hijackAndClose(w)
		return
	}
	s.mu.Lock()
	(*statPtr)++
	s.mu.Unlock()
	if hasFault && fault.StatusCode > 0 {
		if fault.StatusCode == http.StatusNoContent {
			writeResult(w, reqID, handlerResult{status: http.StatusNoContent})
		} else {
			code := cmp.Or(fault.ErrorCode, defaultErrorCode(fault.StatusCode))
			writeResult(w, reqID, errResult(fault.StatusCode, code, cmp.Or(fault.ErrorMessage, "injected fault")))
		}
		return
	}
	res := fn(r)
	if hasFault && fault.DropAfterExecute {
		hijackAndClose(w)
		return
	}
	if hasFault && fault.MalformedBody {
		st := res.status
		if st < 200 || st >= 300 || st == http.StatusNoContent {
			st = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", reqID)
		w.WriteHeader(st)
		_, _ = w.Write([]byte(`{"id":`))
		return
	}
	writeResult(w, reqID, res)
}

func (s *Server) authenticate(r *http.Request) bool {
	if s.apiKey == "" {
		return true
	}
	got := r.Header.Get(apiKeyHeader)
	if got == "" {
		return false
	}
	expHash, gotHash := sha256.Sum256([]byte(s.apiKey)), sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(expHash[:], gotHash[:]) == 1
}

func (s *Server) routeNative(r *http.Request) (string, string, *int, func(*http.Request) handlerResult, handlerResult) {
	root := strings.TrimSuffix(s.basePath, "/") + "/sandboxes"
	if r.URL.Path == root {
		if r.Method != http.MethodPost {
			return "", "", nil, nil, methodNotAllowedResult("POST")
		}
		return opCreate, "", &s.stats.Create, s.handleCreateSandbox, handlerResult{}
	}
	rest, ok := strings.CutPrefix(r.URL.Path, root+"/")
	if !ok || rest == "" {
		return "", "", nil, nil, notFoundRes("route not found")
	}
	parts := strings.Split(rest, "/")
	id, err := url.PathUnescape(parts[0])
	if parts[0] == "" || err != nil || id == "" || id == "." || id == ".." ||
		strings.ContainsAny(id, "/\\") || hasWhitespaceOrControl(id) {
		return "", "", nil, nil, badReq("invalid sandbox id")
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		return opGet, id, &s.stats.Get, func(*http.Request) handlerResult { return s.handleGetSandbox(id) }, handlerResult{}
	case len(parts) == 1 && r.Method == http.MethodDelete:
		return opDelete, id, &s.stats.Delete, func(*http.Request) handlerResult { return s.handleDeleteSandbox(id) }, handlerResult{}
	case len(parts) == 1:
		return "", "", nil, nil, methodNotAllowedResult("GET, DELETE")
	case len(parts) == 2 && parts[1] == "metadata" && r.Method == http.MethodPatch:
		return opPatchMetadata, id, &s.stats.PatchMetadata, func(req *http.Request) handlerResult { return s.handlePatchMetadata(id, req) }, handlerResult{}
	case len(parts) == 2 && parts[1] == "metadata":
		return "", "", nil, nil, methodNotAllowedResult("PATCH")
	case len(parts) == 3 && parts[1] == "endpoints" && parts[2] != "" && r.Method == http.MethodGet:
		return opEndpoint, id, &s.stats.Endpoint, func(req *http.Request) handlerResult { return s.handleGetEndpoint(id, parts[2], req) }, handlerResult{}
	case len(parts) == 3 && parts[1] == "endpoints" && parts[2] != "":
		return "", "", nil, nil, methodNotAllowedResult("GET")
	default:
		return "", "", nil, nil, notFoundRes("route not found")
	}
}

var (
	allowedCreateFields = map[string]bool{
		"templateId": true, "timeout": true, "metadata": true, "extensions": true,
		"networkPolicy": true, "credentialProxy": true, "image": true, "snapshotId": true,
		"entrypoint": true, "env": true, "resourceLimits": true, "resourceRequests": true,
		"volumes": true, "platform": true, "secureAccess": true, "lifecycle": true,
	}
	nonNullForbiddenOverrides = []string{
		"image", "snapshotId", "entrypoint", "env",
		"resourceLimits", "resourceRequests", "volumes", "platform", "lifecycle",
	}
)

func (s *Server) handleCreateSandbox(r *http.Request) handlerResult {
	raw, fields, err := readRawUniqueObject(r.Body)
	if err != nil {
		return badReq(err.Error())
	}
	for k := range fields {
		if !allowedCreateFields[k] {
			return badReq("unknown create field: " + k)
		}
	}
	for _, name := range nonNullForbiddenOverrides {
		if v, present := fields[name]; present && !isJSONNull(v) {
			return badReq(name + " override is rejected in template mode")
		}
	}
	var req struct {
		TemplateID      *string           `json:"templateId"`
		Timeout         json.RawMessage   `json:"timeout"`
		Metadata        map[string]string `json:"metadata"`
		Extensions      map[string]string `json:"extensions"`
		NetworkPolicy   map[string]any    `json:"networkPolicy"`
		CredentialProxy map[string]any    `json:"credentialProxy"`
		SecureAccess    *bool             `json:"secureAccess"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return badReq("invalid create request payload")
	}
	if req.TemplateID == nil || *req.TemplateID == "" || hasWhitespaceOrControl(*req.TemplateID) {
		return badReq("templateId must be a non-empty string without whitespace")
	}
	if req.SecureAccess != nil && *req.SecureAccess {
		return badReq("secureAccess override is rejected in template mode")
	}
	if _, ok := fields["timeout"]; !ok || isJSONNull(req.Timeout) {
		return badReq("timeout is required in template mode")
	}
	timeoutSec, err := parseStrictJSONInt64(req.Timeout)
	if err != nil || timeoutSec < minTimeoutSeconds || timeoutSec > s.maxTimeoutSeconds {
		return badReq("timeout must be an integer within [60, maxTimeoutSeconds]")
	}
	if rawMeta, ok := fields["metadata"]; ok && !isStrictStringMap(rawMeta) {
		return badReq("metadata must be a JSON string map")
	}
	for k, v := range req.Metadata {
		if err := validateNativeMetadataEntry(k, &v); err != nil {
			return badReq(err.Error())
		}
	}
	if rawExt, ok := fields["extensions"]; ok && !isJSONNull(rawExt) &&
		(!isStrictStringMap(rawExt) || strings.TrimSpace(req.Extensions["poolRef"]) != "") {
		return badReq("invalid extensions for template mode")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tpl, ok := s.templates[*req.TemplateID]
	if !ok || !tpl.Ready {
		return notFoundRes("template not found or not ready")
	}
	s.sbxSeq++
	id, now := fmt.Sprintf("sbx-%d", s.sbxSeq), s.now()
	meta := make(map[string]string, len(req.Metadata))
	maps.Copy(meta, req.Metadata)
	sbx := &sandboxRecord{
		id: id, metadata: meta, extensions: maps.Clone(req.Extensions),
		expiresAt: now.Add(time.Duration(timeoutSec) * time.Second),
		createdAt: now, entrypoint: slices.Clone(tpl.Entrypoint),
	}
	setSandboxStatus(sbx, string(tpl.InitialState), "provisioned", "sandbox created from template", now)
	s.sandboxes[id] = sbx
	s.stats.TotalCreated++
	return handlerResult{
		status:  http.StatusAccepted,
		headers: map[string]string{"Location": strings.TrimSuffix(s.basePath, "/") + "/sandboxes/" + id},
		body:    toWireSandbox(sbx),
	}
}

func (s *Server) handleGetSandbox(id string) handlerResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	sbx, ok := s.resolveSandboxLocked(id, true, true)
	if !ok {
		return notFoundRes("sandbox not found")
	}
	return handlerResult{status: http.StatusOK, body: toWireSandbox(sbx)}
}

func (s *Server) handleDeleteSandbox(id string) handlerResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	sbx, ok := s.resolveSandboxLocked(id, false, false)
	if !ok || sbx.deleted {
		return notFoundRes("sandbox not found")
	}
	sbx.deleted, sbx.transitions = true, nil
	setSandboxStatus(sbx, string(native.StateTerminated), "user_delete", "sandbox deleted", s.now())
	if !s.retainTerminated {
		delete(s.sandboxes, id)
	}
	return handlerResult{status: http.StatusNoContent}
}

func (s *Server) handleGetEndpoint(id, portStr string, r *http.Request) handlerResult {
	if r.URL.Query().Has("expires") {
		return badReq("expires query parameter is not supported")
	}
	port, err := parseStrictPort(portStr)
	if err != nil || port == 0 {
		return badReq("port must be an integer between 1 and 65535")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sbx, ok := s.resolveSandboxLocked(id, true, false)
	if !ok {
		return notFoundRes("sandbox not found")
	}
	if sbx.status.State != native.StateRunning {
		return errResult(http.StatusConflict, "CONFLICT", "sandbox is not Running")
	}
	epURL := s.defaultEndpointBase
	var hdrs map[string]string
	for _, targetID := range []string{id, opAll} {
		if custom, ok := s.endpoints[endpointKey{sandboxID: targetID, port: port}]; ok {
			epURL = cmp.Or(custom.URL, epURL)
			if custom.Headers != nil {
				hdrs = maps.Clone(custom.Headers)
			}
			break
		}
	}
	if hdrs == nil {
		hdrs = map[string]string{"OpenSandbox-Ingress-To": fmt.Sprintf("%s:%d", id, port)}
	}
	return handlerResult{status: http.StatusOK, body: map[string]any{"endpoint": epURL, "headers": hdrs}}
}

func (s *Server) handlePatchMetadata(id string, r *http.Request) handlerResult {
	raw, fields, err := readRawUniqueObject(r.Body)
	if err != nil {
		return badReq(err.Error())
	}
	for _, rv := range fields {
		if t := trimJSONSpace(rv); !bytes.Equal(t, []byte("null")) && (len(t) < 2 || t[0] != '"') {
			return badReq("metadata patch values must be strings or null")
		}
	}
	var patch map[string]*string
	if err := json.Unmarshal(raw, &patch); err != nil {
		return badReq("invalid metadata patch")
	}
	for k, vp := range patch {
		if err := validateNativeMetadataEntry(k, vp); err != nil {
			return badReq(err.Error())
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sbx, exists := s.resolveSandboxLocked(id, true, false)
	if !exists || sbx.deleted {
		return notFoundRes("sandbox not found")
	}
	for _, k := range slices.Sorted(maps.Keys(patch)) {
		if patch[k] == nil {
			delete(sbx.metadata, k)
		} else {
			sbx.metadata[k] = *patch[k]
		}
	}
	return handlerResult{status: http.StatusOK, body: toWireSandbox(sbx)}
}

func (s *Server) now() time.Time { return s.clock().UTC() }

func (s *Server) resolveSandboxLocked(id string, advanceTrans, allowPoll bool) (*sandboxRecord, bool) {
	sbx, ok := s.sandboxes[id]
	if !ok {
		return nil, false
	}
	now := s.now()
	if advanceTrans {
		s.advanceTransitionsLocked(sbx, now, allowPoll)
	}
	s.evaluateTTLLocked(id, sbx, now)
	sbx, ok = s.sandboxes[id]
	return sbx, ok
}

func (s *Server) advanceTransitionsLocked(sbx *sandboxRecord, now time.Time, allowPollStep bool) {
	if sbx.deleted || sbx.status.State == native.StateTerminated {
		return
	}
	consumedPoll := false
	for len(sbx.transitions) > 0 {
		step := sbx.transitions[0]
		if step.After > 0 {
			if now.Before(sbx.createdAt.Add(step.After)) {
				break
			}
		} else if !allowPollStep || consumedPoll {
			break
		} else {
			consumedPoll = true
		}
		sbx.transitions = sbx.transitions[1:]
		setSandboxStatus(sbx, string(step.State), step.Reason, step.Message, now)
		if sbx.status.State == native.StateTerminated {
			sbx.transitions = nil
			break
		}
	}
}

func (s *Server) evaluateTTLLocked(id string, sbx *sandboxRecord, now time.Time) {
	if now.Before(sbx.expiresAt) {
		return
	}
	if sbx.status.State != native.StateTerminated {
		sbx.transitions = nil
		setSandboxStatus(sbx, string(native.StateTerminated), "ttl_expiry", "sandbox TTL expired", now)
	}
	if !s.retainTerminated {
		delete(s.sandboxes, id)
	}
}

func setSandboxStatus(sbx *sandboxRecord, raw, reason, msg string, at time.Time) {
	raw = cmp.Or(raw, string(native.StateRunning))
	sbx.status = native.SandboxStatus{
		State: native.ParseState(raw), RawState: raw, Reason: reason, Message: msg, LastTransitionAt: &at,
	}
}

func snapshotSandbox(sbx *sandboxRecord) native.Sandbox {
	exp, st := sbx.expiresAt, sbx.status
	if st.LastTransitionAt != nil {
		t := *st.LastTransitionAt
		st.LastTransitionAt = &t
	}
	meta := make(map[string]string, len(sbx.metadata))
	maps.Copy(meta, sbx.metadata)
	return native.Sandbox{
		ID: sbx.id, Status: st, Metadata: meta, Extensions: maps.Clone(sbx.extensions),
		ExpiresAt: &exp, CreatedAt: sbx.createdAt, Entrypoint: slices.Clone(sbx.entrypoint),
	}
}

func toWireSandbox(sbx *sandboxRecord) map[string]any {
	snap := snapshotSandbox(sbx)
	st := map[string]any{"state": cmp.Or(snap.Status.RawState, string(snap.Status.State))}
	if snap.Status.Reason != "" {
		st["reason"] = snap.Status.Reason
	}
	if snap.Status.Message != "" {
		st["message"] = snap.Status.Message
	}
	if snap.Status.LastTransitionAt != nil {
		st["lastTransitionAt"] = snap.Status.LastTransitionAt
	}
	out := map[string]any{
		"id": snap.ID, "status": st, "metadata": snap.Metadata,
		"expiresAt": snap.ExpiresAt, "createdAt": snap.CreatedAt, "entrypoint": snap.Entrypoint,
	}
	if len(snap.Extensions) > 0 {
		out["extensions"] = snap.Extensions
	}
	return out
}

func writeResult(w http.ResponseWriter, reqID string, res handlerResult) {
	for k, v := range res.headers {
		w.Header().Set(k, v)
	}
	if reqID != "" {
		w.Header().Set("X-Request-ID", reqID)
	}
	if res.body == nil {
		w.WriteHeader(res.status)
		return
	}
	data, _ := json.Marshal(res.body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res.status)
	_, _ = w.Write(data)
}

func errResult(status int, code, msg string) handlerResult {
	return handlerResult{status: status, body: map[string]string{"code": code, "message": msg}}
}
func badReq(msg string) handlerResult {
	return errResult(http.StatusBadRequest, "INVALID_REQUEST", msg)
}
func notFoundRes(msg string) handlerResult { return errResult(http.StatusNotFound, "NOT_FOUND", msg) }
func methodNotAllowedResult(allow string) handlerResult {
	return handlerResult{
		status: http.StatusMethodNotAllowed, headers: map[string]string{"Allow": allow},
		body: map[string]string{"code": "METHOD_NOT_ALLOWED", "message": "method not allowed"},
	}
}

var statusCodes = map[int]string{
	http.StatusBadRequest: "INVALID_REQUEST", http.StatusUnauthorized: "UNAUTHORIZED",
	http.StatusForbidden: "FORBIDDEN", http.StatusNotFound: "NOT_FOUND",
	http.StatusConflict: "CONFLICT", http.StatusTooManyRequests: "RATE_LIMITED",
	http.StatusServiceUnavailable: "SERVICE_UNAVAILABLE",
}

func defaultErrorCode(status int) string { return cmp.Or(statusCodes[status], "INTERNAL_ERROR") }

func normalizeBasePath(raw string) string {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "/v1"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return cmp.Or(strings.TrimRight(p, "/"), "/")
}

func validateNativeMetadataEntry(key string, val *string) error {
	if strings.HasPrefix(key, rules.NativeReservedPrefix) {
		return rules.ErrReservedMetadataKey
	}
	checkKey := key
	if after, ok := strings.CutPrefix(key, rules.MetadataReservedPrefix); ok {
		if len(key) > rules.MaxLabelLength {
			return rules.ErrInvalidMetadataKey
		}
		checkKey = "a-" + after
	}
	if err := rules.ValidateMetadataKey(checkKey); err != nil {
		return err
	}
	if val != nil {
		return rules.ValidateLabelValue(*val)
	}
	return nil
}

func trimJSONSpace(b []byte) []byte       { return bytes.Trim(b, " \t\n\r") }
func isJSONNull(raw json.RawMessage) bool { return bytes.Equal(trimJSONSpace(raw), []byte("null")) }

func readRawUniqueObject(rc io.ReadCloser) ([]byte, map[string]json.RawMessage, error) {
	defer func() { _ = rc.Close() }()
	raw, err := io.ReadAll(io.LimitReader(rc, maxRequestBodyBytes+1))
	if err != nil || len(raw) > maxRequestBodyBytes {
		return nil, nil, errors.New("request body unreadable or exceeds limit")
	}
	fields, err := decodeUniqueObject(raw)
	return raw, fields, err
}

func decodeUniqueObject(data []byte) (map[string]json.RawMessage, error) {
	if isJSONNull(data) {
		return nil, errors.New("expected JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, errors.New("malformed object key")
		}
		key := keyTok.(string)
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate JSON key: " + key)
		}
		var rawVal json.RawMessage
		if err := dec.Decode(&rawVal); err != nil {
			return nil, errors.New("malformed object value")
		}
		fields[key] = rawVal
	}
	if endTok, err := dec.Token(); err != nil || endTok != json.Delim('}') {
		return nil, errors.New("unclosed JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected trailing JSON data")
	}
	return fields, nil
}

func isStrictStringMap(raw json.RawMessage) bool {
	fields, err := decodeUniqueObject(raw)
	if err != nil {
		return false
	}
	for _, rv := range fields {
		if t := trimJSONSpace(rv); len(t) < 2 || t[0] != '"' {
			return false
		}
	}
	return true
}

func parseStrictJSONInt64(raw json.RawMessage) (int64, error) {
	trimmed := trimJSONSpace(raw)
	digits := bytes.TrimPrefix(trimmed, []byte("-"))
	if len(digits) == 0 || (len(digits) > 1 && digits[0] == '0') {
		return 0, errors.New("expected canonical JSON integer")
	}
	for _, b := range digits {
		if b < '0' || b > '9' {
			return 0, errors.New("expected JSON integer")
		}
	}
	return strconv.ParseInt(string(trimmed), 10, 64)
}

func parseStrictPort(raw string) (int, error) {
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return 0, errors.New("invalid port")
	}
	n, err := strconv.ParseUint(raw, 10, 16)
	return int(n), err
}

func hasWhitespaceOrControl(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}
