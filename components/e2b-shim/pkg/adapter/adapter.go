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

package adapter

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
)

const (
	DefaultReadinessTimeout      = 30 * time.Second
	DefaultReadinessPollInterval = 100 * time.Millisecond
	DefaultCleanupTimeout        = 10 * time.Second
	DefaultMaxBodyBytes          = int64(1 << 20)

	apiKeyHeader         = "X-API-KEY"       // #nosec G101 -- HTTP header name, not a credential
	idempotencyKeyHeader = "Idempotency-Key" // #nosec G101 -- HTTP header name, not a credential
	requestIDHeader      = "X-Request-ID"    // #nosec G101 -- HTTP header name, not a credential
	shouldRetryHeader    = "Should-Retry"    // #nosec G101 -- HTTP header name, not a credential
	maxLoggedSandboxID   = 128

	opCreate, opDelete      = "create", "delete"
	opConnect, opPause      = "connect", "pause"
	opGetInfo, opList       = "get_info", "list"
	opSetTimeout, opUnknown = "set_timeout", "unknown"
)

// Options configures a Gate 1a E2B control-plane Handler.
type Options struct {
	Config                                                  *config.Config
	Native                                                  native.Lifecycle
	Initializer                                             EnvdInitializer
	Admission                                               AdmissionController
	Logger                                                  *slog.Logger
	ReadinessTimeout, ReadinessPollInterval, CleanupTimeout time.Duration
	MaxBodyBytes                                            int64
	Clock                                                   func() time.Time
}

// Handler serves E2B control-plane routes beneath the compatibility prefix.
type Handler struct {
	prefix, adapterID, domain, hmacKeyVersion, apiKey       string
	apiKeyHash                                              [32]byte
	catalog                                                 *rules.TemplateCatalog
	tokenDeriver                                            *rules.TokenDeriver
	native                                                  native.Lifecycle
	initializer                                             EnvdInitializer
	admission                                               AdmissionController
	logger                                                  *slog.Logger
	readinessTimeout, readinessPollInterval, cleanupTimeout time.Duration
	maxBodyBytes                                            int64
	clock                                                   func() time.Time
	reqSeq                                                  *atomic.Uint64
	mux                                                     *http.ServeMux
}

type errorResponse struct {
	Code      int    `json:"code"`
	Message   string `json:"message"`
	ErrorCode string `json:"error_code"`
}

type createSandboxResponse struct {
	TemplateID      string `json:"templateID"`
	SandboxID       string `json:"sandboxID"`
	ClientID        string `json:"clientID"`
	EnvdVersion     string `json:"envdVersion"`
	EnvdAccessToken string `json:"envdAccessToken"`
	Domain          string `json:"domain,omitempty"`
}

// New validates opts and builds a prefix-mounted E2B control-plane Handler.
func New(opts Options) (*Handler, error) {
	if opts.Config == nil || opts.Native == nil || opts.Initializer == nil || opts.Admission == nil {
		return nil, errors.New("adapter: config, native, initializer, and admission are required")
	}
	cfg := opts.Config
	prefix, err := normalizeCompatPrefix(cfg.CompatPrefix)
	if err != nil {
		return nil, err
	}
	if cfg.AdapterAPIKey.IsZero() {
		return nil, errors.New("adapter: adapter_api_key is required")
	}
	rawAPIKey := cfg.AdapterAPIKey.Reveal()
	if strings.ContainsFunc(rawAPIKey, unicode.IsControl) {
		return nil, errors.New("adapter: adapter_api_key must not contain control characters")
	}
	if strings.ContainsAny(cfg.Domain, "/?#@:") || hasWhitespaceOrControl(cfg.Domain) {
		return nil, errors.New("adapter: invalid domain")
	}
	catalog, err := rules.NewTemplateCatalog(cfg.Templates, rules.TimeoutPolicy{
		DefaultSeconds: cfg.TimeoutDefaultSeconds,
		MinSeconds:     cfg.TimeoutMinSeconds,
		MaxSeconds:     cfg.TimeoutMaxSeconds,
	})
	if err != nil {
		return nil, fmt.Errorf("adapter: invalid template catalog: %w", err)
	}
	deriver, err := rules.NewTokenDeriver(cfg.HMACKey, cfg.HMACKeyVersion, cfg.AdapterID)
	if err != nil {
		return nil, fmt.Errorf("adapter: invalid token deriver: %w", err)
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	clk := opts.Clock
	if clk == nil {
		clk = time.Now
	}
	clonedKey := strings.Clone(rawAPIKey)
	h := &Handler{
		prefix: prefix, adapterID: cfg.AdapterID, domain: cfg.Domain, hmacKeyVersion: cfg.HMACKeyVersion,
		apiKey: clonedKey, apiKeyHash: sha256.Sum256([]byte(clonedKey)),
		catalog: catalog, tokenDeriver: deriver, native: opts.Native,
		initializer: opts.Initializer, admission: opts.Admission, logger: logger,
		readinessTimeout:      positiveOr(opts.ReadinessTimeout, DefaultReadinessTimeout),
		readinessPollInterval: positiveOr(opts.ReadinessPollInterval, DefaultReadinessPollInterval),
		cleanupTimeout:        positiveOr(opts.CleanupTimeout, DefaultCleanupTimeout),
		maxBodyBytes:          positiveOr(opts.MaxBodyBytes, DefaultMaxBodyBytes),
		clock:                 clk, reqSeq: new(atomic.Uint64), mux: http.NewServeMux(),
	}
	h.registerRoutes()
	return h, nil
}

func positiveOr[T ~int64](v, fallback T) T {
	if v > 0 {
		return v
	}
	return fallback
}

func (h Handler) String() string               { return redacted }
func (h Handler) GoString() string             { return redacted }
func (h Handler) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redacted) }
func (h Handler) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (h Handler) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (h Handler) LogValue() slog.Value         { return slog.StringValue(redacted) }

func (h *Handler) Prefix() string {
	if h == nil {
		return ""
	}
	return h.prefix
}

// Mount attaches the compatibility subtree onto mux without claiming root E2B paths.
func (h *Handler) Mount(mux *http.ServeMux) {
	if h != nil && mux != nil {
		mux.Handle(h.prefix, h)
		mux.Handle(h.prefix+"/", h)
	}
}

func (h *Handler) registerRoutes() {
	v2Sandboxes := h.prefix + "/v2/sandboxes"
	v2Connect := h.prefix + "/v2/sandboxes/{id}/connect"
	v1Sandbox := h.prefix + "/sandboxes/{id}"
	v1Pause := h.prefix + "/sandboxes/{id}/pause"
	v1Timeout := h.prefix + "/sandboxes/{id}/timeout"

	h.mux.HandleFunc("POST "+v2Sandboxes, h.wrapAuth(opCreate, http.MethodPost, "", h.handleCreate))
	h.mux.HandleFunc("GET "+v2Sandboxes, h.wrapAuth(opList, http.MethodGet, "GET, POST", h.handleUnsupported(opList)))
	h.mux.HandleFunc(v2Sandboxes, h.handleMethodNotAllowed("GET, POST"))

	h.mux.HandleFunc("POST "+v2Connect, h.wrapAuth(opConnect, http.MethodPost, "", h.handleUnsupported(opConnect)))
	h.mux.HandleFunc(v2Connect, h.handleMethodNotAllowed("POST"))

	h.mux.HandleFunc("DELETE "+v1Sandbox, h.wrapAuth(opDelete, http.MethodDelete, "", h.handleDelete))
	h.mux.HandleFunc("GET "+v1Sandbox, h.wrapAuth(opGetInfo, http.MethodGet, "DELETE, GET", h.handleUnsupported(opGetInfo)))
	h.mux.HandleFunc(v1Sandbox, h.handleMethodNotAllowed("DELETE, GET"))

	h.mux.HandleFunc("POST "+v1Pause, h.wrapAuth(opPause, http.MethodPost, "", h.handleUnsupported(opPause)))
	h.mux.HandleFunc(v1Pause, h.handleMethodNotAllowed("POST"))

	h.mux.HandleFunc("POST "+v1Timeout, h.wrapAuth(opSetTimeout, http.MethodPost, "", h.handleUnsupported(opSetTimeout)))
	h.mux.HandleFunc(v1Timeout, h.handleMethodNotAllowed("POST"))

	h.mux.HandleFunc(h.prefix+"/", h.handleNotFound)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil || r.URL == nil {
		http.NotFound(w, r)
		return
	}
	escPath := cmp.Or(r.URL.EscapedPath(), r.URL.Path)
	if !strings.HasPrefix(r.URL.Path, h.prefix+"/") || !strings.HasPrefix(escPath, h.prefix+"/") {
		h.handleNotFound(w, r)
		return
	}
	sub := strings.TrimPrefix(escPath, h.prefix)
	if opKind, allow, abnormal, unclean := classifySubpath(sub); abnormal {
		h.serveAbnormalIDRoute(w, r, opKind, allow)
		return
	} else if unclean {
		h.handleNotFound(w, r)
		return
	}
	h.mux.ServeHTTP(w, r)
}

func classifySubpath(sub string) (opKind, allow string, abnormalID, unclean bool) {
	if !strings.HasPrefix(sub, "/") || len(sub) <= 1 {
		return "", "", false, true
	}
	segs := strings.Split(sub[1:], "/")
	isSegDirty := func(s string) bool {
		u, err := url.PathUnescape(s)
		return s == "" || s == "." || s == ".." || err != nil || u == "." || u == ".." || strings.Contains(u, "/")
	}
	switch {
	case len(segs) == 4 && segs[0] == "v2" && segs[1] == "sandboxes" && segs[3] == "connect":
		if isSegDirty(segs[2]) {
			return opConnect, "POST", true, false
		}
	case len(segs) == 2 && segs[0] == "sandboxes" && segs[1] != "":
		if isSegDirty(segs[1]) {
			return "sandbox_item", "DELETE, GET", true, false
		}
	case len(segs) == 3 && segs[0] == "sandboxes" && segs[2] == "pause":
		if isSegDirty(segs[1]) {
			return opPause, "POST", true, false
		}
	case len(segs) == 3 && segs[0] == "sandboxes" && segs[2] == "timeout":
		if isSegDirty(segs[1]) {
			return opSetTimeout, "POST", true, false
		}
	}
	for _, seg := range segs {
		if isSegDirty(seg) {
			return "", "", false, true
		}
	}
	return "", "", false, false
}

func (h *Handler) serveAbnormalIDRoute(w http.ResponseWriter, r *http.Request, opKind, allow string) {
	op := opKind
	if opKind == "sandbox_item" {
		switch r.Method {
		case http.MethodDelete:
			op = opDelete
		case http.MethodGet:
			op = opGetInfo
		default:
			h.handleMethodNotAllowed(allow)(w, r)
			return
		}
	} else if r.Method != http.MethodPost {
		h.handleMethodNotAllowed(allow)(w, r)
		return
	}
	start, reqID := h.clock(), h.nextRequestID()
	if !h.authenticate(r) {
		h.respondError(w, start, reqID, op, "", http.StatusUnauthorized, "unauthorized", "unauthorized", false)
		return
	}
	if op == opDelete {
		h.respondError(w, start, reqID, opDelete, "", http.StatusBadRequest, "invalid sandbox ID", "invalid_sandbox_id", false)
		return
	}
	h.respondUnsupported(w, start, reqID, op)
}

type authedHandlerFunc func(w http.ResponseWriter, r *http.Request, start time.Time, reqID string)

func (h *Handler) wrapAuth(op, wantMethod, allowOnMismatch string, next authedHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != wantMethod {
			h.handleMethodNotAllowed(cmp.Or(allowOnMismatch, wantMethod))(w, r)
			return
		}
		start, reqID := h.clock(), h.nextRequestID()
		if !h.authenticate(r) {
			h.respondError(w, start, reqID, op, "", http.StatusUnauthorized, "unauthorized", "unauthorized", false)
			return
		}
		next(w, r, start, reqID)
	}
}

func (h *Handler) handleUnsupported(op string) authedHandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request, start time.Time, reqID string) {
		h.respondUnsupported(w, start, reqID, op)
	}
}

func (h *Handler) respondUnsupported(w http.ResponseWriter, start time.Time, reqID, op string) {
	h.respondError(w, start, reqID, op, "", http.StatusNotImplemented,
		op+" is not supported in the Gate 1a profile", "operation_not_supported", false)
}

func (h *Handler) handleNotFound(w http.ResponseWriter, _ *http.Request) {
	h.respondError(w, h.clock(), h.nextRequestID(), opUnknown, "", http.StatusNotFound, "route not found", "not_found", false)
}

func (h *Handler) handleMethodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allow)
		h.respondError(w, h.clock(), h.nextRequestID(), opUnknown, "", http.StatusMethodNotAllowed, "method not allowed", "method_not_allowed", false)
	}
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request, start time.Time, reqID string) {
	if len(headerValuesIgnoreCase(r.Header, idempotencyKeyHeader)) > 0 {
		h.respondError(w, start, reqID, opCreate, "", http.StatusBadRequest, "Idempotency-Key is not supported in this profile", "idempotency_key_unsupported", false)
		return
	}
	rawBody, statusErr, msg, code := h.readCreateBody(r.Body)
	if statusErr != 0 {
		h.respondError(w, start, reqID, opCreate, "", statusErr, msg, code, false)
		return
	}
	validated, err := rules.ValidateCreateRequest(rawBody, h.catalog, h.adapterID, h.hmacKeyVersion)
	if err != nil {
		st, errMsg, errCode := classifyCreateValidationError(err)
		h.respondError(w, start, reqID, opCreate, "", st, errMsg, errCode, false)
		return
	}

	// Strictly single native create attempt: never replay on ambiguous outcomes.
	created, err := h.native.CreateTemplateSandbox(r.Context(), native.CreateTemplateSandboxRequest{
		TemplateID: validated.Template.NativeTemplateID, TimeoutSeconds: validated.TimeoutSeconds, Metadata: validated.NativeMetadata,
	})
	if err != nil {
		if native.IsDefiniteFailure(err) {
			st, errMsg, errCode, noRetry := mapNativeDefiniteError(err, true)
			h.respondError(w, start, reqID, opCreate, "", st, errMsg, errCode, noRetry)
			return
		}
		h.respondError(w, start, reqID, opCreate, "", http.StatusServiceUnavailable, "sandbox creation outcome is ambiguous", "create_outcome_ambiguous", true)
		return
	}
	if created == nil || !isValidSandboxID(created.ID) {
		h.respondError(w, start, reqID, opCreate, "", http.StatusServiceUnavailable, "sandbox creation outcome is ambiguous", "create_outcome_ambiguous", true)
		return
	}

	sandboxID := created.ID
	failPostAlloc := func(errMsg, errCode string) {
		h.cleanupOnCreateFailure(sandboxID)
		h.respondError(w, start, reqID, opCreate, sandboxID, http.StatusServiceUnavailable, errMsg, errCode, true)
	}

	if err := h.waitForRunning(r.Context(), sandboxID, created.Status.State); err != nil {
		failPostAlloc("sandbox failed to reach Running readiness", "sandbox_readiness_failed")
		return
	}
	token, err := h.tokenDeriver.Derive(sandboxID)
	if err != nil {
		failPostAlloc("failed to derive sandbox access token", "initialization_failed")
		return
	}
	ep, err := h.native.GetEndpoint(r.Context(), sandboxID, EnvdPort)
	if err != nil || ep == nil || ep.URL == "" {
		failPostAlloc("failed to resolve sandbox envd endpoint", "endpoint_resolution_failed")
		return
	}
	initRes, err := h.initializer.Initialize(r.Context(), EnvdInitRequest{
		SandboxID: sandboxID, AccessToken: token, ExpectedEnvdVersion: validated.Template.ExpectedEnvdVersion,
		Endpoint: &native.Endpoint{URL: ep.URL, Headers: maps.Clone(ep.Headers)}, EnvVars: maps.Clone(validated.EnvVars),
	})
	if err != nil || initRes == nil || initRes.EnvdVersion == "" || initRes.EnvdVersion != validated.Template.ExpectedEnvdVersion {
		failPostAlloc("failed to initialize sandbox envd daemon", "envd_init_failed")
		return
	}
	if err := h.admission.Open(r.Context(), AdmissionRecord{
		SandboxID: sandboxID, TemplateRevision: validated.Template.Revision,
		EnvdVersion: initRes.EnvdVersion, Initialized: true,
	}); err != nil {
		failPostAlloc("failed to open sandbox admission", "admission_open_failed")
		return
	}

	h.respondJSON(w, http.StatusCreated, reqID, false, createSandboxResponse{
		TemplateID: validated.Template.TemplateID, SandboxID: sandboxID, ClientID: h.adapterID,
		EnvdVersion: initRes.EnvdVersion, EnvdAccessToken: token, Domain: h.domain,
	})
	h.logRequest(start, reqID, opCreate, "success", http.StatusCreated, sandboxID, "")
}

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request, start time.Time, reqID string) {
	sandboxID := r.PathValue("id")
	if !isValidSandboxID(sandboxID) {
		h.respondError(w, start, reqID, opDelete, "", http.StatusBadRequest, "invalid sandbox ID", "invalid_sandbox_id", false)
		return
	}

	ctx := r.Context()
	sbx, err := h.native.GetSandbox(ctx, sandboxID)
	if err != nil {
		if native.IsNotFound(err) {
			if closeErr := h.admission.Close(ctx, sandboxID); closeErr != nil {
				h.respondError(w, start, reqID, opDelete, sandboxID, http.StatusServiceUnavailable,
					"failed to revoke sandbox admission", "admission_close_failed", true)
				return
			}
			h.respondError(w, start, reqID, opDelete, sandboxID, http.StatusNotFound, "sandbox not found", "sandbox_not_found", false)
			return
		}
		if native.IsDefiniteFailure(err) {
			st, errMsg, errCode, noRetry := mapNativeDefiniteError(err, false)
			h.respondError(w, start, reqID, opDelete, sandboxID, st, errMsg, errCode, noRetry)
			return
		}
		h.respondError(w, start, reqID, opDelete, sandboxID, http.StatusServiceUnavailable,
			"failed to query sandbox state", "backend_unavailable", true)
		return
	}

	if own := rules.DecodeSandboxOwnership(sbx.Metadata, h.adapterID, h.hmacKeyVersion, h.catalog); !own.Owned {
		h.respondError(w, start, reqID, opDelete, sandboxID, http.StatusNotFound, "sandbox not found", "sandbox_not_found", false)
		return
	}

	// Condition (1): revoke E2B data-plane admission before native deletion.
	if err := h.admission.Close(ctx, sandboxID); err != nil {
		h.respondError(w, start, reqID, opDelete, sandboxID, http.StatusServiceUnavailable,
			"failed to revoke sandbox admission", "admission_close_failed", true)
		return
	}

	// Condition (2): single non-retried native DELETE, or confirmed terminal/absent state.
	delErr := h.native.DeleteSandbox(ctx, sandboxID)
	switch {
	case delErr == nil:
		h.respondNoContent(w, start, reqID, opDelete, sandboxID)
	case native.IsNotFound(delErr) && sbx.Status.State == native.StateTerminated:
		h.respondError(w, start, reqID, opDelete, sandboxID, http.StatusNotFound, "sandbox not found", "sandbox_not_found", false)
	case native.IsNotFound(delErr):
		h.respondNoContent(w, start, reqID, opDelete, sandboxID)
	case native.IsConflict(delErr):
		h.respondError(w, start, reqID, opDelete, sandboxID, http.StatusConflict, "sandbox lifecycle conflict", "lifecycle_conflict", false)
	case native.IsDefiniteFailure(delErr):
		st, errMsg, errCode, noRetry := mapNativeDefiniteError(delErr, false)
		h.respondError(w, start, reqID, opDelete, sandboxID, st, errMsg, errCode, noRetry)
	default:
		// Ambiguous DELETE outcome: never replay DELETE; perform one read-only state check.
		checkSbx, checkErr := h.native.GetSandbox(ctx, sandboxID)
		if native.IsNotFound(checkErr) || (checkErr == nil && checkSbx != nil && checkSbx.Status.State == native.StateTerminated) {
			h.respondNoContent(w, start, reqID, opDelete, sandboxID)
			return
		}
		h.respondError(w, start, reqID, opDelete, sandboxID, http.StatusServiceUnavailable,
			"sandbox deletion outcome is ambiguous", "delete_outcome_ambiguous", true)
	}
}

func (h *Handler) waitForRunning(ctx context.Context, sandboxID string, initialState native.State) error {
	if initialState == native.StateRunning {
		return nil
	}
	if initialState != native.StatePending {
		return fmt.Errorf("adapter: unexpected initial sandbox state %q", initialState)
	}
	waitCtx, cancel := context.WithTimeout(ctx, h.readinessTimeout)
	defer cancel()
	timer := time.NewTimer(h.readinessPollInterval)
	defer timer.Stop()

	for {
		select {
		case <-waitCtx.Done():
			return waitCtx.Err()
		case <-timer.C:
		}
		sbx, err := h.native.GetSandbox(waitCtx, sandboxID)
		if err != nil {
			return err
		}
		switch sbx.Status.State {
		case native.StateRunning:
			return nil
		case native.StatePending:
			timer.Reset(h.readinessPollInterval)
		default:
			return fmt.Errorf("adapter: sandbox transitioned to non-ready state %q", sbx.Status.State)
		}
	}
}

func (h *Handler) cleanupOnCreateFailure(sandboxID string) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), h.cleanupTimeout)
	defer cancel()
	_ = h.admission.Close(cleanupCtx, sandboxID)
	_ = h.native.DeleteSandbox(cleanupCtx, sandboxID)
}

func (h *Handler) authenticate(r *http.Request) bool {
	vals := headerValuesIgnoreCase(r.Header, apiKeyHeader)
	candidate, validCount := "", len(vals) == 1 && vals[0] != ""
	if validCount {
		candidate = vals[0]
	}
	gotHash := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(h.apiKeyHash[:], gotHash[:]) == 1 && validCount
}

func (h *Handler) readCreateBody(body io.ReadCloser) ([]byte, int, string, string) {
	if body == nil {
		return nil, http.StatusBadRequest, "request body is required", "invalid_request"
	}
	defer func() { _ = body.Close() }()
	limited, err := io.ReadAll(io.LimitReader(body, h.maxBodyBytes+1))
	if err != nil {
		return nil, http.StatusBadRequest, "failed to read request body", "invalid_request"
	}
	if int64(len(limited)) > h.maxBodyBytes {
		return nil, http.StatusBadRequest, "request body exceeds maximum size", "request_too_large"
	}
	if strings.TrimSpace(string(limited)) == "" {
		return nil, http.StatusBadRequest, "request body is required", "invalid_request"
	}
	return limited, 0, "", ""
}

var createValidationMap = []struct {
	target error
	status int
	msg    string
	code   string
}{
	{rules.ErrTemplateNotFound, http.StatusNotFound, "template not found", "template_not_found"},
	{rules.ErrTemplateNotReady, http.StatusBadRequest, "template is not ready", "template_not_ready"},
	{rules.ErrTemplateProfileIncompatible, http.StatusBadRequest, "template is incompatible with the active profile", "template_profile_incompatible"},
	{rules.ErrMissingTemplateID, http.StatusBadRequest, "templateID is required", "missing_template_id"},
	{rules.ErrUnknownField, http.StatusBadRequest, "unknown field in create request", "unknown_field"},
	{rules.ErrDuplicateField, http.StatusBadRequest, "duplicate JSON field in create request", "duplicate_field"},
	{rules.ErrUnsupportedOption, http.StatusBadRequest, "unsupported create option in the Gate 1a profile", "unsupported_option"},
	{rules.ErrInvalidEnvVar, http.StatusBadRequest, "invalid environment variable in envVars", "invalid_env_var"},
	{rules.ErrTimeoutInvalidType, http.StatusBadRequest, "timeout must be a positive integer", "invalid_timeout"},
	{rules.ErrTimeoutNonPositive, http.StatusBadRequest, "timeout must be a positive integer", "invalid_timeout"},
	{rules.ErrTimeoutBelowMin, http.StatusBadRequest, "timeout is below the profile minimum", "timeout_below_minimum"},
	{rules.ErrTimeoutExceedsMax, http.StatusBadRequest, "timeout exceeds the allowed maximum", "timeout_exceeds_maximum"},
	{rules.ErrReservedMetadataKey, http.StatusBadRequest, "metadata contains a reserved key", "reserved_metadata_key"},
	{rules.ErrInvalidMetadataKey, http.StatusBadRequest, "metadata contains an invalid key", "invalid_metadata_key"},
	{rules.ErrInvalidMetadataValue, http.StatusBadRequest, "metadata contains an invalid value", "invalid_metadata_value"},
}

func classifyCreateValidationError(err error) (int, string, string) {
	for _, m := range createValidationMap {
		if errors.Is(err, m.target) {
			return m.status, m.msg, m.code
		}
	}
	return http.StatusBadRequest, "invalid create request", "invalid_request"
}

func mapNativeDefiniteError(err error, isCreate bool) (int, string, string, bool) {
	var ce *native.CallError
	if !errors.As(err, &ce) || ce == nil {
		return http.StatusBadRequest, "invalid request", "invalid_request", false
	}
	switch ce.HTTPStatus {
	case http.StatusBadRequest:
		return http.StatusBadRequest, "invalid request", "invalid_request", false
	case http.StatusForbidden:
		return http.StatusForbidden, "forbidden", "forbidden", false
	case http.StatusNotFound:
		if isCreate {
			return http.StatusNotFound, "template not found", "template_not_found", false
		}
		return http.StatusNotFound, "sandbox not found", "sandbox_not_found", false
	case http.StatusConflict:
		return http.StatusConflict, "sandbox lifecycle conflict", "lifecycle_conflict", false
	case http.StatusTooManyRequests:
		return http.StatusTooManyRequests, "rate limit exceeded", "rate_limited", false
	default:
		return http.StatusServiceUnavailable, "backend service unavailable", "backend_unavailable", true
	}
}

func (h *Handler) nextRequestID() string { return fmt.Sprintf("e2b-%d", h.reqSeq.Add(1)) }

func (h *Handler) respondNoContent(w http.ResponseWriter, start time.Time, reqID, op, sandboxID string) {
	w.Header().Set(requestIDHeader, reqID)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	h.logRequest(start, reqID, op, "success", http.StatusNoContent, sandboxID, "")
}

func (h *Handler) respondError(w http.ResponseWriter, start time.Time, reqID, op, sandboxID string, status int, msg, errCode string, setNoRetry bool) {
	h.respondJSON(w, status, reqID, setNoRetry, errorResponse{Code: status, Message: msg, ErrorCode: errCode})
	outcome := "error"
	if status == http.StatusServiceUnavailable && setNoRetry {
		outcome = "ambiguous_or_unavailable"
	}
	h.logRequest(start, reqID, op, outcome, status, sandboxID, errCode)
}

func (h *Handler) respondJSON(w http.ResponseWriter, status int, reqID string, setNoRetry bool, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		data, status = []byte(`{"code":500,"message":"internal error","error_code":"internal_error"}`), http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set(requestIDHeader, reqID)
	if setNoRetry {
		w.Header().Set(shouldRetryHeader, "false")
	}
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func (h *Handler) logRequest(start time.Time, reqID, op, outcome string, status int, sandboxID, errCode string) {
	attrs := []slog.Attr{
		slog.String("operation", op), slog.String("outcome", outcome),
		slog.Int("status", status), slog.Int64("duration_ms", max(h.clock().Sub(start).Milliseconds(), 0)),
		slog.String("request_id", reqID),
	}
	if isValidSandboxID(sandboxID) && len(sandboxID) <= maxLoggedSandboxID {
		attrs = append(attrs, slog.String("sandbox_id", sandboxID))
	}
	if errCode != "" {
		attrs = append(attrs, slog.String("error_code", errCode))
	}
	h.logger.LogAttrs(context.Background(), slog.LevelInfo, "e2b_request", attrs...)
}

func normalizeCompatPrefix(p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", errors.New("adapter: compat_prefix must be an absolute path")
	}
	if strings.ContainsAny(p, "?#") || strings.ContainsAny(p, "%\\") || hasWhitespaceOrControl(p) {
		return "", errors.New("adapter: compat_prefix contains forbidden characters")
	}
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "", errors.New("adapter: compat_prefix must not be the root path")
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", errors.New("adapter: compat_prefix must not contain empty, '.' or '..' segments")
		}
	}
	if p == config.HealthPath || strings.HasPrefix(p, config.HealthPath+"/") {
		return "", errors.New("adapter: compat_prefix must not overlap the health check path")
	}
	return p, nil
}

func isValidSandboxID(id string) bool {
	return id != "" && id != "." && id != ".." && !strings.ContainsAny(id, "/\\?#") && !hasWhitespaceOrControl(id)
}

func hasWhitespaceOrControl(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

func headerValuesIgnoreCase(hdr http.Header, target string) []string {
	var out []string
	for k, vals := range hdr {
		if strings.EqualFold(k, target) {
			out = append(out, vals...)
		}
	}
	return out
}
