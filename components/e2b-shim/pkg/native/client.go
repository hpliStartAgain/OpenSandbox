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

package native

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
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
)

const (
	DefaultRequestTimeout   = 15 * time.Second
	DefaultReadMaxAttempts  = 2
	MaxReadMaxAttempts      = 5
	DefaultReadRetryBackoff = 50 * time.Millisecond

	minCreateTimeoutSeconds = 60
	maxResponseBodyBytes    = 1 << 20
	drainBodyBytes          = 4 << 10

	apiKeyHeader    = "OPEN-SANDBOX-API-KEY" // #nosec G101 -- HTTP header name, not a credential
	requestIDHeader = "X-Request-ID"
)

type ClientConfig struct {
	BaseURL          string
	APIKey           config.Secret
	HTTPClient       *http.Client
	RequestTimeout   time.Duration
	ReadMaxAttempts  int
	ReadRetryBackoff time.Duration
}

type Client struct {
	baseURL          string
	apiKey           string
	httpClient       http.Client
	readMaxAttempts  int
	readRetryBackoff time.Duration
}

var _ Lifecycle = (*Client)(nil)

func NewClient(cfg ClientConfig) (*Client, error) {
	baseURL, err := validateBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.APIKey.IsZero() {
		return nil, fmt.Errorf("%w: api_key is required", ErrInvalidArgument)
	}
	rawKey := cfg.APIKey.Reveal()
	if strings.ContainsFunc(rawKey, unicode.IsControl) {
		return nil, fmt.Errorf("%w: api_key must not contain control characters", ErrInvalidArgument)
	}
	readMax := cfg.ReadMaxAttempts
	if readMax <= 0 {
		readMax = DefaultReadMaxAttempts
	} else if readMax > MaxReadMaxAttempts {
		return nil, fmt.Errorf("%w: read_max_attempts must not exceed %d", ErrInvalidArgument, MaxReadMaxAttempts)
	}
	backoff := cfg.ReadRetryBackoff
	if backoff < 0 {
		backoff = DefaultReadRetryBackoff
	}

	var hc http.Client
	if cfg.HTTPClient != nil {
		hc = *cfg.HTTPClient
		if cfg.RequestTimeout > 0 {
			hc.Timeout = cfg.RequestTimeout
		}
	} else {
		timeout := cfg.RequestTimeout
		if timeout <= 0 {
			timeout = DefaultRequestTimeout
		}
		hc = http.Client{Timeout: timeout}
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &Client{
		baseURL: baseURL, apiKey: strings.Clone(rawKey), httpClient: hc,
		readMaxAttempts: readMax, readRetryBackoff: backoff,
	}, nil
}

func (c Client) String() string               { return redacted }
func (c Client) GoString() string             { return redacted }
func (c Client) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redacted) }
func (c Client) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (c Client) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (c Client) LogValue() slog.Value         { return slog.StringValue(redacted) }

func (c *Client) CreateTemplateSandbox(ctx context.Context, req CreateTemplateSandboxRequest) (*CreateSandboxResult, error) {
	const op = OpCreateTemplateSandbox
	if err := c.checkInitialized(op); err != nil {
		return nil, err
	}
	if req.TemplateID == "" || hasWhitespaceOrControl(req.TemplateID) {
		return nil, invalidArgError(op, "templateID must not be empty or contain whitespace or control characters")
	}
	if req.TimeoutSeconds < minCreateTimeoutSeconds {
		return nil, invalidArgError(op, "timeout must be at least 60 seconds")
	}
	for _, k := range slices.Sorted(maps.Keys(req.Metadata)) {
		v := req.Metadata[k]
		if err := validateMetadataEntry(op, k, &v); err != nil {
			return nil, err
		}
	}
	resp, err := c.doMutation(ctx, op, http.MethodPost, "/sandboxes", http.StatusAccepted, wireCreateTemplateRequest{
		TemplateID: req.TemplateID, Timeout: req.TimeoutSeconds, Metadata: req.Metadata,
	})
	if err != nil {
		return nil, err
	}
	sbx, err := decodeWireSandbox(op, resp)
	if err != nil {
		return nil, err
	}
	return &CreateSandboxResult{
		ID: sbx.ID, Status: sbx.Status, Metadata: sbx.Metadata, Extensions: sbx.Extensions,
		ExpiresAt: sbx.ExpiresAt, CreatedAt: sbx.CreatedAt, Entrypoint: sbx.Entrypoint,
	}, nil
}

func (c *Client) GetSandbox(ctx context.Context, sandboxID string) (*Sandbox, error) {
	const op = OpGetSandbox
	escapedID, err := c.prepareSandboxOp(op, sandboxID)
	if err != nil {
		return nil, err
	}
	resp, err := c.doReadWithRetry(ctx, op, "/sandboxes/"+escapedID)
	if err != nil {
		return nil, err
	}
	return decodeWireSandbox(op, resp)
}

func (c *Client) DeleteSandbox(ctx context.Context, sandboxID string) error {
	const op = OpDeleteSandbox
	escapedID, err := c.prepareSandboxOp(op, sandboxID)
	if err != nil {
		return err
	}
	_, err = c.doMutation(ctx, op, http.MethodDelete, "/sandboxes/"+escapedID, http.StatusNoContent, nil)
	return err
}

func (c *Client) GetEndpoint(ctx context.Context, sandboxID string, port int) (*Endpoint, error) {
	const op = OpGetEndpoint
	escapedID, err := c.prepareSandboxOp(op, sandboxID)
	if err != nil {
		return nil, err
	}
	if port < 1 || port > 65535 {
		return nil, invalidArgError(op, "port must be between 1 and 65535")
	}
	// Never send expires or use_server_proxy query parameters.
	resp, err := c.doReadWithRetry(ctx, op, "/sandboxes/"+escapedID+"/endpoints/"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	var w wireEndpoint
	if err := decodeWireJSON(op, resp, &w); err != nil {
		return nil, err
	}
	if w.Endpoint == "" || hasWhitespaceOrControl(w.Endpoint) {
		return nil, ambiguousBodyError(op, resp, "native: endpoint response missing or invalid endpoint field")
	}
	return &Endpoint{URL: w.Endpoint, Headers: maps.Clone(w.Headers)}, nil
}

func (c *Client) PatchMetadata(ctx context.Context, sandboxID string, patch MetadataPatch) (*Sandbox, error) {
	const op = OpPatchMetadata
	escapedID, err := c.prepareSandboxOp(op, sandboxID)
	if err != nil {
		return nil, err
	}
	if patch == nil {
		return nil, invalidArgError(op, "metadata patch must not be nil")
	}
	for _, k := range slices.Sorted(maps.Keys(patch)) {
		if err := validateMetadataEntry(op, k, patch[k]); err != nil {
			return nil, err
		}
	}
	resp, err := c.doMutation(ctx, op, http.MethodPatch, "/sandboxes/"+escapedID+"/metadata", http.StatusOK, patch)
	if err != nil {
		return nil, err
	}
	return decodeWireSandbox(op, resp)
}

func (c *Client) PauseSandbox(context.Context, string) error  { return ErrNotImplemented }
func (c *Client) ResumeSandbox(context.Context, string) error { return ErrNotImplemented }
func (c *Client) RenewExpiration(context.Context, string, time.Time) (*RenewExpirationResult, error) {
	return nil, ErrNotImplemented
}
func (c *Client) ListSandboxes(context.Context, ListSandboxesRequest) (*ListSandboxesResult, error) {
	return nil, ErrNotImplemented
}

type rawResponse struct {
	statusCode int
	requestID  string
	body       []byte
	tooLarge   bool
	bodyErr    error
}

type wireCreateTemplateRequest struct {
	TemplateID string            `json:"templateId"`
	Timeout    int64             `json:"timeout"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type wireSandbox struct {
	ID     string `json:"id"`
	Status struct {
		State            string     `json:"state"`
		Reason           string     `json:"reason"`
		Message          string     `json:"message"`
		LastTransitionAt *time.Time `json:"lastTransitionAt"`
	} `json:"status"`
	Metadata   map[string]string `json:"metadata"`
	Extensions map[string]string `json:"extensions"`
	ExpiresAt  *time.Time        `json:"expiresAt"`
	CreatedAt  *time.Time        `json:"createdAt"`
	Entrypoint []string          `json:"entrypoint"`
}

type wireEndpoint struct {
	Endpoint string            `json:"endpoint"`
	Headers  map[string]string `json:"headers"`
}

type wireErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// doMutation executes a single non-retried mutation request.
func (c *Client) doMutation(ctx context.Context, op, method, path string, wantStatus int, bodyObj any) (*rawResponse, error) {
	var payload []byte
	if bodyObj != nil {
		var err error
		payload, err = json.Marshal(bodyObj)
		if err != nil {
			return nil, wrapInvalidArg(op, err)
		}
	}
	resp, err := c.sendRequest(ctx, method, path, payload)
	if err != nil {
		return nil, &CallError{Operation: op, Outcome: OutcomeAmbiguous, Cause: err}
	}
	if resp.bodyErr != nil {
		if isDefiniteFailureStatus(resp.statusCode) {
			return nil, buildErrorCallError(op, OutcomeDefiniteFailure, resp)
		}
		return nil, &CallError{Operation: op, Outcome: OutcomeAmbiguous, HTTPStatus: resp.statusCode, RequestID: resp.requestID, Cause: resp.bodyErr}
	}
	if resp.statusCode != wantStatus {
		if isDefiniteFailureStatus(resp.statusCode) {
			return nil, buildErrorCallError(op, OutcomeDefiniteFailure, resp)
		}
		return nil, buildErrorCallError(op, OutcomeAmbiguous, resp)
	}
	return resp, nil
}

func (c *Client) doReadWithRetry(ctx context.Context, op, path string) (*rawResponse, error) {
	if ctx == nil {
		return nil, &CallError{Operation: op, Outcome: OutcomeAmbiguous, Cause: errors.New("native: nil context")}
	}
	var lastErr *CallError
	for attempt := 1; attempt <= c.readMaxAttempts; attempt++ {
		resp, err := c.sendRequest(ctx, http.MethodGet, path, nil)
		retryable := false
		switch {
		case err != nil:
			lastErr = &CallError{Operation: op, Outcome: OutcomeAmbiguous, Cause: err}
			retryable = true
		case isDefiniteFailureStatus(resp.statusCode):
			return nil, buildErrorCallError(op, OutcomeDefiniteFailure, resp)
		case resp.statusCode == http.StatusOK && resp.bodyErr == nil:
			return resp, nil
		case resp.statusCode == http.StatusOK:
			lastErr = &CallError{Operation: op, Outcome: OutcomeAmbiguous, HTTPStatus: resp.statusCode, RequestID: resp.requestID, Cause: resp.bodyErr}
			retryable = true
		default:
			lastErr = buildErrorCallError(op, OutcomeAmbiguous, resp)
			retryable = isRetryableReadStatus(resp.statusCode)
		}
		if !retryable || attempt >= c.readMaxAttempts || ctx.Err() != nil {
			return nil, lastErr
		}
		if sleepErr := c.sleepBackoff(ctx); sleepErr != nil {
			return nil, &CallError{Operation: op, Outcome: OutcomeAmbiguous, Cause: sleepErr}
		}
	}
	return nil, lastErr
}

func (c *Client) sendRequest(ctx context.Context, method, path string, payload []byte) (*rawResponse, error) {
	if ctx == nil {
		return nil, errors.New("native: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, errors.New("native: failed to build request")
	}
	if method != http.MethodGet {
		req.GetBody = nil
	}
	req.Header.Set(apiKeyHeader, c.apiKey)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, sanitizeTransportError(err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainBodyBytes))
		_ = resp.Body.Close()
	}()

	limited, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	out := &rawResponse{statusCode: resp.StatusCode, requestID: resp.Header.Get(requestIDHeader)}
	if readErr != nil {
		out.bodyErr = sanitizeTransportError(readErr)
	} else if len(limited) > maxResponseBodyBytes {
		out.tooLarge, out.body = true, limited[:maxResponseBodyBytes]
	} else {
		out.body = limited
	}
	return out, nil
}

func (c *Client) sleepBackoff(ctx context.Context) error {
	if c.readRetryBackoff <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(c.readRetryBackoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) checkInitialized(op string) error {
	if c == nil || c.baseURL == "" || c.apiKey == "" || c.readMaxAttempts <= 0 {
		return invalidArgError(op, "client is not initialized")
	}
	return nil
}

func (c *Client) prepareSandboxOp(op, sandboxID string) (string, error) {
	if err := c.checkInitialized(op); err != nil {
		return "", err
	}
	if sandboxID == "" || sandboxID == "." || sandboxID == ".." ||
		strings.ContainsAny(sandboxID, "/\\?#") || hasWhitespaceOrControl(sandboxID) {
		return "", invalidArgError(op, "invalid sandboxID")
	}
	return url.PathEscape(sandboxID), nil
}

func decodeWireJSON(op string, resp *rawResponse, dst any) error {
	if resp.tooLarge {
		return ambiguousBodyError(op, resp, "native: response body exceeds maximum size")
	}
	if err := json.Unmarshal(resp.body, dst); err != nil {
		return ambiguousBodyError(op, resp, "native: malformed JSON response")
	}
	return nil
}

func decodeWireSandbox(op string, resp *rawResponse) (*Sandbox, error) {
	var w wireSandbox
	if err := decodeWireJSON(op, resp, &w); err != nil {
		return nil, err
	}
	if w.ID == "" || hasWhitespaceOrControl(w.ID) || w.Status.State == "" || hasWhitespaceOrControl(w.Status.State) {
		return nil, ambiguousBodyError(op, resp, "native: sandbox response missing or invalid required id or status.state")
	}
	var createdAt time.Time
	if w.CreatedAt != nil {
		createdAt = *w.CreatedAt
	}
	return &Sandbox{
		ID: w.ID,
		Status: SandboxStatus{
			State: ParseState(w.Status.State), RawState: w.Status.State,
			Reason: w.Status.Reason, Message: w.Status.Message, LastTransitionAt: w.Status.LastTransitionAt,
		},
		Metadata: maps.Clone(w.Metadata), Extensions: maps.Clone(w.Extensions),
		ExpiresAt: w.ExpiresAt, CreatedAt: createdAt, Entrypoint: slices.Clone(w.Entrypoint),
	}, nil
}

func ambiguousBodyError(op string, resp *rawResponse, msg string) error {
	return &CallError{Operation: op, Outcome: OutcomeAmbiguous, HTTPStatus: resp.statusCode, RequestID: resp.requestID, Cause: errors.New(msg)}
}

func buildErrorCallError(op string, outcome OutcomeClass, resp *rawResponse) *CallError {
	ce := &CallError{Operation: op, Outcome: outcome, HTTPStatus: resp.statusCode, RequestID: resp.requestID}
	if !resp.tooLarge && len(resp.body) > 0 {
		var we wireErrorResponse
		if json.Unmarshal(resp.body, &we) == nil {
			ce.NativeCode, ce.NativeMessage = we.Code, we.Message
		}
	}
	return ce
}

func isDefiniteFailureStatus(status int) bool {
	return status >= 400 && status < 500 && status != http.StatusRequestTimeout
}

func isRetryableReadStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func sanitizeTransportError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Err != nil {
			return ue.Err
		}
		return errors.New("native: transport error")
	}
	return err
}

func validateBaseURL(raw string) (string, error) {
	bad := func(msg string) (string, error) { return "", fmt.Errorf("%w: base_url %s", ErrInvalidArgument, msg) }
	if raw == "" || hasWhitespaceOrControl(raw) {
		return bad("must not be empty or contain whitespace or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return bad("is not a valid URL")
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return bad("scheme must be http or https")
	case u.Opaque != "":
		return bad("must be a hierarchical URL")
	case u.User != nil:
		return bad("must not contain user info")
	case u.Host == "" || u.Hostname() == "":
		return bad("must have a host")
	case u.RawQuery != "" || u.ForceQuery:
		return bad("must not contain a query")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return bad("must not contain a fragment")
	case strings.Contains(u.Path, "\\"):
		return bad("must not contain backslashes")
	}
	if port := u.Port(); port != "" || strings.HasSuffix(u.Host, ":") {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return bad("port must be between 1 and 65535")
		}
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return bad("must not contain '.' or '..' segments")
		}
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func validateMetadataEntry(op, key string, val *string) error {
	var err error
	if strings.HasPrefix(key, rules.MetadataReservedPrefix) {
		if len(key) > rules.MaxLabelLength {
			err = rules.ErrInvalidMetadataKey
		} else {
			err = rules.ValidateMetadataKey("a-" + strings.TrimPrefix(key, rules.MetadataReservedPrefix))
		}
	} else {
		err = rules.ValidateMetadataKey(key)
	}
	if err == nil && val != nil {
		err = rules.ValidateLabelValue(*val)
	}
	if err != nil {
		return wrapInvalidArg(op, err)
	}
	return nil
}

func hasWhitespaceOrControl(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

func invalidArgError(op, msg string) error {
	return &CallError{Operation: op, Outcome: OutcomeDefiniteFailure, Cause: fmt.Errorf("%w: %s", ErrInvalidArgument, msg)}
}

func wrapInvalidArg(op string, err error) error {
	return &CallError{Operation: op, Outcome: OutcomeDefiniteFailure, Cause: fmt.Errorf("%w: %w", ErrInvalidArgument, err)}
}
