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

// Package envdinit bootstraps new envd instances through trusted native routes.
// It must not be used to initialize a restored same-instance checkpoint.
package envdinit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/adapter"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/native"
)

const (
	DefaultRequestTimeout = 15 * time.Second
	maxDrainBytes         = 4 << 10
	accessTokenHeader     = "X-Access-Token"
)

var (
	ErrDefiniteFailure = errors.New("envdinit: definite failure")
	ErrAmbiguous       = errors.New("envdinit: ambiguous outcome")
)

// ClassifyError has the same outcome vocabulary as the native client. No error
// retains upstream bodies, headers, URLs, or the original transport error.
func ClassifyError(err error) native.OutcomeClass {
	if err == nil {
		return native.OutcomeSuccess
	}
	if errors.Is(err, ErrDefiniteFailure) {
		return native.OutcomeDefiniteFailure
	}
	return native.OutcomeAmbiguous
}

type Initializer struct{ client *http.Client }

var _ adapter.EnvdInitializer = (*Initializer)(nil)

// New copies the client, enforces no redirects/cookies and a finite timeout.
// Standard transports are cloned without keep-alives so net/http cannot replay
// a request on a stale pooled connection. Custom transports must not retry.
func New(client *http.Client) *Initializer {
	c := http.Client{Timeout: DefaultRequestTimeout}
	if client != nil {
		c = *client
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultRequestTimeout
	}
	c.Jar = nil
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	transport := c.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if t, ok := transport.(*http.Transport); ok {
		cloned := t.Clone()
		cloned.DisableKeepAlives = true
		c.Transport = cloned
	}
	return &Initializer{client: &c}
}

func (i Initializer) String() string             { return "envdinit.Initializer{[REDACTED]}" }
func (i Initializer) GoString() string           { return i.String() }
func (i Initializer) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, i.String()) }

func (i *Initializer) Initialize(ctx context.Context, req adapter.EnvdInitRequest) (*adapter.EnvdInitResult, error) {
	if i == nil || i.client == nil || ctx == nil || req.Endpoint == nil || req.AccessToken == "" || req.ExpectedEnvdVersion == "" {
		return nil, fmt.Errorf("%w: invalid request", ErrDefiniteFailure)
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ErrDefiniteFailure, ctx.Err())
	}
	if !config.ValidDefaultUser(req.DefaultUser) {
		return nil, fmt.Errorf("%w: invalid default user", ErrDefiniteFailure)
	}
	base, err := url.Parse(req.Endpoint.URL)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") || base.User != nil || base.Fragment != "" || base.Opaque != "" {
		return nil, fmt.Errorf("%w: invalid endpoint", ErrDefiniteFailure)
	}
	payload, err := json.Marshal(struct {
		DefaultUser string            `json:"defaultUser"`
		AccessToken string            `json:"accessToken"`
		EnvVars     map[string]string `json:"envVars,omitempty"`
	}{req.DefaultUser, req.AccessToken, req.EnvVars})
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload", ErrDefiniteFailure)
	}
	// Construct all target requests before sending /init.
	build := func(method, path string, body io.Reader, token string) (*http.Request, error) {
		target := *base
		target.Path = strings.TrimRight(base.Path, "/") + path
		if base.RawPath != "" {
			target.RawPath = strings.TrimRight(base.EscapedPath(), "/") + path
		}
		r, e := http.NewRequestWithContext(ctx, method, target.String(), body)
		if e != nil {
			return nil, fmt.Errorf("%w: invalid request", ErrDefiniteFailure)
		}
		for k, v := range req.Endpoint.Headers {
			if strings.EqualFold(k, "Host") {
				r.Host = v
			} else {
				r.Header.Set(k, v)
			}
		}
		// Native routing credentials are separate from envd authentication.
		r.Header.Del(accessTokenHeader)
		if token != "" {
			r.Header.Set(accessTokenHeader, token)
		}
		r.GetBody = nil // Never make /init replayable.
		return r, nil
	}
	initReq, err := build(http.MethodPost, "/init", bytes.NewReader(payload), "")
	if err != nil {
		return nil, err
	}
	initReq.Header.Set("Content-Type", "application/json")
	probe, err := build(http.MethodGet, "/metrics", nil, req.AccessToken)
	if err != nil {
		return nil, err
	}
	unauthProbe, err := build(http.MethodGet, "/metrics", nil, "")
	if err != nil {
		return nil, err
	}
	status, version, defaults, err := i.call(initReq)
	if err != nil {
		return nil, err
	}
	if status != http.StatusNoContent {
		return nil, fmt.Errorf("%w: init rejected", ErrDefiniteFailure)
	}
	// Verify defaults before version and authentication probes.
	var effective struct {
		User     string
		Fallback *bool
	}
	if json.Unmarshal([]byte(defaults), &effective) != nil || effective.User != req.DefaultUser || effective.Fallback == nil || *effective.Fallback {
		return nil, fmt.Errorf("%w: invalid effective defaults", ErrDefiniteFailure)
	}
	if version != req.ExpectedEnvdVersion {
		return nil, fmt.Errorf("%w: version mismatch", ErrDefiniteFailure)
	}
	status, _, _, err = i.call(probe)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: authenticated probe rejected", ErrDefiniteFailure)
	}
	status, _, _, err = i.call(unauthProbe)
	if err != nil {
		return nil, err
	}
	if status != http.StatusUnauthorized {
		return nil, fmt.Errorf("%w: authentication not proven", ErrDefiniteFailure)
	}
	return &adapter.EnvdInitResult{EnvdVersion: version}, nil
}

func (i *Initializer) call(req *http.Request) (int, string, string, error) {
	resp, err := i.client.Do(req)
	if err != nil {
		// In particular, *url.Error contains the private URL. Never wrap it.
		return 0, "", "", ErrAmbiguous
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes)); err != nil {
		return 0, "", "", ErrAmbiguous
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500 {
		return 0, "", "", ErrAmbiguous
	}
	return resp.StatusCode, resp.Header.Get("X-Envd-Version"), resp.Header.Get("X-Envd-Defaults"), nil
}
