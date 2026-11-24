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

// Package rules implements pure, deterministic OSEP-0027 validation, metadata,
// timeout, template catalog, and HMAC token derivation rules.
package rules

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
)

const (
	EnvdTokenDomainV1 = "opensandbox-e2b-shim/envd-token/v1"
	redacted          = "[REDACTED]"
)

var ErrInvalidTokenInput = errors.New("rules: invalid token input")

// TokenDeriver derives and verifies per-sandbox envd access tokens from a
// protected HMAC key. All formatting paths redact internal state.
type TokenDeriver struct {
	key        []byte
	keyVersion string
	adapterID  string
}

func NewTokenDeriver(hmacKey config.Secret, keyVersion, adapterID string) (*TokenDeriver, error) {
	if hmacKey.IsZero() {
		return nil, fmt.Errorf("%w: hmac key is empty", ErrInvalidTokenInput)
	}
	if err := ValidateLabelValue(keyVersion); err != nil {
		return nil, fmt.Errorf("%w: invalid hmac key version", ErrInvalidTokenInput)
	}
	if err := ValidateLabelValue(adapterID); err != nil {
		return nil, fmt.Errorf("%w: invalid adapter ID", ErrInvalidTokenInput)
	}
	raw := hmacKey.Reveal()
	keyCopy := make([]byte, len(raw))
	copy(keyCopy, raw)
	return &TokenDeriver{
		key:        keyCopy,
		keyVersion: keyVersion,
		adapterID:  adapterID,
	}, nil
}

func (d TokenDeriver) String() string               { return redacted }
func (d TokenDeriver) GoString() string             { return redacted }
func (d TokenDeriver) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redacted) }
func (d TokenDeriver) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (d TokenDeriver) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (d TokenDeriver) LogValue() slog.Value         { return slog.StringValue(redacted) }

func (d *TokenDeriver) Derive(nativeSandboxID string) (string, error) {
	if d == nil || len(d.key) == 0 || d.keyVersion == "" || d.adapterID == "" {
		return "", fmt.Errorf("%w: token deriver is not initialized", ErrInvalidTokenInput)
	}
	if nativeSandboxID == "" || hasWhitespaceOrControl(nativeSandboxID) {
		return "", fmt.Errorf("%w: invalid sandbox ID", ErrInvalidTokenInput)
	}
	mac := hmac.New(sha256.New, d.key)
	_, _ = mac.Write([]byte(EnvdTokenDomainV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(d.keyVersion))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(d.adapterID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(nativeSandboxID))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (d *TokenDeriver) Verify(nativeSandboxID, presentedToken string) (bool, error) {
	expected, err := d.Derive(nativeSandboxID)
	if err != nil {
		return false, err
	}
	if presentedToken == "" {
		return false, nil
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presentedToken)) == 1, nil
}

func hasWhitespaceOrControl(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

// ValidSandboxID applies the shared adapter/router sandbox selector rules.
func ValidSandboxID(id string) bool {
	return id != "" && id != "." && id != ".." && !strings.ContainsAny(id, "/\\?#") && !hasWhitespaceOrControl(id)
}
