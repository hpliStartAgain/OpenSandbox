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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"unicode"
)

type OutcomeClass string

const (
	OutcomeSuccess         OutcomeClass = "success"
	OutcomeDefiniteFailure OutcomeClass = "definite_failure"
	OutcomeAmbiguous       OutcomeClass = "ambiguous"
)

const (
	OpCreateTemplateSandbox = "create_template_sandbox"
	OpGetSandbox            = "get_sandbox"
	OpDeleteSandbox         = "delete_sandbox"
	OpGetEndpoint           = "get_endpoint"
	OpPatchMetadata         = "patch_metadata"
)

var (
	ErrNotImplemented  = errors.New("native: operation not implemented")
	ErrInvalidArgument = errors.New("native: invalid argument")
)

type CallError struct {
	Operation     string
	Outcome       OutcomeClass
	HTTPStatus    int
	NativeCode    string
	NativeMessage string
	RequestID     string
	Cause         error
}

func (e *CallError) Error() string {
	if e == nil {
		return "native unknown: ambiguous"
	}
	return e.summary()
}

func (e CallError) summary() string {
	op := sanitizeToken(e.Operation)
	if op == "" {
		op = "unknown"
	}
	outcome := normalizeOutcome(e.Outcome)
	var parts []string
	if e.HTTPStatus > 0 {
		parts = append(parts, fmt.Sprintf("status=%d", e.HTTPStatus))
	}
	if code := sanitizeToken(e.NativeCode); code != "" {
		parts = append(parts, "code="+code)
	}
	if reqID := sanitizeToken(e.RequestID); reqID != "" {
		parts = append(parts, "request_id="+reqID)
	}
	if e.HTTPStatus == 0 && e.Cause != nil {
		parts = append(parts, "reason="+classifyCauseLabel(e.Cause))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("native %s: %s", op, outcome)
	}
	return fmt.Sprintf("native %s: %s (%s)", op, outcome, strings.Join(parts, ", "))
}

func (e CallError) GoString() string             { return e.summary() }
func (e CallError) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, e.summary()) }
func (e CallError) MarshalText() ([]byte, error) { return []byte(e.summary()), nil }

func (e CallError) MarshalJSON() ([]byte, error) {
	op := sanitizeToken(e.Operation)
	if op == "" {
		op = "unknown"
	}
	var msg, reason string
	if e.NativeMessage != "" {
		msg = redacted
	}
	if e.HTTPStatus == 0 && e.Cause != nil {
		reason = classifyCauseLabel(e.Cause)
	}
	return json.Marshal(struct {
		Operation     string       `json:"operation"`
		Outcome       OutcomeClass `json:"outcome"`
		HTTPStatus    int          `json:"http_status,omitempty"`
		NativeCode    string       `json:"native_code,omitempty"`
		NativeMessage string       `json:"native_message,omitempty"`
		RequestID     string       `json:"request_id,omitempty"`
		Reason        string       `json:"reason,omitempty"`
	}{
		Operation:     op,
		Outcome:       normalizeOutcome(e.Outcome),
		HTTPStatus:    e.HTTPStatus,
		NativeCode:    sanitizeToken(e.NativeCode),
		NativeMessage: msg,
		RequestID:     sanitizeToken(e.RequestID),
		Reason:        reason,
	})
}

func (e CallError) LogValue() slog.Value {
	op := sanitizeToken(e.Operation)
	if op == "" {
		op = "unknown"
	}
	attrs := []slog.Attr{
		slog.String("operation", op),
		slog.String("outcome", string(normalizeOutcome(e.Outcome))),
	}
	if e.HTTPStatus > 0 {
		attrs = append(attrs, slog.Int("http_status", e.HTTPStatus))
	}
	if code := sanitizeToken(e.NativeCode); code != "" {
		attrs = append(attrs, slog.String("native_code", code))
	}
	if e.NativeMessage != "" {
		attrs = append(attrs, slog.String("native_message", redacted))
	}
	if reqID := sanitizeToken(e.RequestID); reqID != "" {
		attrs = append(attrs, slog.String("request_id", reqID))
	}
	if e.HTTPStatus == 0 && e.Cause != nil {
		attrs = append(attrs, slog.String("reason", classifyCauseLabel(e.Cause)))
	}
	return slog.GroupValue(attrs...)
}

func (e *CallError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func ClassifyError(err error) OutcomeClass {
	if err == nil {
		return OutcomeSuccess
	}
	var ce *CallError
	if errors.As(err, &ce) && ce != nil {
		return normalizeOutcome(ce.Outcome)
	}
	if errors.Is(err, ErrInvalidArgument) {
		return OutcomeDefiniteFailure
	}
	return OutcomeAmbiguous
}

func IsAmbiguous(err error) bool { return err != nil && ClassifyError(err) == OutcomeAmbiguous }
func IsDefiniteFailure(err error) bool {
	return err != nil && ClassifyError(err) == OutcomeDefiniteFailure
}

func IsNotFound(err error) bool {
	var ce *CallError
	return errors.As(err, &ce) && ce != nil && ce.Outcome == OutcomeDefiniteFailure && ce.HTTPStatus == http.StatusNotFound
}

func IsConflict(err error) bool {
	var ce *CallError
	return errors.As(err, &ce) && ce != nil && ce.Outcome == OutcomeDefiniteFailure && ce.HTTPStatus == http.StatusConflict
}

func normalizeOutcome(o OutcomeClass) OutcomeClass {
	if o == OutcomeSuccess || o == OutcomeDefiniteFailure || o == OutcomeAmbiguous {
		return o
	}
	return OutcomeAmbiguous
}

func classifyCauseLabel(err error) string {
	switch {
	case errors.Is(err, ErrInvalidArgument):
		return "invalid_argument"
	case errors.Is(err, context.Canceled):
		return "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	default:
		return "transport_error"
	}
}

func sanitizeToken(s string) string {
	const maxLen = 128
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxLen {
			break
		}
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			b.WriteByte('_')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
