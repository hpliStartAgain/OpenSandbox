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

package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
)

const maxDurationSeconds = math.MaxInt64 / int64(time.Second)

type TimeoutOperation string

const (
	TimeoutOpCreate         TimeoutOperation = "create"
	TimeoutOpConnectRunning TimeoutOperation = "connect_running"
	TimeoutOpConnectPaused  TimeoutOperation = "connect_paused"
	TimeoutOpSetTimeout     TimeoutOperation = "set_timeout"
)

type TimeoutMode string

const (
	TimeoutModeCreate                TimeoutMode = "create"
	TimeoutModeExtendOnly            TimeoutMode = "extend_only"
	TimeoutModeResetFromAttemptStart TimeoutMode = "reset_from_attempt_start"
	TimeoutModeReplaceDeadline       TimeoutMode = "replace_deadline"
)

type TimeoutPolicy struct {
	DefaultSeconds int64
	MinSeconds     int64
	MaxSeconds     int64
}

type TimeoutDecision struct {
	EffectiveSeconds int64
	Mode             TimeoutMode
}

var (
	ErrTimeoutInvalidPolicy   = errors.New("rules: invalid timeout policy")
	ErrTimeoutMissing         = errors.New("rules: timeout is required")
	ErrTimeoutInvalidType     = errors.New("rules: timeout must be a JSON integer")
	ErrTimeoutNonPositive     = errors.New("rules: timeout must be positive")
	ErrTimeoutBelowMin        = errors.New("rules: timeout is below profile minimum")
	ErrTimeoutExceedsMax      = errors.New("rules: timeout exceeds maximum")
	ErrTimeoutZeroUnsupported = errors.New("rules: zero timeout is unsupported")
	ErrTimeoutDeadlinePast    = errors.New("rules: computed timeout deadline is not in the future")
)

func EvaluateTimeout(op TimeoutOperation, present bool, raw json.RawMessage, policy TimeoutPolicy) (TimeoutDecision, error) {
	switch op {
	case TimeoutOpCreate, TimeoutOpConnectRunning, TimeoutOpConnectPaused, TimeoutOpSetTimeout:
	default:
		return TimeoutDecision{}, fmt.Errorf("%w: unknown timeout operation", ErrTimeoutInvalidPolicy)
	}
	if policy.MinSeconds < 1 || policy.MaxSeconds < policy.MinSeconds || policy.MaxSeconds > maxDurationSeconds {
		return TimeoutDecision{}, ErrTimeoutInvalidPolicy
	}

	seconds := policy.DefaultSeconds
	if !present {
		if op == TimeoutOpSetTimeout {
			return TimeoutDecision{}, ErrTimeoutMissing
		}
	} else {
		n, err := parseStrictJSONInt64(raw)
		if err != nil {
			return TimeoutDecision{}, err
		}
		seconds = n
	}

	switch op {
	case TimeoutOpCreate:
		if seconds <= 0 {
			return TimeoutDecision{}, ErrTimeoutNonPositive
		}
		if seconds < policy.MinSeconds {
			return TimeoutDecision{}, ErrTimeoutBelowMin
		}
		if seconds > policy.MaxSeconds {
			return TimeoutDecision{}, ErrTimeoutExceedsMax
		}
		return TimeoutDecision{EffectiveSeconds: seconds, Mode: TimeoutModeCreate}, nil
	case TimeoutOpConnectRunning, TimeoutOpConnectPaused:
		if seconds <= 0 {
			return TimeoutDecision{}, ErrTimeoutNonPositive
		}
		if seconds > policy.MaxSeconds {
			return TimeoutDecision{}, ErrTimeoutExceedsMax
		}
		mode := TimeoutModeExtendOnly
		if op == TimeoutOpConnectPaused {
			mode = TimeoutModeResetFromAttemptStart
		}
		return TimeoutDecision{EffectiveSeconds: seconds, Mode: mode}, nil
	default: // TimeoutOpSetTimeout
		if seconds < 0 {
			return TimeoutDecision{}, ErrTimeoutNonPositive
		}
		if seconds == 0 {
			return TimeoutDecision{}, ErrTimeoutZeroUnsupported
		}
		if seconds > policy.MaxSeconds {
			return TimeoutDecision{}, ErrTimeoutExceedsMax
		}
		return TimeoutDecision{EffectiveSeconds: seconds, Mode: TimeoutModeReplaceDeadline}, nil
	}
}

func ComputeDeadline(now time.Time, seconds int64) (time.Time, error) {
	if seconds <= 0 {
		return time.Time{}, ErrTimeoutNonPositive
	}
	if seconds > maxDurationSeconds {
		return time.Time{}, fmt.Errorf("%w: exceeds maximum representable time.Duration", ErrTimeoutExceedsMax)
	}
	return now.UTC().Add(time.Duration(seconds) * time.Second), nil
}

func ExtendDeadline(now, currentExpiresAt time.Time, seconds int64) (time.Time, bool, error) {
	candidate, err := ComputeDeadline(now, seconds)
	if err != nil {
		return time.Time{}, false, err
	}
	if candidate.After(currentExpiresAt) {
		return candidate, true, nil
	}
	return currentExpiresAt.UTC(), false, nil
}

func ValidateFutureDeadline(deadline, now time.Time) error {
	if !deadline.After(now) {
		return ErrTimeoutDeadlinePast
	}
	return nil
}

func trimJSONSpace(b []byte) []byte {
	return bytes.Trim(b, " \t\n\r")
}

func parseStrictJSONInt64(raw json.RawMessage) (int64, error) {
	trimmed := trimJSONSpace(raw)
	if len(trimmed) == 0 {
		return 0, ErrTimeoutInvalidType
	}
	digits := trimmed
	if digits[0] == '-' {
		digits = digits[1:]
	}
	if len(digits) == 0 || (len(digits) > 1 && digits[0] == '0') {
		return 0, ErrTimeoutInvalidType
	}
	for _, b := range digits {
		if b < '0' || b > '9' {
			return 0, ErrTimeoutInvalidType
		}
	}
	n, err := strconv.ParseInt(string(trimmed), 10, 64)
	if err != nil {
		return 0, ErrTimeoutInvalidType
	}
	return n, nil
}
