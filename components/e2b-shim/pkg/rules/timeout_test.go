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

package rules_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
)

func TestEvaluateTimeoutSemanticsMatrix(t *testing.T) {
	p := defaultProfileTimeout() // Default: 300, Min: 60, Max: 3600
	cases := []struct {
		name     string
		op       rules.TimeoutOperation
		present  bool
		raw      string
		policy   rules.TimeoutPolicy
		wantSecs int64
		wantMode rules.TimeoutMode
		wantErr  error
	}{
		{"create omitted uses 300s default", rules.TimeoutOpCreate, false, "", p, 300, rules.TimeoutModeCreate, nil},
		{"create omitted default exceeds max", rules.TimeoutOpCreate, false, "", rules.TimeoutPolicy{DefaultSeconds: 300, MinSeconds: 60, MaxSeconds: 120}, 0, "", rules.ErrTimeoutExceedsMax},
		{"create omitted default below min", rules.TimeoutOpCreate, false, "", rules.TimeoutPolicy{DefaultSeconds: 30, MinSeconds: 60, MaxSeconds: 3600}, 0, "", rules.ErrTimeoutBelowMin},
		{"create omitted default non-positive", rules.TimeoutOpCreate, false, "", rules.TimeoutPolicy{DefaultSeconds: 0, MinSeconds: 60, MaxSeconds: 3600}, 0, "", rules.ErrTimeoutNonPositive},
		{"connect running omitted uses 300s", rules.TimeoutOpConnectRunning, false, "", p, 300, rules.TimeoutModeExtendOnly, nil},
		{"connect running omitted exceeds max", rules.TimeoutOpConnectRunning, false, "", rules.TimeoutPolicy{DefaultSeconds: 500, MinSeconds: 60, MaxSeconds: 300}, 0, "", rules.ErrTimeoutExceedsMax},
		{"connect paused omitted uses 300s", rules.TimeoutOpConnectPaused, false, "", p, 300, rules.TimeoutModeResetFromAttemptStart, nil},
		{"connect paused omitted exceeds max", rules.TimeoutOpConnectPaused, false, "", rules.TimeoutPolicy{DefaultSeconds: 500, MinSeconds: 60, MaxSeconds: 300}, 0, "", rules.ErrTimeoutExceedsMax},
		{"set timeout omitted rejected", rules.TimeoutOpSetTimeout, false, "", p, 0, "", rules.ErrTimeoutMissing},

		{"create -1", rules.TimeoutOpCreate, true, "-1", p, 0, "", rules.ErrTimeoutNonPositive},
		{"create 0", rules.TimeoutOpCreate, true, "0", p, 0, "", rules.ErrTimeoutNonPositive},
		{"create 1 below min", rules.TimeoutOpCreate, true, "1", p, 0, "", rules.ErrTimeoutBelowMin},
		{"create 59 below min", rules.TimeoutOpCreate, true, "59", p, 0, "", rules.ErrTimeoutBelowMin},
		{"create 60 at min", rules.TimeoutOpCreate, true, "60", p, 60, rules.TimeoutModeCreate, nil},
		{"create 300 with JSON whitespace", rules.TimeoutOpCreate, true, " \n\t300\r ", p, 300, rules.TimeoutModeCreate, nil},
		{"create max 3600", rules.TimeoutOpCreate, true, "3600", p, 3600, rules.TimeoutModeCreate, nil},
		{"create max+1 3601", rules.TimeoutOpCreate, true, "3601", p, 0, "", rules.ErrTimeoutExceedsMax},

		{"connect running -1", rules.TimeoutOpConnectRunning, true, "-1", p, 0, "", rules.ErrTimeoutNonPositive},
		{"connect running 0", rules.TimeoutOpConnectRunning, true, "0", p, 0, "", rules.ErrTimeoutNonPositive},
		{"connect running 1", rules.TimeoutOpConnectRunning, true, "1", p, 1, rules.TimeoutModeExtendOnly, nil},
		{"connect running 30", rules.TimeoutOpConnectRunning, true, "30", p, 30, rules.TimeoutModeExtendOnly, nil},
		{"connect running 300", rules.TimeoutOpConnectRunning, true, "300", p, 300, rules.TimeoutModeExtendOnly, nil},
		{"connect running max 3600", rules.TimeoutOpConnectRunning, true, "3600", p, 3600, rules.TimeoutModeExtendOnly, nil},
		{"connect running max+1 3601", rules.TimeoutOpConnectRunning, true, "3601", p, 0, "", rules.ErrTimeoutExceedsMax},

		{"connect paused -1", rules.TimeoutOpConnectPaused, true, "-1", p, 0, "", rules.ErrTimeoutNonPositive},
		{"connect paused 0", rules.TimeoutOpConnectPaused, true, "0", p, 0, "", rules.ErrTimeoutNonPositive},
		{"connect paused 1", rules.TimeoutOpConnectPaused, true, "1", p, 1, rules.TimeoutModeResetFromAttemptStart, nil},
		{"connect paused 30", rules.TimeoutOpConnectPaused, true, "30", p, 30, rules.TimeoutModeResetFromAttemptStart, nil},
		{"connect paused 300", rules.TimeoutOpConnectPaused, true, "300", p, 300, rules.TimeoutModeResetFromAttemptStart, nil},
		{"connect paused max 3600", rules.TimeoutOpConnectPaused, true, "3600", p, 3600, rules.TimeoutModeResetFromAttemptStart, nil},
		{"connect paused max+1 3601", rules.TimeoutOpConnectPaused, true, "3601", p, 0, "", rules.ErrTimeoutExceedsMax},

		{"set timeout -1", rules.TimeoutOpSetTimeout, true, "-1", p, 0, "", rules.ErrTimeoutNonPositive},
		{"set timeout 0 unsupported", rules.TimeoutOpSetTimeout, true, "0", p, 0, "", rules.ErrTimeoutZeroUnsupported},
		{"set timeout 1", rules.TimeoutOpSetTimeout, true, "1", p, 1, rules.TimeoutModeReplaceDeadline, nil},
		{"set timeout 30", rules.TimeoutOpSetTimeout, true, "30", p, 30, rules.TimeoutModeReplaceDeadline, nil},
		{"set timeout max 3600", rules.TimeoutOpSetTimeout, true, "3600", p, 3600, rules.TimeoutModeReplaceDeadline, nil},
		{"set timeout max+1 3601", rules.TimeoutOpSetTimeout, true, "3601", p, 0, "", rules.ErrTimeoutExceedsMax},

		{"unknown op", "bogus", true, "60", p, 0, "", rules.ErrTimeoutInvalidPolicy},
		{"invalid policy min < 1", rules.TimeoutOpCreate, true, "60", rules.TimeoutPolicy{MinSeconds: 0, MaxSeconds: 3600}, 0, "", rules.ErrTimeoutInvalidPolicy},
		{"invalid policy max < min", rules.TimeoutOpCreate, true, "60", rules.TimeoutPolicy{MinSeconds: 120, MaxSeconds: 60}, 0, "", rules.ErrTimeoutInvalidPolicy},
		{"invalid policy max overflow", rules.TimeoutOpCreate, true, "60", rules.TimeoutPolicy{MinSeconds: 60, MaxSeconds: 9223372037}, 0, "", rules.ErrTimeoutInvalidPolicy},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := rules.EvaluateTimeout(tc.op, tc.present, json.RawMessage(tc.raw), tc.policy)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil || got.EffectiveSeconds != tc.wantSecs || got.Mode != tc.wantMode {
				t.Fatalf("got (%+v, %v), want (%d, %q, nil)", got, err, tc.wantSecs, tc.wantMode)
			}
		})
	}
}

func TestEvaluateTimeoutRejectsNonIntegerTokensAcrossAllOperations(t *testing.T) {
	p := defaultProfileTimeout()
	ops := []rules.TimeoutOperation{rules.TimeoutOpCreate, rules.TimeoutOpConnectRunning, rules.TimeoutOpConnectPaused, rules.TimeoutOpSetTimeout}
	badTokens := []string{"null", "true", "false", "60.5", "60.0", "1e2", "1E2", `"60"`, "{}", "[]", "", "+60", "060", "-", "99999999999999999999999", "-99999999999999999999999"}
	for _, op := range ops {
		for _, raw := range badTokens {
			if _, err := rules.EvaluateTimeout(op, true, json.RawMessage(raw), p); !errors.Is(err, rules.ErrTimeoutInvalidType) {
				t.Errorf("EvaluateTimeout(%s, %q) err = %v, want ErrTimeoutInvalidType", op, raw, err)
			}
		}
	}
}

func TestComputeAndExtendDeadline(t *testing.T) {
	now := time.Date(2026, 11, 21, 18, 0, 0, 0, time.FixedZone("UTC+8", 8*3600))
	dl, err := rules.ComputeDeadline(now, 300)
	if err != nil || dl.Location() != time.UTC || !dl.Equal(now.Add(300*time.Second)) {
		t.Fatalf("ComputeDeadline = (%v, %v)", dl, err)
	}
	if _, err := rules.ComputeDeadline(now, 0); !errors.Is(err, rules.ErrTimeoutNonPositive) {
		t.Errorf("ComputeDeadline(0) err = %v", err)
	}
	if _, err := rules.ComputeDeadline(now, -10); !errors.Is(err, rules.ErrTimeoutNonPositive) {
		t.Errorf("ComputeDeadline(-10) err = %v", err)
	}
	if _, err := rules.ComputeDeadline(now, 9223372037); !errors.Is(err, rules.ErrTimeoutExceedsMax) {
		t.Errorf("ComputeDeadline(overflow) err = %v", err)
	}

	if got, ext, err := rules.ExtendDeadline(now, now.Add(100*time.Second), 300); err != nil || !ext || !got.Equal(now.UTC().Add(300*time.Second)) {
		t.Errorf("ExtendDeadline(extend) = (%v, %v, %v)", got, ext, err)
	}
	if got, ext, err := rules.ExtendDeadline(now, now.Add(600*time.Second), 300); err != nil || ext || got.Location() != time.UTC || !got.Equal(now.Add(600*time.Second)) {
		t.Errorf("ExtendDeadline(no-shorten) = (%v, %v, %v)", got, ext, err)
	}
	if got, ext, err := rules.ExtendDeadline(now, now.Add(300*time.Second), 300); err != nil || ext || !got.Equal(now.UTC().Add(300*time.Second)) {
		t.Errorf("ExtendDeadline(equal) = (%v, %v, %v)", got, ext, err)
	}
	if _, _, err := rules.ExtendDeadline(now, now.Add(600*time.Second), 0); !errors.Is(err, rules.ErrTimeoutNonPositive) {
		t.Errorf("ExtendDeadline(0) err = %v", err)
	}
	if err := rules.ValidateFutureDeadline(now.Add(time.Nanosecond), now); err != nil {
		t.Errorf("ValidateFutureDeadline(future): %v", err)
	}
	if err := rules.ValidateFutureDeadline(now, now); !errors.Is(err, rules.ErrTimeoutDeadlinePast) {
		t.Errorf("ValidateFutureDeadline(equal) = %v", err)
	}
	if err := rules.ValidateFutureDeadline(now.Add(-time.Second), now); !errors.Is(err, rules.ErrTimeoutDeadlinePast) {
		t.Errorf("ValidateFutureDeadline(past) = %v", err)
	}
}
