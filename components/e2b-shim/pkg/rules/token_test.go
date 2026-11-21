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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
)

const (
	fakeHMACSecret1 = "fake-hmac-secret-one-DO-NOT-USE"
	fakeHMACSecret2 = "fake-hmac-secret-two-DO-NOT-USE"
)

func testSecret(t *testing.T, hmacVal string) config.Secret {
	t.Helper()
	if hmacVal == "" {
		return config.Secret{}
	}
	env := map[string]string{
		"E2B_SHIM_NATIVE_API_URL":      "https://native.example.internal",
		"E2B_SHIM_ADAPTER_ID":          "e2b-shim-test",
		"E2B_SHIM_HMAC_KEY_VERSION":    "v1",
		"E2B_SHIM_TIMEOUT_MAX_SECONDS": "3600",
		"E2B_SHIM_ADAPTER_API_KEY":     "fake-adapter-key-DO-NOT-USE",
		"E2B_SHIM_NATIVE_API_KEY":      "fake-native-key-DO-NOT-USE",
		"E2B_SHIM_HMAC_KEY":            hmacVal,
	}
	cfg, err := config.Load(config.Source{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }})
	if err != nil {
		t.Fatalf("load test secret: %v", err)
	}
	return cfg.HMACKey
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b := s[i]; !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return false
		}
	}
	return true
}

func TestTokenDeriverDeterminismAndDomainSeparation(t *testing.T) {
	d1, err := rules.NewTokenDeriver(testSecret(t, fakeHMACSecret1), "v1", "adapter-a")
	if err != nil {
		t.Fatalf("NewTokenDeriver: %v", err)
	}
	tok1, err := d1.Derive("sbx-123")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if tok2, err := d1.Derive("sbx-123"); err != nil || tok1 != tok2 {
		t.Fatalf("non-deterministic tokens: %q vs %q (%v)", tok1, tok2, err)
	}
	if !isLowerHex64(tok1) || strings.ContainsRune(tok1, '\\') {
		t.Fatalf("token %q is not 64 lowercase hex chars", tok1)
	}

	mac := hmac.New(sha256.New, []byte(fakeHMACSecret1))
	mac.Write([]byte("opensandbox-e2b-shim/envd-token/v1\x00v1\x00adapter-a\x00sbx-123"))
	if want := hex.EncodeToString(mac.Sum(nil)); tok1 != want {
		t.Errorf("token = %q, want %q", tok1, want)
	}
	if otherSandbox, err := d1.Derive("sbx-124"); err != nil || otherSandbox == tok1 {
		t.Errorf("different sandbox ID collided or failed: %v", err)
	}
	dDiffAdapter, _ := rules.NewTokenDeriver(testSecret(t, fakeHMACSecret1), "v1", "adapter-b")
	if tok, _ := dDiffAdapter.Derive("sbx-123"); tok == tok1 {
		t.Error("different adapterID produced identical token")
	}
	dDiffVer, _ := rules.NewTokenDeriver(testSecret(t, fakeHMACSecret1), "v2", "adapter-a")
	if tok, _ := dDiffVer.Derive("sbx-123"); tok == tok1 {
		t.Error("different keyVersion produced identical token")
	}
	dDiffKey, _ := rules.NewTokenDeriver(testSecret(t, fakeHMACSecret2), "v1", "adapter-a")
	if tok, _ := dDiffKey.Derive("sbx-123"); tok == tok1 {
		t.Error("different hmacKey produced identical token")
	}
}

func TestTokenDeriverDelimiterCollisionResistance(t *testing.T) {
	sec := testSecret(t, fakeHMACSecret1)
	dLeft, _ := rules.NewTokenDeriver(sec, "v1", "a-b")
	dRight, _ := rules.NewTokenDeriver(sec, "v1", "a")
	tLeft, _ := dLeft.Derive("c")
	tRight, _ := dRight.Derive("b-c")
	if tLeft == tRight {
		t.Error("split boundary across adapterID and sandboxID collided")
	}
	dVerLeft, _ := rules.NewTokenDeriver(sec, "v1.a", "b")
	dVerRight, _ := rules.NewTokenDeriver(sec, "v1", "a.b")
	tv1, _ := dVerLeft.Derive("sbx")
	tv2, _ := dVerRight.Derive("sbx")
	if tv1 == tv2 {
		t.Error("split boundary across keyVersion and adapterID collided")
	}
}

func TestTokenDeriverInvalidInputs(t *testing.T) {
	sec := testSecret(t, fakeHMACSecret1)
	ctorCases := []struct {
		name                  string
		secret                config.Secret
		keyVersion, adapterID string
	}{
		{"zero secret", config.Secret{}, "v1", "adapter-1"},
		{"empty key version", sec, "", "adapter-1"},
		{"whitespace key version", sec, "v 1", "adapter-1"},
		{"nul key version", sec, "v1\x00", "adapter-1"},
		{"invalid label key version", sec, "v1@bad", "adapter-1"},
		{"empty adapter id", sec, "v1", ""},
		{"whitespace adapter id", sec, "v1", "adapter\t1"},
		{"nul adapter id", sec, "v1", "a\x00b"},
		{"invalid label adapter id", sec, "v1", "-adapter"},
	}
	for _, tc := range ctorCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rules.NewTokenDeriver(tc.secret, tc.keyVersion, tc.adapterID)
			if !errors.Is(err, rules.ErrInvalidTokenInput) {
				t.Fatalf("err = %v, want ErrInvalidTokenInput", err)
			}
			if strings.Contains(err.Error(), fakeHMACSecret1) {
				t.Fatalf("error leaked secret: %q", err.Error())
			}
		})
	}

	d, _ := rules.NewTokenDeriver(sec, "v1", "ab")
	for _, badID := range []string{"", " ", "sbx 1", "sbx\nsbx", "sbx\x00x", "\xff"} {
		if _, err := d.Derive(badID); !errors.Is(err, rules.ErrInvalidTokenInput) {
			t.Errorf("Derive(%q): err = %v, want ErrInvalidTokenInput", badID, err)
		}
		if ok, err := d.Verify(badID, strings.Repeat("a", 64)); ok || !errors.Is(err, rules.ErrInvalidTokenInput) {
			t.Errorf("Verify(%q): ok=%v err=%v, want false + ErrInvalidTokenInput", badID, ok, err)
		}
	}
	var zeroDeriver rules.TokenDeriver
	if _, err := (&zeroDeriver).Derive("sbx-1"); !errors.Is(err, rules.ErrInvalidTokenInput) {
		t.Errorf("zero TokenDeriver Derive err = %v, want ErrInvalidTokenInput", err)
	}
	if _, err := (*rules.TokenDeriver)(nil).Derive("sbx-1"); !errors.Is(err, rules.ErrInvalidTokenInput) {
		t.Errorf("nil TokenDeriver Derive err = %v, want ErrInvalidTokenInput", err)
	}
}

func TestTokenDeriverVerifyAndRedaction(t *testing.T) {
	d, err := rules.NewTokenDeriver(testSecret(t, fakeHMACSecret1), "v1", "adapter-1")
	if err != nil {
		t.Fatal(err)
	}
	validToken, err := d.Derive("sbx-verify-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, presented string
		want            bool
	}{
		{"exact valid token", validToken, true},
		{"wrong token same length", strings.Repeat("0", 64), false},
		{"uppercase hex rejected", strings.ToUpper(validToken), false},
		{"empty token", "", false},
		{"truncated token", validToken[:63], false},
		{"overlong token", validToken + "0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ok, err := d.Verify("sbx-verify-1", tc.presented); err != nil || ok != tc.want {
				t.Errorf("Verify = (%v, %v), want (%v, nil)", ok, err, tc.want)
			}
		})
	}

	var logBuf bytes.Buffer
	slog.New(slog.NewTextHandler(&logBuf, nil)).Info("check", "ptr", d, "val", *d)
	jsonBlob, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{
		d.String(), d.GoString(), d.LogValue().String(),
		fmt.Sprintf("%v", d), fmt.Sprintf("%+v", d), fmt.Sprintf("%#v", d),
		fmt.Sprintf("%v", *d), fmt.Sprintf("%+v", *d), fmt.Sprintf("%#v", *d),
		fmt.Sprintf("%q", any(d)), fmt.Sprintf("%x", d), logBuf.String(), string(jsonBlob),
	} {
		if strings.Contains(out, fakeHMACSecret1) || !strings.Contains(out, "[REDACTED]") {
			t.Errorf("unexpected formatting output: %q", out)
		}
	}
}
