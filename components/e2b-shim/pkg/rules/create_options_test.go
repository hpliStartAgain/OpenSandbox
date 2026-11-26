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
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
)

func testCreateCatalog(t *testing.T) *rules.TemplateCatalog {
	t.Helper()
	cat, err := rules.NewTemplateCatalog([]config.TemplateMapping{
		{TemplateID: "base", Aliases: []string{"base-envd"}, NativeTemplateID: "envd-only-base", Revision: "envd-only-base.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0"},
		{TemplateID: "short-cap", NativeTemplateID: "envd-short", Revision: "envd-short.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0", TimeoutMaxSeconds: int64Ptr(120)},
		{TemplateID: "unready", NativeTemplateID: "envd-unready", Revision: "envd-unready.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0", Ready: boolPtr(false)},
		{TemplateID: "incompat", NativeTemplateID: "envd-incompat", Revision: "envd-incompat.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0", ProfileCompatible: boolPtr(false)},
	}, defaultProfileTimeout())
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func TestValidateCreateRequestSuccessCases(t *testing.T) {
	cat := testCreateCatalog(t)
	got, err := rules.ValidateCreateRequest([]byte(`{"templateID":"base","metadata":{},"envVars":{}}`), cat, "e2b-shim-dev", "v1")
	if err != nil {
		t.Fatalf("minimal SDK payload failed: %v", err)
	}
	if got.Template.TemplateID != "base" || got.Template.Revision != "envd-only-base.rev-1" || got.TimeoutSeconds != 300 {
		t.Errorf("got = %+v", got)
	}
	if len(got.UserMetadata) != 0 || len(got.EnvVars) != 0 {
		t.Errorf("UserMetadata=%v EnvVars=%v, want empty maps", got.UserMetadata, got.EnvVars)
	}
	if got.NativeMetadata[rules.MetaKeyManaged] != "true" || got.NativeMetadata[rules.MetaKeyRevision] != "envd-only-base.rev-1" {
		t.Errorf("NativeMetadata = %v", got.NativeMetadata)
	}

	fullBody := `{"templateID":"base-envd","timeout":600,"autoPause":false,"secure":true,"allow_internet_access":true,"metadata":{"team":"infra","run-id":"run_42.a"},"envVars":{"API_URL":"https://api.example/v1?a=1&b=2","EMPTY_VAL":""}}`
	full, err := rules.ValidateCreateRequest([]byte(fullBody), cat, "e2b-shim-dev", "v1")
	if err != nil {
		t.Fatalf("full valid payload failed: %v", err)
	}
	if full.Template.TemplateID != "base" || full.Template.Revision != "envd-only-base.rev-1" || full.TimeoutSeconds != 600 {
		t.Errorf("resolved = %+v, timeout = %d", full.Template, full.TimeoutSeconds)
	}
	if !maps.Equal(full.EnvVars, map[string]string{"API_URL": "https://api.example/v1?a=1&b=2", "EMPTY_VAL": ""}) {
		t.Errorf("EnvVars = %v", full.EnvVars)
	}
	if _, leakedToMeta := full.NativeMetadata["API_URL"]; leakedToMeta {
		t.Error("EnvVars must not be placed in NativeMetadata")
	}
	if full.NativeMetadata["team"] != "infra" || full.UserMetadata["run-id"] != "run_42.a" {
		t.Errorf("metadata mismatch: native=%v user=%v", full.NativeMetadata, full.UserMetadata)
	}
}

func TestValidateCreateRequestRejections(t *testing.T) {
	cat := testCreateCatalog(t)
	cases := []struct {
		name, body string
		wantErr    error
	}{
		{"empty body", ``, rules.ErrInvalidCreateRequest},
		{"json null body", `null`, rules.ErrInvalidCreateRequest},
		{"json array body", `[]`, rules.ErrInvalidCreateRequest},
		{"json string body", `"base"`, rules.ErrInvalidCreateRequest},
		{"malformed json", `{"templateID":`, rules.ErrInvalidCreateRequest},
		{"trailing tokens", `{"templateID":"base"} {}`, rules.ErrInvalidCreateRequest},
		{"duplicate top-level key", `{"templateID":"base","templateID":"base"}`, rules.ErrDuplicateField},
		{"unknown field", `{"templateID":"base","bogus":1}`, rules.ErrUnknownField},
		{"missing templateID", `{}`, rules.ErrMissingTemplateID},
		{"empty templateID", `{"templateID":""}`, rules.ErrMissingTemplateID},
		{"null templateID", `{"templateID":null}`, rules.ErrInvalidCreateRequest},
		{"non-string templateID", `{"templateID":123}`, rules.ErrInvalidCreateRequest},
		{"unknown templateID", `{"templateID":"missing"}`, rules.ErrTemplateNotFound},
		{"unready template", `{"templateID":"unready"}`, rules.ErrTemplateNotReady},
		{"profile incompatible template", `{"templateID":"incompat"}`, rules.ErrTemplateProfileIncompatible},
		{"timeout null", `{"templateID":"base","timeout":null}`, rules.ErrTimeoutInvalidType},
		{"timeout float 60.0", `{"templateID":"base","timeout":60.0}`, rules.ErrTimeoutInvalidType},
		{"timeout float 60.5", `{"templateID":"base","timeout":60.5}`, rules.ErrTimeoutInvalidType},
		{"timeout string", `{"templateID":"base","timeout":"60"}`, rules.ErrTimeoutInvalidType},
		{"timeout zero", `{"templateID":"base","timeout":0}`, rules.ErrTimeoutNonPositive},
		{"timeout below min", `{"templateID":"base","timeout":59}`, rules.ErrTimeoutBelowMin},
		{"timeout exceeds profile max", `{"templateID":"base","timeout":3601}`, rules.ErrTimeoutExceedsMax},
		{"timeout exceeds template max", `{"templateID":"short-cap","timeout":121}`, rules.ErrTimeoutExceedsMax},
		{"omitted timeout exceeds template max", `{"templateID":"short-cap"}`, rules.ErrTimeoutExceedsMax},
		{"metadata null", `{"templateID":"base","metadata":null}`, rules.ErrInvalidCreateRequest},
		{"metadata array", `{"templateID":"base","metadata":[]}`, rules.ErrInvalidCreateRequest},
		{"metadata non-string value", `{"templateID":"base","metadata":{"k":1}}`, rules.ErrInvalidCreateRequest},
		{"metadata null value", `{"templateID":"base","metadata":{"k":null}}`, rules.ErrInvalidCreateRequest},
		{"metadata duplicate key", `{"templateID":"base","metadata":{"k":"a","k":"b"}}`, rules.ErrDuplicateField},
		{"metadata uppercase key", `{"templateID":"base","metadata":{"BadKey":"a"}}`, rules.ErrInvalidMetadataKey},
		{"metadata reserved opensandbox key", `{"templateID":"base","metadata":{"opensandbox.io/x":"a"}}`, rules.ErrReservedMetadataKey},
		{"metadata reserved e2b-shim key", `{"templateID":"base","metadata":{"e2b-shim-managed":"true"}}`, rules.ErrReservedMetadataKey},
		{"metadata empty value", `{"templateID":"base","metadata":{"k":""}}`, rules.ErrInvalidMetadataValue},
		{"metadata invalid label value", `{"templateID":"base","metadata":{"k":"a@b"}}`, rules.ErrInvalidMetadataValue},
		{"envVars null", `{"templateID":"base","envVars":null}`, rules.ErrInvalidCreateRequest},
		{"envVars array", `{"templateID":"base","envVars":[]}`, rules.ErrInvalidCreateRequest},
		{"envVars non-string value", `{"templateID":"base","envVars":{"A":123}}`, rules.ErrInvalidCreateRequest},
		{"envVars null value", `{"templateID":"base","envVars":{"A":null}}`, rules.ErrInvalidCreateRequest},
		{"envVars duplicate key", `{"templateID":"base","envVars":{"A":"1","A":"2"}}`, rules.ErrDuplicateField},
		{"envVars empty key", `{"templateID":"base","envVars":{"":"val"}}`, rules.ErrInvalidEnvVar},
		{"envVars key contains equals", `{"templateID":"base","envVars":{"A=B":"val"}}`, rules.ErrInvalidEnvVar},
		{"envVars key contains NUL", `{"templateID":"base","envVars":{"A\u0000B":"val"}}`, rules.ErrInvalidEnvVar},
		{"envVars value contains NUL", `{"templateID":"base","envVars":{"A":"val\u0000x"}}`, rules.ErrInvalidEnvVar},
		{"autoPause true", `{"templateID":"base","autoPause":true}`, rules.ErrUnsupportedOption},
		{"autoPause null", `{"templateID":"base","autoPause":null}`, rules.ErrInvalidCreateRequest},
		{"autoPause string", `{"templateID":"base","autoPause":"false"}`, rules.ErrInvalidCreateRequest},
		{"autoPauseMemory true", `{"templateID":"base","autoPauseMemory":true}`, rules.ErrUnsupportedOption},
		{"autoPauseMemory false", `{"templateID":"base","autoPauseMemory":false}`, rules.ErrUnsupportedOption},
		{"autoPauseMemory null", `{"templateID":"base","autoPauseMemory":null}`, rules.ErrUnsupportedOption},
		{"autoResume object", `{"templateID":"base","autoResume":{"enabled":true}}`, rules.ErrUnsupportedOption},
		{"autoResume null", `{"templateID":"base","autoResume":null}`, rules.ErrUnsupportedOption},
		{"secure false", `{"templateID":"base","secure":false}`, rules.ErrUnsupportedOption},
		{"secure null", `{"templateID":"base","secure":null}`, rules.ErrInvalidCreateRequest},
		{"secure string", `{"templateID":"base","secure":"true"}`, rules.ErrInvalidCreateRequest},
		{"allow_internet_access false", `{"templateID":"base","allow_internet_access":false}`, rules.ErrUnsupportedOption},
		{"allow_internet_access null", `{"templateID":"base","allow_internet_access":null}`, rules.ErrInvalidCreateRequest},
		{"allow_internet_access int", `{"templateID":"base","allow_internet_access":1}`, rules.ErrInvalidCreateRequest},
		{"network object", `{"templateID":"base","network":{"allowPublicTraffic":true}}`, rules.ErrUnsupportedOption},
		{"network null", `{"templateID":"base","network":null}`, rules.ErrUnsupportedOption},
		{"mcp object", `{"templateID":"base","mcp":{"github":{}}}`, rules.ErrUnsupportedOption},
		{"mcp null", `{"templateID":"base","mcp":null}`, rules.ErrUnsupportedOption},
		{"iam object", `{"templateID":"base","iam":{"tokens":{}}}`, rules.ErrUnsupportedOption},
		{"iam null", `{"templateID":"base","iam":null}`, rules.ErrUnsupportedOption},
		{"volumeMounts empty list", `{"templateID":"base","volumeMounts":[]}`, rules.ErrUnsupportedOption},
		{"volumeMounts non-empty", `{"templateID":"base","volumeMounts":[{"name":"v","path":"/mnt"}]}`, rules.ErrUnsupportedOption},
		{"volumeMounts null", `{"templateID":"base","volumeMounts":null}`, rules.ErrUnsupportedOption},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rules.ValidateCreateRequest([]byte(tc.body), cat, "e2b-shim-dev", "v1"); !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want errors.Is(..., %v)", err, tc.wantErr)
			}
		})
	}
	if _, err := rules.ValidateCreateRequest([]byte(`{"templateID":"base"}`), nil, "e2b-shim-dev", "v1"); !errors.Is(err, rules.ErrInvalidCreateRequest) {
		t.Errorf("nil catalog err = %v, want ErrInvalidCreateRequest", err)
	}
}

func TestValidateCreateRequestErrorsNeverEchoUserValues(t *testing.T) {
	cat := testCreateCatalog(t)
	const secretCanary = "SUPER-SECRET-CANARY-VALUE-98765"
	for i, p := range []string{
		`{"templateID":"base","envVars":{"API_KEY":"` + secretCanary + `\u0000"}}`,
		`{"templateID":"base","envVars":{"` + secretCanary + `=BAD":"ok"}}`,
		`{"templateID":"base","envVars":{"API_KEY":["` + secretCanary + `"]}}`,
		`{"templateID":"base","metadata":{"env":"` + secretCanary + `@invalid"}}`,
		`{"templateID":"base","metadata":{"` + secretCanary + `":"valid"}}`,
		`{"templateID":"` + secretCanary + `"}`,
		`{"templateID":"base","` + secretCanary + `":"val"}`,
	} {
		_, err := rules.ValidateCreateRequest([]byte(p), cat, "e2b-shim-dev", "v1")
		if err == nil || strings.Contains(err.Error(), secretCanary) {
			t.Errorf("payload[%d] err = %v", i, err)
		}
	}
}
