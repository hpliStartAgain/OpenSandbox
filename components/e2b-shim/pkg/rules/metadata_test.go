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

func testCatalogForMetadata(t *testing.T) *rules.TemplateCatalog {
	t.Helper()
	cat, err := rules.NewTemplateCatalog([]config.TemplateMapping{
		{TemplateID: "base", Aliases: []string{"default"}, NativeTemplateID: "tpl-base", Revision: "tpl-base.rev-1", ExpectedEnvdVersion: "0.8.0"},
	}, defaultProfileTimeout())
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func TestShimMetadataKeysAreValidFastSandboxDNSLabels(t *testing.T) {
	for _, k := range []string{
		rules.MetaKeyManaged, rules.MetaKeySchema, rules.MetaKeyAdapterID, rules.MetaKeyRevision, rules.MetaKeyHMACKeyVersion,
	} {
		if len(k) > rules.MaxLabelLength {
			t.Errorf("shim key %q exceeds 63 chars", k)
		}
		if err := rules.ValidateMetadataKey(k); !errors.Is(err, rules.ErrReservedMetadataKey) {
			t.Errorf("ValidateMetadataKey(%q) = %v, want ErrReservedMetadataKey", k, err)
		}
		if err := rules.ValidateMetadataKey(strings.TrimPrefix(k, rules.MetadataReservedPrefix)); err != nil {
			t.Errorf("shim key %q suffix is not a valid DNS label: %v", k, err)
		}
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	cat := testCatalogForMetadata(t)
	for _, userMeta := range []map[string]string{nil, {}, {"env": "staging", "team-1": "Platform_A.2"}} {
		encoded, err := rules.EncodeSandboxMetadata(rules.MetadataEncodeInput{
			AdapterID: "e2b-shim-dev", Revision: "tpl-base.rev-1", HMACKeyVersion: "v1", UserMetadata: userMeta,
		})
		if err != nil {
			t.Fatalf("EncodeSandboxMetadata(%v): %v", userMeta, err)
		}
		if encoded[rules.MetaKeyManaged] != "true" || encoded[rules.MetaKeySchema] != "v1" ||
			encoded[rules.MetaKeyAdapterID] != "e2b-shim-dev" || encoded[rules.MetaKeyRevision] != "tpl-base.rev-1" ||
			encoded[rules.MetaKeyHMACKeyVersion] != "v1" {
			t.Fatalf("missing or wrong shim labels: %v", encoded)
		}
		res := rules.DecodeSandboxOwnership(encoded, "e2b-shim-dev", "v1", cat)
		if !res.Owned || res.Reason != rules.OwnershipOK || res.Revision != "tpl-base.rev-1" || res.Template.TemplateID != "base" {
			t.Fatalf("DecodeSandboxOwnership = %+v", res)
		}
		wantUser := map[string]string{}
		maps.Copy(wantUser, userMeta)
		if !maps.Equal(res.UserMetadata, wantUser) {
			t.Errorf("UserMetadata = %v, want %v", res.UserMetadata, wantUser)
		}
		res.UserMetadata["mutated"] = "1"
		if _, leaked := encoded["mutated"]; leaked {
			t.Error("UserMetadata was not a fresh map copy")
		}
	}
}

func TestValidateMetadataKeyAndValueBoundaries(t *testing.T) {
	for _, k := range []string{"a", "0", "a-b", "a--b", strings.Repeat("k", 63)} {
		if err := rules.ValidateMetadataKey(k); err != nil {
			t.Errorf("ValidateMetadataKey(%q) unexpected error: %v", k, err)
		}
	}
	for _, tc := range []struct {
		name, key string
		want      error
	}{
		{"empty", "", rules.ErrInvalidMetadataKey},
		{"length 64", strings.Repeat("k", 64), rules.ErrInvalidMetadataKey},
		{"uppercase", "Env", rules.ErrInvalidMetadataKey},
		{"underscore", "my_key", rules.ErrInvalidMetadataKey},
		{"dot", "my.key", rules.ErrInvalidMetadataKey},
		{"slash", "app.example/key", rules.ErrInvalidMetadataKey},
		{"leading hyphen", "-key", rules.ErrInvalidMetadataKey},
		{"trailing hyphen", "key-", rules.ErrInvalidMetadataKey},
		{"single hyphen", "-", rules.ErrInvalidMetadataKey},
		{"reserved opensandbox prefix", "opensandbox.io/foo", rules.ErrReservedMetadataKey},
		{"reserved e2b-shim managed", "e2b-shim-managed", rules.ErrReservedMetadataKey},
		{"reserved e2b-shim custom", "e2b-shim-custom", rules.ErrReservedMetadataKey},
	} {
		t.Run("key/"+tc.name, func(t *testing.T) {
			if err := rules.ValidateMetadataKey(tc.key); !errors.Is(err, tc.want) {
				t.Errorf("ValidateMetadataKey(%q) = %v, want %v", tc.key, err, tc.want)
			}
		})
	}

	for _, v := range []string{"a", "Z", "9", "v1.2_3-rc1", strings.Repeat("V", 63)} {
		if err := rules.ValidateLabelValue(v); err != nil {
			t.Errorf("ValidateLabelValue(%q) unexpected error: %v", v, err)
		}
	}
	for _, tc := range []struct{ name, val string }{
		{"empty", ""},
		{"length 64", strings.Repeat("v", 64)},
		{"leading hyphen", "-val"},
		{"trailing hyphen", "val-"},
		{"leading dot", ".val"},
		{"trailing underscore", "val_"},
		{"single dot", "."},
		{"at-sign", "tpl@rev-1"},
		{"space", "hello world"},
		{"newline", "hello\nworld"},
		{"unicode", "héllo"},
	} {
		t.Run("value/"+tc.name, func(t *testing.T) {
			if err := rules.ValidateLabelValue(tc.val); !errors.Is(err, rules.ErrInvalidMetadataValue) {
				t.Errorf("ValidateLabelValue(%q) = %v, want ErrInvalidMetadataValue", tc.val, err)
			}
		})
	}

	secretVal := "secret-meta-value@DO-NOT-ECHO"
	_, err := rules.EncodeSandboxMetadata(rules.MetadataEncodeInput{
		AdapterID: "e2b-shim-dev", Revision: "tpl-base.rev-1", HMACKeyVersion: "v1",
		UserMetadata: map[string]string{"env": secretVal},
	})
	if !errors.Is(err, rules.ErrInvalidMetadataValue) || strings.Contains(err.Error(), secretVal) {
		t.Errorf("EncodeSandboxMetadata err = %v", err)
	}
}

func TestDecodeSandboxOwnershipTamperedAndMissing(t *testing.T) {
	cat := testCatalogForMetadata(t)
	valid, err := rules.EncodeSandboxMetadata(rules.MetadataEncodeInput{
		AdapterID: "adapter-1", Revision: "tpl-base.rev-1", HMACKeyVersion: "v1",
		UserMetadata: map[string]string{"owner": "alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	withChange := func(k, v string, del bool) map[string]string {
		cp := maps.Clone(valid)
		if del {
			delete(cp, k)
		} else {
			cp[k] = v
		}
		return cp
	}

	for _, tc := range []struct {
		name                  string
		raw                   map[string]string
		adapterID, keyVersion string
		catalog               *rules.TemplateCatalog
		wantReason            rules.OwnershipReason
	}{
		{"nil map", nil, "adapter-1", "v1", cat, rules.OwnershipMissingMetadata},
		{"empty map", map[string]string{}, "adapter-1", "v1", cat, rules.OwnershipMissingMetadata},
		{"missing marker", withChange(rules.MetaKeyManaged, "", true), "adapter-1", "v1", cat, rules.OwnershipMissingMarker},
		{"wrong marker value", withChange(rules.MetaKeyManaged, "false", false), "adapter-1", "v1", cat, rules.OwnershipMissingMarker},
		{"wrong schema version", withChange(rules.MetaKeySchema, "v99", false), "adapter-1", "v1", cat, rules.OwnershipUnsupportedSchema},
		{"adapter mismatch", valid, "adapter-2", "v1", cat, rules.OwnershipAdapterMismatch},
		{"key version mismatch", valid, "adapter-1", "v2", cat, rules.OwnershipKeyVersionMismatch},
		{"missing revision", withChange(rules.MetaKeyRevision, "", true), "adapter-1", "v1", cat, rules.OwnershipMissingRevision},
		{"unknown revision", withChange(rules.MetaKeyRevision, "unknown.rev-9", false), "adapter-1", "v1", cat, rules.OwnershipUnknownRevision},
		{"nil catalog", valid, "adapter-1", "v1", nil, rules.OwnershipUnknownRevision},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := rules.DecodeSandboxOwnership(tc.raw, tc.adapterID, tc.keyVersion, tc.catalog)
			if res.Owned || res.Reason != tc.wantReason {
				t.Errorf("got %+v, want Owned=false Reason=%q", res, tc.wantReason)
			}
		})
	}
}
