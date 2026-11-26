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
	"strings"
	"testing"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
	"github.com/alibaba/opensandbox/e2b-shim/pkg/rules"
)

func boolPtr(v bool) *bool    { return &v }
func int64Ptr(v int64) *int64 { return &v }

func defaultProfileTimeout() rules.TimeoutPolicy {
	return rules.TimeoutPolicy{DefaultSeconds: 300, MinSeconds: 60, MaxSeconds: 3600}
}

func TestTemplateCatalogResolveAndAliasReassignment(t *testing.T) {
	catV1, err := rules.NewTemplateCatalog([]config.TemplateMapping{
		{TemplateID: "base", Aliases: []string{"default", "base-envd"}, NativeTemplateID: "tpl-base-v1", Revision: "tpl-base.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0", TimeoutMaxSeconds: int64Ptr(1200)},
		{TemplateID: "unready-tpl", NativeTemplateID: "tpl-unready", Revision: "tpl-unready.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0", Ready: boolPtr(false)},
		{TemplateID: "incompat-tpl", NativeTemplateID: "tpl-incompat", Revision: "tpl-incompat.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0", ProfileCompatible: boolPtr(false)},
	}, defaultProfileTimeout())
	if err != nil {
		t.Fatalf("NewTemplateCatalog v1: %v", err)
	}

	for _, sel := range []string{"base", "default", "base-envd"} {
		res, err := catV1.ResolveForCreate(sel)
		if err != nil {
			t.Fatalf("ResolveForCreate(%q): %v", sel, err)
		}
		if res.TemplateID != "base" || res.Revision != "tpl-base.rev-1" || res.NativeTemplateID != "tpl-base-v1" {
			t.Errorf("ResolveForCreate(%q) = %+v", sel, res)
		}
		if res.Timeout.MaxSeconds != 1200 || res.Timeout.DefaultSeconds != 300 || res.Timeout.MinSeconds != 60 {
			t.Errorf("effective timeout = %+v", res.Timeout)
		}
		res.Aliases[0] = "mutated"
	}
	if again, _ := catV1.ResolveForCreate("base"); again.Aliases[0] != "default" {
		t.Errorf("Aliases slice was not defensively copied: %v", again.Aliases)
	}

	for _, bad := range []string{"", "unknown"} {
		if _, err := catV1.ResolveForCreate(bad); !errors.Is(err, rules.ErrTemplateNotFound) {
			t.Errorf("ResolveForCreate(%q) err = %v, want ErrTemplateNotFound", bad, err)
		}
	}
	if _, err := (*rules.TemplateCatalog)(nil).ResolveForCreate("base"); !errors.Is(err, rules.ErrTemplateNotFound) {
		t.Errorf("nil catalog ResolveForCreate err = %v, want ErrTemplateNotFound", err)
	}
	if _, err := catV1.ResolveForCreate("unready-tpl"); !errors.Is(err, rules.ErrTemplateNotReady) {
		t.Errorf("unready err = %v, want ErrTemplateNotReady", err)
	}
	if _, err := catV1.ResolveForCreate("incompat-tpl"); !errors.Is(err, rules.ErrTemplateProfileIncompatible) {
		t.Errorf("incompat err = %v, want ErrTemplateProfileIncompatible", err)
	}

	// Catalog v2 moves alias "default" to rev-2 while retaining rev-1 for existing instances.
	catV2, err := rules.NewTemplateCatalog([]config.TemplateMapping{
		{TemplateID: "base-v1", NativeTemplateID: "tpl-base-v1", Revision: "tpl-base.rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0", Ready: boolPtr(false)},
		{TemplateID: "base-v2", Aliases: []string{"default"}, NativeTemplateID: "tpl-base-v2", Revision: "tpl-base.rev-2", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0"},
	}, defaultProfileTimeout())
	if err != nil {
		t.Fatalf("NewTemplateCatalog v2: %v", err)
	}
	if created, err := catV2.ResolveForCreate("default"); err != nil || created.Revision != "tpl-base.rev-2" || created.TemplateID != "base-v2" {
		t.Fatalf("ResolveForCreate(default) in v2 = %+v, err = %v", created, err)
	}
	if oldRev, err := catV2.ResolveByRevision("tpl-base.rev-1"); err != nil || oldRev.TemplateID != "base-v1" || oldRev.NativeTemplateID != "tpl-base-v1" {
		t.Fatalf("ResolveByRevision(tpl-base.rev-1) in v2 = %+v, err = %v", oldRev, err)
	}
	for _, unknown := range []string{"", "default", "tpl-base.rev-999"} {
		if _, err := catV2.ResolveByRevision(unknown); !errors.Is(err, rules.ErrTemplateRevisionNotFound) {
			t.Errorf("ResolveByRevision(%q) err = %v, want ErrTemplateRevisionNotFound", unknown, err)
		}
	}
	if _, err := (*rules.TemplateCatalog)(nil).ResolveByRevision("tpl-base.rev-1"); !errors.Is(err, rules.ErrTemplateRevisionNotFound) {
		t.Errorf("nil catalog ResolveByRevision err = %v, want ErrTemplateRevisionNotFound", err)
	}
}

func TestNewTemplateCatalogRejectsInvalidConfigs(t *testing.T) {
	valid := config.TemplateMapping{TemplateID: "base", NativeTemplateID: "tpl-base", Revision: "rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0"}
	p := defaultProfileTimeout()
	cases := []struct {
		name     string
		mappings []config.TemplateMapping
		policy   rules.TimeoutPolicy
		wantIs   error
	}{
		{"invalid profile min timeout", nil, rules.TimeoutPolicy{DefaultSeconds: 300, MinSeconds: 0, MaxSeconds: 3600}, rules.ErrTimeoutInvalidPolicy},
		{"profile max below min", nil, rules.TimeoutPolicy{DefaultSeconds: 300, MinSeconds: 100, MaxSeconds: 60}, rules.ErrTimeoutInvalidPolicy},
		{"empty template id", []config.TemplateMapping{{NativeTemplateID: "t", Revision: "r1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0"}}, p, nil},
		{"invalid revision label at-sign", []config.TemplateMapping{{TemplateID: "base", NativeTemplateID: "t", Revision: "tpl@rev1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0"}}, p, rules.ErrInvalidMetadataValue},
		{"revision exceeds 63 chars", []config.TemplateMapping{{TemplateID: "base", NativeTemplateID: "t", Revision: strings.Repeat("r", 64), DefaultUser: "user", ExpectedEnvdVersion: "0.8.0"}}, p, rules.ErrInvalidMetadataValue},
		{"duplicate selector", []config.TemplateMapping{valid, {TemplateID: "other", Aliases: []string{"base"}, NativeTemplateID: "t2", Revision: "rev-2", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0"}}, p, nil},
		{"duplicate revision", []config.TemplateMapping{valid, {TemplateID: "other", NativeTemplateID: "t2", Revision: "rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0"}}, p, nil},
		{"empty alias", []config.TemplateMapping{{TemplateID: "base", Aliases: []string{""}, NativeTemplateID: "t", Revision: "rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0"}}, p, nil},
		{"per-template max below min", []config.TemplateMapping{{TemplateID: "base", NativeTemplateID: "t", Revision: "rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0", TimeoutMaxSeconds: int64Ptr(30)}}, p, rules.ErrTimeoutInvalidPolicy},
		{"per-template max above max", []config.TemplateMapping{{TemplateID: "base", NativeTemplateID: "t", Revision: "rev-1", DefaultUser: "user", ExpectedEnvdVersion: "0.8.0", TimeoutMaxSeconds: int64Ptr(7200)}}, p, rules.ErrTimeoutInvalidPolicy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rules.NewTemplateCatalog(tc.mappings, tc.policy)
			if err == nil {
				t.Fatal("NewTemplateCatalog succeeded; want error")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("err = %v, want errors.Is(..., %v)", err, tc.wantIs)
			}
		})
	}
}
