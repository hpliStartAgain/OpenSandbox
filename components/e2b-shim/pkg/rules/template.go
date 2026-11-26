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
	"errors"
	"fmt"
	"slices"

	"github.com/alibaba/opensandbox/e2b-shim/pkg/config"
)

var (
	ErrTemplateNotFound            = errors.New("rules: template not found")
	ErrTemplateNotReady            = errors.New("rules: template is not ready")
	ErrTemplateProfileIncompatible = errors.New("rules: template is incompatible with active profile")
	ErrTemplateRevisionNotFound    = errors.New("rules: template revision not found")
)

type ResolvedTemplate struct {
	TemplateID          string
	Aliases             []string
	NativeTemplateID    string
	Revision            string
	DefaultUser         string
	ExpectedEnvdVersion string
	Ready               bool
	ProfileCompatible   bool
	Timeout             TimeoutPolicy
}

type TemplateCatalog struct {
	bySelector map[string]ResolvedTemplate
	byRevision map[string]ResolvedTemplate
}

func NewTemplateCatalog(mappings []config.TemplateMapping, profileTimeout TimeoutPolicy) (*TemplateCatalog, error) {
	if profileTimeout.MinSeconds < 1 || profileTimeout.MaxSeconds < profileTimeout.MinSeconds ||
		profileTimeout.MaxSeconds > maxDurationSeconds || profileTimeout.DefaultSeconds < 1 ||
		profileTimeout.DefaultSeconds > maxDurationSeconds {
		return nil, ErrTimeoutInvalidPolicy
	}

	bySelector := make(map[string]ResolvedTemplate, len(mappings))
	byRevision := make(map[string]ResolvedTemplate, len(mappings))

	for i, m := range mappings {
		at := fmt.Sprintf("templates[%d]", i)
		if !config.ValidDefaultUser(m.DefaultUser) {
			return nil, fmt.Errorf("rules: %s.default_user: invalid username", at)
		}
		for _, f := range []struct{ name, v string }{
			{"template_id", m.TemplateID},
			{"native_template_id", m.NativeTemplateID},
			{"revision", m.Revision},
			{"expected_envd_version", m.ExpectedEnvdVersion},
		} {
			if f.v == "" || hasWhitespaceOrControl(f.v) {
				return nil, fmt.Errorf("rules: %s.%s must not be empty or contain whitespace or control characters", at, f.name)
			}
		}
		if err := ValidateLabelValue(m.Revision); err != nil {
			return nil, fmt.Errorf("rules: %s.revision: %w", at, err)
		}
		if _, exists := byRevision[m.Revision]; exists {
			return nil, fmt.Errorf("rules: %s.revision: duplicate revision", at)
		}

		effTimeout := profileTimeout
		if m.TimeoutMaxSeconds != nil {
			tmax := *m.TimeoutMaxSeconds
			if tmax < profileTimeout.MinSeconds || tmax > profileTimeout.MaxSeconds {
				return nil, fmt.Errorf("%w: %s.timeout_max_seconds out of profile bounds", ErrTimeoutInvalidPolicy, at)
			}
			effTimeout.MaxSeconds = tmax
		}

		aliases := make([]string, len(m.Aliases))
		copy(aliases, m.Aliases)
		entry := ResolvedTemplate{
			TemplateID:          m.TemplateID,
			Aliases:             aliases,
			NativeTemplateID:    m.NativeTemplateID,
			Revision:            m.Revision,
			DefaultUser:         m.DefaultUser,
			ExpectedEnvdVersion: m.ExpectedEnvdVersion,
			Ready:               m.IsReady(),
			ProfileCompatible:   m.IsProfileCompatible(),
			Timeout:             effTimeout,
		}

		for j, sel := range append([]string{m.TemplateID}, m.Aliases...) {
			if j > 0 && (sel == "" || hasWhitespaceOrControl(sel)) {
				return nil, fmt.Errorf("rules: %s.aliases[%d] must not be empty or contain whitespace or control characters", at, j-1)
			}
			if _, exists := bySelector[sel]; exists {
				return nil, fmt.Errorf("rules: %s: duplicate template selector", at)
			}
			bySelector[sel] = entry
		}
		byRevision[m.Revision] = entry
	}

	return &TemplateCatalog{
		bySelector: bySelector,
		byRevision: byRevision,
	}, nil
}

func (c *TemplateCatalog) ResolveForCreate(selector string) (ResolvedTemplate, error) {
	if c == nil || selector == "" {
		return ResolvedTemplate{}, ErrTemplateNotFound
	}
	entry, ok := c.bySelector[selector]
	if !ok {
		return ResolvedTemplate{}, ErrTemplateNotFound
	}
	if !entry.Ready {
		return ResolvedTemplate{}, ErrTemplateNotReady
	}
	if !entry.ProfileCompatible {
		return ResolvedTemplate{}, ErrTemplateProfileIncompatible
	}
	entry.Aliases = slices.Clone(entry.Aliases)
	return entry, nil
}

func (c *TemplateCatalog) ResolveByRevision(revision string) (ResolvedTemplate, error) {
	if c == nil || revision == "" {
		return ResolvedTemplate{}, ErrTemplateRevisionNotFound
	}
	entry, ok := c.byRevision[revision]
	if !ok {
		return ResolvedTemplate{}, ErrTemplateRevisionNotFound
	}
	entry.Aliases = slices.Clone(entry.Aliases)
	return entry, nil
}
