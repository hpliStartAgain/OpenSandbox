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
	"io"
	"maps"
	"slices"
	"strings"
)

var (
	ErrInvalidCreateRequest = errors.New("rules: invalid create request")
	ErrUnknownField         = errors.New("rules: unknown create request field")
	ErrDuplicateField       = errors.New("rules: duplicate JSON field")
	ErrMissingTemplateID    = errors.New("rules: templateID is required")
	ErrUnsupportedOption    = errors.New("rules: unsupported create option")
	ErrInvalidEnvVar        = errors.New("rules: invalid environment variable")
)

var knownCreateFields = map[string]bool{
	"templateID":            true,
	"timeout":               true,
	"metadata":              true,
	"envVars":               true,
	"autoPause":             true,
	"autoPauseMemory":       true,
	"autoResume":            true,
	"secure":                true,
	"allow_internet_access": true,
	"network":               true,
	"mcp":                   true,
	"iam":                   true,
	"volumeMounts":          true,
}

type ValidatedCreateRequest struct {
	Template       ResolvedTemplate
	TimeoutSeconds int64
	NativeMetadata map[string]string
	UserMetadata   map[string]string
	EnvVars        map[string]string
}

func ValidateCreateRequest(rawBody []byte, catalog *TemplateCatalog, adapterID, keyVersion string) (*ValidatedCreateRequest, error) {
	if catalog == nil {
		return nil, fmt.Errorf("%w: template catalog is nil", ErrInvalidCreateRequest)
	}
	fields, err := decodeUniqueObjectFields("request body", rawBody)
	if err != nil {
		return nil, err
	}
	for _, k := range slices.Sorted(maps.Keys(fields)) {
		if !knownCreateFields[k] {
			return nil, ErrUnknownField
		}
	}

	rawTemplateID, ok := fields["templateID"]
	if !ok {
		return nil, ErrMissingTemplateID
	}
	templateSelector, err := decodeStrictString("templateID", rawTemplateID)
	if err != nil {
		return nil, err
	}
	if templateSelector == "" {
		return nil, ErrMissingTemplateID
	}

	for _, omittedOnly := range []string{"autoPauseMemory", "autoResume", "network", "mcp", "iam", "volumeMounts"} {
		if _, present := fields[omittedOnly]; present {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedOption, omittedOnly)
		}
	}
	if raw, present := fields["autoPause"]; present {
		v, err := decodeStrictBool("autoPause", raw)
		if err != nil {
			return nil, err
		}
		if v {
			return nil, fmt.Errorf("%w: autoPause=true", ErrUnsupportedOption)
		}
	}
	for _, defaultTrue := range []string{"secure", "allow_internet_access"} {
		if raw, present := fields[defaultTrue]; present {
			v, err := decodeStrictBool(defaultTrue, raw)
			if err != nil {
				return nil, err
			}
			if !v {
				return nil, fmt.Errorf("%w: %s=false", ErrUnsupportedOption, defaultTrue)
			}
		}
	}

	userMeta := map[string]string{}
	if rawMeta, present := fields["metadata"]; present {
		userMeta, err = decodeStrictStringMap("metadata", rawMeta)
		if err != nil {
			return nil, err
		}
	}

	envVars := map[string]string{}
	if rawEnv, present := fields["envVars"]; present {
		parsed, err := decodeStrictStringMap("envVars", rawEnv)
		if err != nil {
			return nil, err
		}
		for _, k := range slices.Sorted(maps.Keys(parsed)) {
			if k == "" || strings.ContainsRune(k, '=') || strings.ContainsRune(k, '\x00') {
				return nil, fmt.Errorf("%w: invalid key", ErrInvalidEnvVar)
			}
			if strings.ContainsRune(parsed[k], '\x00') {
				return nil, fmt.Errorf("%w: value contains NUL byte", ErrInvalidEnvVar)
			}
		}
		envVars = parsed
	}

	resolved, err := catalog.ResolveForCreate(templateSelector)
	if err != nil {
		return nil, err
	}
	rawTimeout, hasTimeout := fields["timeout"]
	timeoutDecision, err := EvaluateTimeout(TimeoutOpCreate, hasTimeout, rawTimeout, resolved.Timeout)
	if err != nil {
		return nil, err
	}
	nativeMeta, err := EncodeSandboxMetadata(MetadataEncodeInput{
		AdapterID:      adapterID,
		Revision:       resolved.Revision,
		HMACKeyVersion: keyVersion,
		UserMetadata:   userMeta,
	})
	if err != nil {
		return nil, err
	}
	return &ValidatedCreateRequest{
		Template:       resolved,
		TimeoutSeconds: timeoutDecision.EffectiveSeconds,
		NativeMetadata: nativeMeta,
		UserMetadata:   userMeta,
		EnvVars:        envVars,
	}, nil
}

func decodeUniqueObjectFields(fieldName string, data []byte) (map[string]json.RawMessage, error) {
	if bytes.Equal(trimJSONSpace(data), []byte("null")) {
		return nil, fmt.Errorf("%w: %s must not be null", ErrInvalidCreateRequest, fieldName)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %s is malformed JSON", ErrInvalidCreateRequest, fieldName)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("%w: %s must be a JSON object", ErrInvalidCreateRequest, fieldName)
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %s has malformed key", ErrInvalidCreateRequest, fieldName)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %s has malformed key", ErrInvalidCreateRequest, fieldName)
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidCreateRequest, fieldName, ErrDuplicateField)
		}
		var rawVal json.RawMessage
		if err := dec.Decode(&rawVal); err != nil {
			return nil, fmt.Errorf("%w: %s has malformed value", ErrInvalidCreateRequest, fieldName)
		}
		fields[key] = rawVal
	}
	if endTok, err := dec.Token(); err != nil || endTok != json.Delim('}') {
		return nil, fmt.Errorf("%w: %s is unclosed", ErrInvalidCreateRequest, fieldName)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: unexpected trailing data", ErrInvalidCreateRequest)
	}
	return fields, nil
}

func decodeStrictString(fieldName string, raw json.RawMessage) (string, error) {
	trimmed := trimJSONSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '"' {
		return "", fmt.Errorf("%w: %s must be a JSON string", ErrInvalidCreateRequest, fieldName)
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err != nil {
		return "", fmt.Errorf("%w: %s must be a valid JSON string", ErrInvalidCreateRequest, fieldName)
	}
	return s, nil
}

func decodeStrictBool(fieldName string, raw json.RawMessage) (bool, error) {
	trimmed := trimJSONSpace(raw)
	if bytes.Equal(trimmed, []byte("true")) {
		return true, nil
	}
	if bytes.Equal(trimmed, []byte("false")) {
		return false, nil
	}
	return false, fmt.Errorf("%w: %s must be a boolean", ErrInvalidCreateRequest, fieldName)
}

func decodeStrictStringMap(fieldName string, raw json.RawMessage) (map[string]string, error) {
	rawMap, err := decodeUniqueObjectFields(fieldName, raw)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rawMap))
	for _, k := range slices.Sorted(maps.Keys(rawMap)) {
		val, err := decodeStrictString(fieldName+" value", rawMap[k])
		if err != nil {
			return nil, err
		}
		out[k] = val
	}
	return out, nil
}
