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
	"maps"
	"slices"
	"strings"
)

const (
	MetadataReservedPrefix = "e2b-shim-"
	NativeReservedPrefix   = "opensandbox.io/"
	MetaKeyManaged         = "e2b-shim-managed"
	MetaKeySchema          = "e2b-shim-schema"
	MetaKeyAdapterID       = "e2b-shim-adapter"
	MetaKeyRevision        = "e2b-shim-revision"
	MetaKeyHMACKeyVersion  = "e2b-shim-key-ver"
	MetaSchemaV1           = "v1"
	MaxLabelLength         = 63
)

var (
	ErrInvalidMetadataKey   = errors.New("rules: invalid metadata key")
	ErrReservedMetadataKey  = errors.New("rules: reserved metadata key")
	ErrInvalidMetadataValue = errors.New("rules: invalid metadata value")
)

type OwnershipReason string

const (
	OwnershipOK                 OwnershipReason = ""
	OwnershipMissingMetadata    OwnershipReason = "missing_metadata"
	OwnershipMissingMarker      OwnershipReason = "missing_marker"
	OwnershipUnsupportedSchema  OwnershipReason = "unsupported_schema"
	OwnershipAdapterMismatch    OwnershipReason = "adapter_mismatch"
	OwnershipKeyVersionMismatch OwnershipReason = "key_version_mismatch"
	OwnershipMissingRevision    OwnershipReason = "missing_revision"
	OwnershipUnknownRevision    OwnershipReason = "unknown_revision"
)

type MetadataEncodeInput struct {
	AdapterID      string
	Revision       string
	HMACKeyVersion string
	UserMetadata   map[string]string
}

type OwnershipResult struct {
	Owned        bool
	Reason       OwnershipReason
	Revision     string
	Template     ResolvedTemplate
	UserMetadata map[string]string
}

func ValidateMetadataKey(key string) error {
	if strings.HasPrefix(key, NativeReservedPrefix) || strings.HasPrefix(key, MetadataReservedPrefix) {
		return ErrReservedMetadataKey
	}
	if len(key) == 0 || len(key) > MaxLabelLength || !isDNSLabel(key) {
		return ErrInvalidMetadataKey
	}
	return nil
}

func ValidateLabelValue(value string) error {
	if len(value) == 0 || len(value) > MaxLabelLength || !isLabelValue(value) {
		return ErrInvalidMetadataValue
	}
	return nil
}

func EncodeSandboxMetadata(in MetadataEncodeInput) (map[string]string, error) {
	if err := ValidateLabelValue(in.AdapterID); err != nil {
		return nil, fmt.Errorf("adapter_id: %w", err)
	}
	if err := ValidateLabelValue(in.Revision); err != nil {
		return nil, fmt.Errorf("revision: %w", err)
	}
	if err := ValidateLabelValue(in.HMACKeyVersion); err != nil {
		return nil, fmt.Errorf("hmac_key_version: %w", err)
	}
	keys := slices.Sorted(maps.Keys(in.UserMetadata))
	for _, k := range keys {
		if err := ValidateMetadataKey(k); err != nil {
			return nil, err
		}
		if err := ValidateLabelValue(in.UserMetadata[k]); err != nil {
			return nil, err
		}
	}
	out := make(map[string]string, len(in.UserMetadata)+5)
	for _, k := range keys {
		out[k] = in.UserMetadata[k]
	}
	out[MetaKeyManaged] = "true"
	out[MetaKeySchema] = MetaSchemaV1
	out[MetaKeyAdapterID] = in.AdapterID
	out[MetaKeyRevision] = in.Revision
	out[MetaKeyHMACKeyVersion] = in.HMACKeyVersion
	return out, nil
}

func DecodeSandboxOwnership(raw map[string]string, expectedAdapterID, expectedKeyVersion string, catalog *TemplateCatalog) OwnershipResult {
	if len(raw) == 0 {
		return OwnershipResult{Reason: OwnershipMissingMetadata}
	}
	if raw[MetaKeyManaged] != "true" {
		return OwnershipResult{Reason: OwnershipMissingMarker}
	}
	if raw[MetaKeySchema] != MetaSchemaV1 {
		return OwnershipResult{Reason: OwnershipUnsupportedSchema}
	}
	if ValidateLabelValue(expectedAdapterID) != nil || raw[MetaKeyAdapterID] != expectedAdapterID {
		return OwnershipResult{Reason: OwnershipAdapterMismatch}
	}
	if ValidateLabelValue(expectedKeyVersion) != nil || raw[MetaKeyHMACKeyVersion] != expectedKeyVersion {
		return OwnershipResult{Reason: OwnershipKeyVersionMismatch}
	}
	rev := raw[MetaKeyRevision]
	if rev == "" {
		return OwnershipResult{Reason: OwnershipMissingRevision}
	}
	if catalog == nil {
		return OwnershipResult{Reason: OwnershipUnknownRevision}
	}
	tpl, err := catalog.ResolveByRevision(rev)
	if err != nil {
		return OwnershipResult{Reason: OwnershipUnknownRevision}
	}
	userMeta := make(map[string]string)
	for k, v := range raw {
		if strings.HasPrefix(k, MetadataReservedPrefix) || strings.HasPrefix(k, NativeReservedPrefix) {
			continue
		}
		userMeta[k] = v
	}
	return OwnershipResult{
		Owned:        true,
		Reason:       OwnershipOK,
		Revision:     rev,
		Template:     tpl,
		UserMetadata: userMeta,
	}
}

func isLowerAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func isASCIIAlphaNum(b byte) bool {
	return isLowerAlphaNum(b) || (b >= 'A' && b <= 'Z')
}

func isDNSLabel(s string) bool {
	if !isLowerAlphaNum(s[0]) || !isLowerAlphaNum(s[len(s)-1]) {
		return false
	}
	for i := 1; i < len(s)-1; i++ {
		b := s[i]
		if !isLowerAlphaNum(b) && b != '-' {
			return false
		}
	}
	return true
}

func isLabelValue(s string) bool {
	if !isASCIIAlphaNum(s[0]) || !isASCIIAlphaNum(s[len(s)-1]) {
		return false
	}
	for i := 1; i < len(s)-1; i++ {
		b := s[i]
		if !isASCIIAlphaNum(b) && b != '-' && b != '_' && b != '.' {
			return false
		}
	}
	return true
}
