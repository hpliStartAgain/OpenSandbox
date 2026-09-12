// Copyright 2026 Alibaba Group Holding Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package main

import (
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
)

func TestPublicEgressStartupRequiresProtectedPortAndControlIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, port, token, identity string
		valid                       bool
	}{
		{"default", "", "fixture", "/fixture/identity.jwt", true},
		{"backend", "381", "fixture", "/fixture/identity.jwt", true},
		{"old-port", "18081", "fixture", "/fixture/identity.jwt", false},
		{"invalid-port", "typo", "fixture", "/fixture/identity.jwt", false},
		{"no-token", "381", "", "/fixture/identity.jwt", false},
		{"blank-token", "381", " ", "/fixture/identity.jwt", false},
		{"no-identity", "381", "fixture", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(constants.EnvMitmproxyPort, tc.port)
			t.Setenv(constants.EnvEgressToken, tc.token)
			t.Setenv(constants.EnvUpstreamProxyIdentityFile, tc.identity)
			if err := validatePublicEgressStartup(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
