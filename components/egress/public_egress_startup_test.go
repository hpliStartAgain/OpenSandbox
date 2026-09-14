// Copyright 2026 Alibaba Group Holding Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestPublicEgressStartupRejectsUnknownIsolationMode(t *testing.T) {
	t.Setenv(constants.EnvMitmproxyPort, "381")
	t.Setenv(constants.EnvEgressToken, "fixture")
	t.Setenv(constants.EnvUpstreamProxyIdentityFile, "/fixture/identity.jwt")
	t.Setenv(constants.EnvPublicIsolationMode, "auto")
	if err := validatePublicEgressStartup(); err == nil {
		t.Fatal("accepted automatic isolation downgrade")
	}
}

func TestPublicEgressReadyMarkerIsAtomicAndResettable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public-egress-ready")
	if err := writePublicEgressReadyMarkerAt(path); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "ready\n" {
		t.Fatalf("content=%q err=%v", content, err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary marker remains: %v", err)
	}
	if err := resetPublicEgressReadyMarkerAt(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("ready marker remains: %v", err)
	}
}

func TestPublicEgressCompatibilityGateWaitsForProtectedFiles(t *testing.T) {
	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.pem")
	markerPath := filepath.Join(directory, "ready")
	if err := os.WriteFile(caPath, []byte("ca"), 0444); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := waitForPublicEgressFiles(
		ctx, caPath, markerPath, uint32(os.Getuid()), time.Millisecond,
	); err == nil {
		t.Fatal("gate passed without the ready marker")
	}
	if err := os.WriteFile(markerPath, []byte("ready"), 0444); err != nil {
		t.Fatal(err)
	}
	if err := waitForPublicEgressFiles(
		context.Background(), caPath, markerPath, uint32(os.Getuid()), time.Millisecond,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(markerPath, 0666); err != nil {
		t.Fatal(err)
	}
	if readyFileOwnedBy(markerPath, uint32(os.Getuid())) {
		t.Fatal("gate trusted a group/world-writable marker")
	}
}
