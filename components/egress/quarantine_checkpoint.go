//go:build !egress_quarantine_faults

// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0
package main

// Production images have no environment-triggered fault injection.
func quarantineCheckpoint(string) {}
