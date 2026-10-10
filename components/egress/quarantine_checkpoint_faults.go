//go:build egress_quarantine_faults

// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Only the separately tagged CI image contains this deterministic crash seam.
// It pauses after a durable boundary without changing any production outcome.
func quarantineCheckpoint(stage string) {
	if os.Getenv("OPENSANDBOX_EGRESS_TEST_QUARANTINE_PAUSE") != stage {
		return
	}
	if err := os.WriteFile(filepath.Join(quarantineDirectory, "checkpoint"), []byte(stage), 0600); err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, "quarantine test checkpoint:", stage)
	for {
		time.Sleep(time.Second)
	}
}
