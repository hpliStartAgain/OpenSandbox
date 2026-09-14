// Copyright 2026 Alibaba Group Holding Ltd.
// Licensed under the Apache License, Version 2.0.

//go:build !linux

package mitmproxy

import "syscall"

// Launch rejects non-Linux platforms before this helper is called. Keeping a
// no-op definition lets package tests and static analysis compile elsewhere.
func setAmbientNetBindService(_ *syscall.SysProcAttr) {}
