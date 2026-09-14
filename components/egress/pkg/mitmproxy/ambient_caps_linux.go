// Copyright 2026 Alibaba Group Holding Ltd.
// Licensed under the Apache License, Version 2.0.

//go:build linux

package mitmproxy

import "syscall"

func setAmbientNetBindService(attributes *syscall.SysProcAttr) {
	attributes.AmbientCaps = []uintptr{10} // CAP_NET_BIND_SERVICE
}
