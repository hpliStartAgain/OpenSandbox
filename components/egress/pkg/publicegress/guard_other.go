// Copyright 2026 Alibaba Group Holding Ltd.
// Licensed under the Apache License, Version 2.0.

//go:build !linux

package publicegress

import (
	"context"
	"fmt"
	"time"
)

// Guard is a compile-time placeholder outside Linux. The egress process
// rejects transparent operation on non-Linux platforms before installation.
type Guard struct{}

func Install(context.Context, *Config, uint16) (*Guard, error) {
	return nil, fmt.Errorf("public egress isolation is only supported on linux")
}

func InstallNonRootUID(context.Context, *Config, uint16, uint32) (*Guard, error) {
	return nil, fmt.Errorf("public egress isolation is only supported on linux")
}

func (*Guard) SetGatewayIPs(context.Context, []string, time.Duration) error {
	return fmt.Errorf("public egress isolation is only supported on linux")
}
