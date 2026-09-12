// Copyright 2026 Alibaba Group Holding Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package publicegress

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

const EnvPolicy = "OPENSANDBOX_EGRESS_PUBLIC_POLICY"

// Strict services bind privileged backend ports. The old high-port control
// and DNS addresses are persistent NAT frontends, never trusted listeners.
const DNSListenAddr = "127.0.0.1:353"
const ControlPort = 380
const MITMPort = 381

func IsReservedPort(port uint16) bool {
	return port == 53 || port == 353 || port == ControlPort || port == MITMPort || port == 15353 || port == 18080 || port == 18081
}

// Config is an operator-owned contract, never a sandbox networkPolicy field.
// All destinations are mediated; InternalTargets is not a kernel bypass for apps.
type Config struct {
	Version         int              `json:"version"`
	DNSServers      []string         `json:"dns_servers"`
	InternalTargets []InternalTarget `json:"internal_targets"`
}

type InternalTarget struct {
	Host  string   `json:"host"`
	IPs   []string `json:"ips"`
	Ports []uint16 `json:"ports"`
}

var hostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func Parse(raw string) (*Config, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	if len(raw) > 32768 {
		return nil, fmt.Errorf("public policy exceeds 32 KiB")
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	var c Config
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("invalid public policy: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("public policy has trailing JSON")
	}
	if c.Version != 1 || len(c.DNSServers) == 0 || len(c.DNSServers) > 8 || len(c.InternalTargets) > 128 {
		return nil, fmt.Errorf("public policy requires version 1, 1..8 pinned DNS servers and at most 128 internal targets")
	}
	for _, s := range c.DNSServers {
		if !validIP(s) {
			return nil, fmt.Errorf("public policy DNS server must be a unicast IPv4 address")
		}
	}
	seen := map[string]bool{}
	for _, t := range c.InternalTargets {
		if len(t.Host) > 253 || !hostname.MatchString(t.Host) || seen[t.Host] {
			return nil, fmt.Errorf("public policy requires unique canonical DNS hosts")
		}
		if _, err := netip.ParseAddr(t.Host); err == nil {
			return nil, fmt.Errorf("public policy host cannot be an IP")
		}
		seen[t.Host] = true
		if len(t.IPs) == 0 || len(t.IPs) > 32 || len(t.Ports) == 0 || len(t.Ports) > 32 {
			return nil, fmt.Errorf("internal target requires bounded nonempty IP and port lists")
		}
		for _, ip := range t.IPs {
			if !validIP(ip) {
				return nil, fmt.Errorf("internal target must use unicast IPv4 addresses")
			}
		}
		for _, p := range t.Ports {
			if p == 0 || IsReservedPort(p) {
				return nil, fmt.Errorf("internal target uses a reserved port")
			}
		}
	}
	return &c, nil
}

func validIP(s string) bool {
	if s == "100.100.100.200" || s == "168.63.129.16" {
		return false
	}
	ip, err := netip.ParseAddr(s)
	return err == nil && ip.Is4() && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !strings.HasPrefix(s, "0.") && !strings.HasPrefix(s, "240.") && ip.As4()[0] < 224
}

func (c *Config) InterceptPorts() []uint16 {
	ports := map[uint16]bool{80: true, 443: true}
	for _, t := range c.InternalTargets {
		for _, p := range t.Ports {
			ports[p] = true
		}
	}
	out := make([]uint16, 0, len(ports))
	for p := range ports {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
