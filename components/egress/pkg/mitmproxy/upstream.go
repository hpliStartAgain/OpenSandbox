// Copyright 2026 Alibaba Group Holding Ltd.
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

package mitmproxy

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/publicegress"
)

// UpstreamProxySpec is the validated chained upstream proxy endpoint parsed
// from OPENSANDBOX_EGRESS_UPSTREAM_PROXY.
type UpstreamProxySpec struct {
	Scheme string // "http" or "https"
	Host   string
	Port   int
}

// upstreamProxyScriptPath is the bundled upstream-proxy addon shipped via the
// egress Dockerfile (COPY components/egress/mitmscripts /var/egress/mitmscripts).
// Loaded after system.py and before user addons when chaining is enabled.
const upstreamProxyScriptPath = "/var/egress/mitmscripts/upstream_proxy.py"

// UpstreamProxyFromEnv parses OPENSANDBOX_EGRESS_UPSTREAM_PROXY. It returns
// (nil, nil) when the env is unset and an error when the configuration is
// inconsistent (bad URL, or _AUTH without _PROXY).
func UpstreamProxyFromEnv() (*UpstreamProxySpec, error) {
	raw := strings.TrimSpace(os.Getenv(constants.EnvUpstreamProxy))
	identityFile := strings.TrimSpace(os.Getenv(constants.EnvUpstreamProxyIdentityFile))
	caFile := strings.TrimSpace(os.Getenv(constants.EnvUpstreamProxyCAFile))
	if raw == "" {
		if strings.TrimSpace(os.Getenv(constants.EnvUpstreamProxyAuth)) != "" || identityFile != "" || caFile != "" {
			return nil, fmt.Errorf("%s, %s or %s configured but %s is empty", constants.EnvUpstreamProxyAuth, constants.EnvUpstreamProxyIdentityFile, constants.EnvUpstreamProxyCAFile, constants.EnvUpstreamProxy)
		}
		return nil, nil
	}
	spec, err := parseUpstreamProxy(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", constants.EnvUpstreamProxy, err)
	}
	if identityFile != "" || caFile != "" {
		if identityFile == "" || caFile == "" || spec.Scheme != "https" || net.ParseIP(spec.Host) != nil || strings.TrimSpace(os.Getenv(constants.EnvUpstreamProxyAuth)) != "" {
			return nil, fmt.Errorf("upstream proxy file identity requires HTTPS with a DNS hostname, a gateway CA, and no inline authorization")
		}
		if constants.IsTruthy(os.Getenv(constants.EnvMitmproxySslInsecure)) {
			return nil, fmt.Errorf("upstream proxy file identity forbids ssl_insecure")
		}
		if strings.TrimSpace(os.Getenv(constants.EnvMitmproxyScript)) != "" {
			return nil, fmt.Errorf("upstream proxy file identity forbids additional mitmproxy scripts")
		}
		pem, err := os.ReadFile(caFile)
		if err != nil || !x509.NewCertPool().AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("upstream proxy gateway CA must be a readable PEM certificate bundle")
		}
		// Identity is deliberately not read here: missing approval/issuance must
		// not prevent local sandbox work or make readiness depend on a grant.
	}
	return &spec, nil
}

// validateUpstreamProxyEnv fails fast on inconsistent chained-proxy env
// configuration, before mitmdump is spawned: the addon cannot fix a bad spec
// at runtime, and a silent fallback to direct egress would be a policy hole.
func validateUpstreamProxyEnv() error {
	spec, err := UpstreamProxyFromEnv()
	if err != nil {
		return err
	}
	strict, err := publicegress.Parse(os.Getenv(publicegress.EnvPolicy))
	if err != nil {
		return err
	}
	if strict != nil && (spec == nil || strings.TrimSpace(os.Getenv(constants.EnvUpstreamProxyIdentityFile)) == "" || spec.Scheme != "https") {
		return fmt.Errorf("public egress requires HTTPS upstream with file identity")
	}
	return nil
}

// parseUpstreamProxy parses "scheme://host[:port]" into a spec. The port
// defaults to the URL scheme default (80 for http, 443 for https). Userinfo,
// query and fragment are rejected so the value can only ever carry an address;
// credentials belong exclusively in OPENSANDBOX_EGRESS_UPSTREAM_PROXY_AUTH.
func parseUpstreamProxy(raw string) (UpstreamProxySpec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return UpstreamProxySpec{}, fmt.Errorf("value is empty")
	}
	if !strings.Contains(raw, "://") {
		return UpstreamProxySpec{}, fmt.Errorf("missing scheme, want http://host:port or https://host:port")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return UpstreamProxySpec{}, fmt.Errorf("invalid proxy URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return UpstreamProxySpec{}, fmt.Errorf("unsupported scheme %q, want http or https", u.Scheme)
	}
	if u.User != nil {
		return UpstreamProxySpec{}, fmt.Errorf("userinfo is not allowed, use %s for credentials", constants.EnvUpstreamProxyAuth)
	}
	host := u.Hostname()
	if host == "" {
		return UpstreamProxySpec{}, fmt.Errorf("missing host")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return UpstreamProxySpec{}, fmt.Errorf("query and fragment are not allowed")
	}
	port := 0
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return UpstreamProxySpec{}, fmt.Errorf("invalid port %q", p)
		}
	} else if u.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	if strings.ContainsAny(host, " \t\r\n/@") {
		return UpstreamProxySpec{}, fmt.Errorf("invalid host %q", host)
	}
	return UpstreamProxySpec{Scheme: u.Scheme, Host: strings.ToLower(host), Port: port}, nil
}
