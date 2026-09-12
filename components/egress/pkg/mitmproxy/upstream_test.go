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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/stretchr/testify/require"
)

func TestFileIdentityPreflight(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1)}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	require.NoError(t, err)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0600))
	invalidCA := filepath.Join(t.TempDir(), "invalid.pem")
	require.NoError(t, os.WriteFile(invalidCA, []byte("not a PEM certificate"), 0600))
	t.Setenv(constants.EnvUpstreamProxy, "https://gateway.example:443")
	t.Setenv(constants.EnvUpstreamProxyCAFile, ca)
	t.Setenv(constants.EnvUpstreamProxyIdentityFile, filepath.Join(t.TempDir(), "not-issued-yet.jwt"))
	t.Setenv(constants.EnvUpstreamProxyAuth, "")
	t.Setenv(constants.EnvMitmproxySslInsecure, "")
	t.Setenv(constants.EnvMitmproxyScript, "")
	_, err = UpstreamProxyFromEnv()
	require.NoError(t, err, "missing identity must not block startup")
	for _, tc := range []struct{ key, value string }{
		{constants.EnvUpstreamProxy, "http://gateway.example"},
		{constants.EnvUpstreamProxy, "https://127.0.0.1"},
		{constants.EnvUpstreamProxyAuth, "sensitive-inline-value"},
		{constants.EnvMitmproxySslInsecure, "true"},
		{constants.EnvMitmproxyScript, "/untrusted.py"},
		{constants.EnvUpstreamProxyCAFile, "missing-ca"},
		{constants.EnvUpstreamProxyCAFile, invalidCA},
		{constants.EnvUpstreamProxyIdentityFile, ""},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			_, err := UpstreamProxyFromEnv()
			require.Error(t, err)
			require.NotContains(t, err.Error(), "sensitive-inline-value")
		})
	}
}

func TestFileIdentityReadinessRequiresAddonAcknowledgement(t *testing.T) {
	t.Setenv(constants.EnvUpstreamProxyIdentityFile, "/private/identity.jwt")
	require.Contains(t, buildMitmdumpEnv(nil, "/home/mitmproxy"), "PYTHONUNBUFFERED=1")
	ready, exited := make(chan struct{}, 1), make(chan error, 1)
	require.Error(t, waitUpstreamProxyReady(ready, exited, time.Millisecond))
	exited <- errors.New("process exited")
	require.Error(t, waitUpstreamProxyReady(ready, exited, time.Second))
	for _, incomplete := range []string{
		"upstream proxy: ready\n",
		"credential proxy: system addon ready\n",
		"upstream proxy: ready\ncredential proxy: system addon ready\n",
	} {
		forwardMitmdumpOutput(io.NopCloser(strings.NewReader(incomplete)), ready)
		require.Error(t, waitUpstreamProxyReady(ready, exited, time.Millisecond))
	}
	forwardMitmdumpOutput(io.NopCloser(strings.NewReader("[12:00:00.000] credential proxy: system addon ready\n[12:00:00.001] upstream proxy: ready\n")), ready)
	require.NoError(t, waitUpstreamProxyReady(ready, exited, time.Second))
}

func TestParseUpstreamProxyValid(t *testing.T) {
	tests := []struct {
		raw    string
		scheme string
		host   string
		port   int
	}{
		{"http://proxy.example.com:3128", "http", "proxy.example.com", 3128},
		{"https://proxy.example.com:8443", "https", "proxy.example.com", 8443},
		{"http://proxy.example.com", "http", "proxy.example.com", 80},
		{"https://proxy.example.com", "https", "proxy.example.com", 443},
		{"http://10.0.0.1:3128", "http", "10.0.0.1", 3128},
		{"http://[fd00::1]:3128", "http", "fd00::1", 3128},
		{"  http://proxy.example.com:3128  ", "http", "proxy.example.com", 3128},
	}
	for _, tc := range tests {
		spec, err := parseUpstreamProxy(tc.raw)
		require.NoError(t, err, tc.raw)
		require.Equal(t, tc.scheme, spec.Scheme, tc.raw)
		require.Equal(t, tc.host, spec.Host, tc.raw)
		require.Equal(t, tc.port, spec.Port, tc.raw)
	}
}

func TestParseUpstreamProxyRejectsInvalid(t *testing.T) {
	tests := []string{
		"",
		"   ",
		"proxy.example.com:3128",          // missing scheme
		"socks5://proxy.example.com:1080", // unsupported scheme
		"http://",                         // missing host
		"http:///path",                    // missing host
		"http://user:pass@proxy:3128",     // userinfo must not carry credentials
		"http://proxy:3128?x=1",           // query not meaningful for CONNECT
		"http://proxy:3128#frag",          // fragment not meaningful
		"http://proxy:notaport",           // invalid port
		"http://proxy:0",                  // port out of range
		"http://proxy:70000",              // port out of range
	}
	for _, raw := range tests {
		_, err := parseUpstreamProxy(raw)
		require.Error(t, err, raw)
	}
}
