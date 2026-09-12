package mitmproxy

import "regexp"

var publicDenial = regexp.MustCompile(`^public policy: denied EGRESS_PUBLIC_POLICY_[A-Z_]{1,64}$`)
var identityDenial = regexp.MustCompile(`^upstream proxy: identity denied EGRESS_IDENTITY_[A-Z_]{1,32}$`)

// Only this deliberately tiny protocol crosses the mitmdump log pipe. Never
// forward HTTP flow dumps, arbitrary gateway status text or response headers.
func publicEvent(message string) string {
	switch message {
	case "public policy: route public":
		return "route_public"
	case "public policy: route internal":
		return "route_internal"
	case "upstream proxy: gateway_connect_failed":
		return "gateway_connect_failed"
	case "upstream proxy: gateway_tls_failed":
		return "gateway_tls_failed"
	case "upstream proxy: gateway_connect_denied":
		return "gateway_connect_denied"
	case "upstream proxy: gateway_grant_denied":
		return "gateway_grant_denied"
	case "upstream proxy: gateway_rate_limited":
		return "gateway_rate_limited"
	}
	if publicDenial.MatchString(message) {
		return "destination_denied"
	}
	if identityDenial.MatchString(message) {
		return "identity_denied"
	}
	return ""
}
