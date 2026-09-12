package telemetry

import (
	"context"
	"go.opentelemetry.io/otel/attribute"
)

// RecordPublicEvent accepts a closed set. Destinations, identifiers, paths,
// gateway error text and credential material can never become metric labels.
func RecordPublicEvent(outcome string) {
	switch outcome {
	case "route_public", "route_internal", "destination_denied", "identity_denied", "gateway_connect_failed", "gateway_tls_failed", "gateway_connect_denied", "gateway_grant_denied", "gateway_rate_limited":
	default:
		return
	}
	if publicEvents != nil {
		publicEvents.Add(context.Background(), 1, egressMetricOptWith(attribute.String("outcome", outcome)))
	}
}
