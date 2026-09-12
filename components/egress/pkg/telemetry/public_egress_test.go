package telemetry

import (
	"context"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"testing"
)

func TestPublicEventsHaveFiniteLabels(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	old := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(old) })
	require.NoError(t, registerEgressMetrics())
	RecordPublicEvent("route_public")
	RecordPublicEvent("identity_denied")
	RecordPublicEvent("gateway_tls_failed")
	RecordPublicEvent("secret.example/path?token=private")
	RecordPublicEvent("identity_denied token=private")
	var result metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &result))
	found := false
	for _, scope := range result.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name == "egress.public.events_total" {
				found = true
				sum := m.Data.(metricdata.Sum[int64])
				require.Len(t, sum.DataPoints, 3)
				for _, point := range sum.DataPoints {
					require.Equal(t, len(egressSharedAttrs())+1, point.Attributes.Len())
				}
			}
		}
	}
	require.True(t, found)
}
