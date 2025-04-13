// Copyright 2024 The ADK Authors
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

package observability

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

var (
	meter         metric.Meter
	meterOnce     sync.Once
	tokenCounter  metric.Int64Counter
	latencyHist   metric.Float64Histogram
	requestsCount metric.Int64Counter
	failureCount  metric.Int64Counter
)

// InitMeter initializes the OpenTelemetry meter provider.
// It returns a shutdown function that should be called when the program exits.
func InitMeter(ctx context.Context, svcName string) (func(context.Context) error, error) {
	if svcName == "" {
		svcName = serviceName
	}

	// Create stdout exporter
	exporter, err := stdoutmetric.New()
	if err != nil {
		return nil, err
	}

	// Create resource
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(svcName),
		),
	)
	if err != nil {
		return nil, err
	}

	// Create meter provider
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(15*time.Second))),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	meterOnce.Do(func() {
		meter = otel.Meter("github.com/go-a2a/adk-go")

		var err error

		// Initialize counters and histograms
		tokenCounter, err = meter.Int64Counter(
			"token_count",
			metric.WithDescription("Number of tokens processed"),
			metric.WithUnit("tokens"),
		)
		if err != nil {
			slog.Error("Failed to create token counter", slog.Any("error", err))
		}

		latencyHist, err = meter.Float64Histogram(
			"request_latency",
			metric.WithDescription("Latency of requests"),
			metric.WithUnit("ms"),
		)
		if err != nil {
			slog.Error("Failed to create latency histogram", slog.Any("error", err))
		}

		requestsCount, err = meter.Int64Counter(
			"requests_total",
			metric.WithDescription("Total number of requests"),
			metric.WithUnit("1"),
		)
		if err != nil {
			slog.Error("Failed to create requests counter", slog.Any("error", err))
		}

		failureCount, err = meter.Int64Counter(
			"failures_total",
			metric.WithDescription("Total number of failures"),
			metric.WithUnit("1"),
		)
		if err != nil {
			slog.Error("Failed to create failures counter", slog.Any("error", err))
		}
	})

	slog.Info("Meter initialized", "service", svcName)

	return mp.Shutdown, nil
}

// RecordTokens records the number of tokens processed.
func RecordTokens(ctx context.Context, count int64, attrs ...attribute.KeyValue) {
	if tokenCounter != nil {
		tokenCounter.Add(ctx, count, metric.WithAttributes(attrs...))
	}
}

// RecordLatency records the latency of a request.
func RecordLatency(ctx context.Context, duration time.Duration, attrs ...attribute.KeyValue) {
	if latencyHist != nil {
		latencyHist.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(attrs...))
	}
}

// IncrementRequests increments the number of requests.
func IncrementRequests(ctx context.Context, attrs ...attribute.KeyValue) {
	if requestsCount != nil {
		requestsCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// IncrementFailures increments the number of failures.
func IncrementFailures(ctx context.Context, attrs ...attribute.KeyValue) {
	if failureCount != nil {
		failureCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// MeasureLatency records the latency of a function execution.
func MeasureLatency(ctx context.Context, operation string, attrs ...attribute.KeyValue) func() {
	start := time.Now()
	IncrementRequests(ctx, append(attrs, attribute.String("operation", operation))...)

	return func() {
		duration := time.Since(start)
		RecordLatency(ctx, duration, append(attrs, attribute.String("operation", operation))...)
	}
}
