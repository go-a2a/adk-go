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
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	serviceName = "adk-go"
)

// InitTracer initializes the OpenTelemetry tracer provider with the given service name.
// It returns a shutdown function that should be called when the program exits.
func InitTracer(ctx context.Context, svcName string) (func(context.Context) error, error) {
	if svcName == "" {
		svcName = serviceName
	}

	// Create stdout exporter
	exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
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

	// Create trace provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)

	// Set global propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	slog.Info("Tracer initialized", "service", svcName)

	return tp.Shutdown, nil
}

// Tracer returns a named tracer from the global provider.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

// StartSpan starts a new span with the given name and returns the context with the span.
func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return Tracer("github.com/go-a2a/adk-go").Start(ctx, name)
}

// WithSpan executes the given function within a new span.
func WithSpan(ctx context.Context, name string, fn func(context.Context) error) error {
	ctx, span := StartSpan(ctx, name)
	defer span.End()

	startTime := time.Now()
	err := fn(ctx)
	duration := time.Since(startTime)

	if err != nil {
		span.RecordError(err)
		WithContext(ctx, slog.LevelError, "operation failed",
			slog.String("span", name),
			slog.Duration("duration", duration),
			slog.Any("error", err),
		)
		return err
	}

	span.SetAttributes(attribute.Int64("duration_ms", duration.Milliseconds()))
	WithContext(ctx, slog.LevelDebug, "operation completed",
		slog.String("span", name),
		slog.Duration("duration", duration),
	)

	return nil
}

// AddSpanAttributes adds attributes to the current span.
func AddSpanAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attrs...)
}
