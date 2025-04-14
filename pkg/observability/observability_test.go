// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package observability_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/go-a2a/adk-go/pkg/observability"
)

// TestLogger tests the Logger function and ensures it returns a slog.Logger
func TestLogger(t *testing.T) {
	// Test with default context
	ctx := context.Background()
	logger := observability.Logger(ctx)
	if logger == nil {
		t.Fatalf("logger is nil, want non-nil")
	}

	// Test with context containing a logger
	var buf bytes.Buffer
	testLogger := slog.New(slog.NewJSONHandler(&buf, nil))
	ctx = context.WithValue(ctx, observability.LoggerKey, testLogger)

	logger = observability.Logger(ctx)
	if logger == nil {
		t.Fatalf("logger is nil, want non-nil")
	}
	// We can't directly compare loggers with cmp.Equal due to unexported fields
	// Instead, let's verify that the logger from context is returned correctly
	if logger != testLogger {
		t.Errorf("logger != testLogger")
	}
}

// TestError tests the Error function for logging errors
func TestError(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	testLogger := slog.New(handler)

	ctx := context.WithValue(context.Background(), observability.LoggerKey, testLogger)

	// Log an error
	testErr := errors.New("test error")
	observability.Error(ctx, testErr, "Error occurred", slog.String("key", "value"))

	// Verify log output
	logOutput := buf.String()
	if !strings.Contains(logOutput, "Error occurred") {
		t.Errorf("logOutput does not contain %q", "Error occurred")
	}
	if !strings.Contains(logOutput, "test error") {
		t.Errorf("logOutput does not contain %q", "test error")
	}
	if !strings.Contains(logOutput, "key") {
		t.Errorf("logOutput does not contain %q", "key")
	}
	if !strings.Contains(logOutput, "value") {
		t.Errorf("logOutput does not contain %q", "value")
	}
}

// TestStartSpan tests the StartSpan function
func TestStartSpan(t *testing.T) {
	ctx := context.Background()

	// Create a span
	ctx, span := observability.StartSpan(ctx, "test_span")
	if span == nil {
		t.Fatalf("span is nil, want non-nil")
	}

	// Note: In a test environment without a proper OpenTelemetry setup,
	// SpanContextFromContext may not be valid.
	// We'll just check that a span was created, which is the most important part

	span.End()
}

// TestMeasureLatency tests the MeasureLatency function
func TestMeasureLatency(t *testing.T) {
	ctx := context.Background()

	// Measure latency
	endFunc := observability.MeasureLatency(ctx, "test_operation",
		attribute.String("key", "value"))

	// Simulate some work
	time.Sleep(10 * time.Millisecond)

	// End the measurement
	endFunc()

	// In a real test, we would verify metrics recording
	// This test mainly checks that the function doesn't panic
}

// TestIncrementRequests tests the IncrementRequests function
func TestIncrementRequests(t *testing.T) {
	ctx := context.Background()

	// Increment request count
	observability.IncrementRequests(ctx,
		attribute.String("service", "test"),
		attribute.String("operation", "test_op"))

	// In a real test, we would verify metrics recording
	// This test mainly checks that the function doesn't panic
}

// TestIncrementFailures tests the IncrementFailures function
func TestIncrementFailures(t *testing.T) {
	ctx := context.Background()

	// Increment failure count
	observability.IncrementFailures(ctx,
		attribute.String("service", "test"),
		attribute.String("error_type", "test_error"))

	// In a real test, we would verify metrics recording
	// This test mainly checks that the function doesn't panic
}

// TestRecordTokens tests the RecordTokens function
func TestRecordTokens(t *testing.T) {
	ctx := context.Background()

	// Record token count
	observability.RecordTokens(ctx, 100,
		attribute.String("model", "test_model"),
		attribute.String("token_type", "output"))

	// In a real test, we would verify metrics recording
	// This test mainly checks that the function doesn't panic
}

// For a complete test suite, we would add integration tests with actual
// OpenTelemetry exporters to verify the metrics and traces are correctly recorded
// These tests would typically be marked as integration tests and run separately
