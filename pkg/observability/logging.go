// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// LogLevel represents the logging level.
type LogLevel int

const (
	// LevelDebug is the debug log level.
	LevelDebug LogLevel = iota
	// LevelInfo is the info log level.
	LevelInfo
	// LevelWarn is the warning log level.
	LevelWarn
	// LevelError is the error log level.
	LevelError
)

// LoggerKey is the context key for storing a logger.
type loggerKeyType struct{}

// LoggerKey is the key for storing a logger in the context.
var LoggerKey = loggerKeyType{}

// LoggerOptions represents options for configuring the logger.
type LoggerOptions struct {
	// Level is the minimum log level that will be output.
	Level LogLevel
	// Writer is where logs will be written to.
	Writer io.Writer
	// AddSource adds source code location to log lines.
	AddSource bool
	// JSONFormat outputs logs in JSON format instead of text.
	JSONFormat bool
}

// defaultOptions returns the default logging options.
func defaultOptions() LoggerOptions {
	return LoggerOptions{
		Level:      LevelInfo,
		Writer:     os.Stdout,
		AddSource:  false,
		JSONFormat: false,
	}
}

// SetupLogger initializes the global logger with the specified options.
func SetupLogger(opts LoggerOptions) {
	var level slog.Level
	switch opts.Level {
	case LevelDebug:
		level = slog.LevelDebug
	case LevelInfo:
		level = slog.LevelInfo
	case LevelWarn:
		level = slog.LevelWarn
	case LevelError:
		level = slog.LevelError
	}

	handlerOpts := &slog.HandlerOptions{
		Level:     level,
		AddSource: opts.AddSource,
	}

	var handler slog.Handler
	if opts.JSONFormat {
		handler = slog.NewJSONHandler(opts.Writer, handlerOpts)
	} else {
		handler = slog.NewTextHandler(opts.Writer, handlerOpts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
}

// Logger returns a new slog.Logger with trace context if available.
func Logger(ctx context.Context) *slog.Logger {
	// Check if there's a logger in the context
	if logger, ok := ctx.Value(LoggerKey).(*slog.Logger); ok {
		return logger
	}

	// Use default logger with trace info
	logger := slog.Default()
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		traceID := span.SpanContext().TraceID().String()
		spanID := span.SpanContext().SpanID().String()

		logger = logger.With(
			slog.String("trace_id", traceID),
			slog.String("span_id", spanID),
		)
	}
	return logger
}

// WithContext logs the message with the context.
func WithContext(ctx context.Context, level slog.Level, msg string, args ...any) {
	Logger(ctx).Log(ctx, level, msg, args...)
}

// Error logs an error message and records it in the active span.
func Error(ctx context.Context, err error, msg string, args ...any) {
	// Add error to the active span
	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
	span.SetStatus(codes.Error, msg)

	// Add error to the log
	allArgs := append([]any{slog.Any("error", err)}, args...)
	Logger(ctx).Error(msg, allArgs...)
}

// LogSpanEvent adds an event to the current span and logs it if level >= configured level.
func LogSpanEvent(ctx context.Context, level slog.Level, name string, attributes ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(attributes...))

	if len(attributes) > 0 {
		attrMap := make(map[string]any, len(attributes))
		for _, attr := range attributes {
			attrMap[string(attr.Key)] = attr.Value.AsInterface()
		}
		Logger(ctx).Log(ctx, level, name, slog.Any("attributes", attrMap))
	} else {
		Logger(ctx).Log(ctx, level, name)
	}
}

// MeasureExecutionTime returns a function that logs the execution time when called.
func MeasureExecutionTime(ctx context.Context, operation string) func() {
	span := trace.SpanFromContext(ctx)
	start := time.Now()

	return func() {
		duration := time.Since(start)
		span.AddEvent("execution_time", trace.WithAttributes(
			attribute.String("operation", operation),
			attribute.Int64("duration_ms", duration.Milliseconds()),
		))

		Logger(ctx).Info("operation completed",
			slog.String("operation", operation),
			slog.Duration("duration", duration),
		)
	}
}
