// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// Preprocessor adds authentication to requests before they're sent.
type Preprocessor struct {
	// handler is the authentication handler.
	handler *Handler

	// credentialsID is the ID of the credentials to use.
	credentialsID string

	// logger is the logger for preprocessing operations.
	logger *slog.Logger
}

// PreprocessorOption is a function that configures the Preprocessor.
type PreprocessorOption func(*Preprocessor)

// WithCredentialsID sets the credentials ID for the Preprocessor.
func WithCredentialsIDPreprocessorOption(id string) PreprocessorOption {
	return func(p *Preprocessor) {
		p.credentialsID = id
	}
}

// WithPreprocessorLogger sets the logger for the Preprocessor.
func WithPreprocessorLogger(logger *slog.Logger) PreprocessorOption {
	return func(p *Preprocessor) {
		p.logger = logger
	}
}

// NewPreprocessor creates a new authentication Preprocessor.
func NewPreprocessor(handler *Handler, opts ...PreprocessorOption) *Preprocessor {
	preprocessor := &Preprocessor{
		handler: handler,
		logger:  handler.logger,
	}

	for _, opt := range opts {
		opt(preprocessor)
	}

	return preprocessor
}

// ProcessRequest adds authentication to an HTTP request.
func (p *Preprocessor) ProcessRequest(req *http.Request) error {
	if p.credentialsID == "" {
		return errors.New("credentials ID not set")
	}

	credentials, err := p.handler.GetCredentials(p.credentialsID)
	if err != nil {
		p.logger.ErrorContext(req.Context(), "Failed to get credentials",
			slog.String("credentials_id", p.credentialsID),
			slog.String("error", err.Error()),
		)
		return err
	}

	// If credentials are expired, try to refresh them
	if credentials.IsExpired() {
		refreshed, err := p.handler.RefreshCredentials(req.Context(), credentials)
		if err != nil {
			p.logger.ErrorContext(req.Context(), "Failed to refresh expired credentials",
				slog.String("credentials_id", p.credentialsID),
				slog.String("error", err.Error()),
			)
			return err
		}
		credentials = refreshed
	}

	err = p.handler.AuthenticateRequest(req, credentials)
	if err != nil {
		p.logger.ErrorContext(req.Context(), "Failed to authenticate request",
			slog.String("credentials_id", p.credentialsID),
			slog.String("error", err.Error()),
		)
		return err
	}

	p.logger.DebugContext(req.Context(), "Added authentication to request",
		slog.String("credentials_id", p.credentialsID),
		slog.String("scheme_type", credentials.Type()),
		slog.String("url", req.URL.String()),
	)

	return nil
}

// RoundTripper is an http.RoundTripper that adds authentication to requests.
type RoundTripper struct {
	// preprocessor is the authentication preprocessor.
	preprocessor *Preprocessor

	// transport is the underlying http.RoundTripper.
	transport http.RoundTripper
}

// NewRoundTripper creates a new authentication RoundTripper.
func NewRoundTripper(preprocessor *Preprocessor, transport http.RoundTripper) *RoundTripper {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &RoundTripper{
		preprocessor: preprocessor,
		transport:    transport,
	}
}

// RoundTrip implements http.RoundTripper.
func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqCopy := req.Clone(req.Context())

	// Add authentication to the request
	if err := rt.preprocessor.ProcessRequest(reqCopy); err != nil {
		return nil, err
	}

	// Send the authenticated request
	return rt.transport.RoundTrip(reqCopy)
}

// ClientMiddleware adds authentication to an HTTP client.
type ClientMiddleware struct {
	// preprocessor is the authentication preprocessor.
	preprocessor *Preprocessor
}

// NewClientMiddleware creates a new authentication ClientMiddleware.
func NewClientMiddleware(preprocessor *Preprocessor) *ClientMiddleware {
	return &ClientMiddleware{
		preprocessor: preprocessor,
	}
}

// WrapClient wraps an HTTP client with authentication.
func (m *ClientMiddleware) WrapClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}

	// Create a new client with the same fields
	wrappedClient := &http.Client{
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       client.Timeout,
	}

	// Wrap the transport with authentication
	wrappedClient.Transport = NewRoundTripper(m.preprocessor, client.Transport)

	return wrappedClient
}

// AuthenticatedClient creates an HTTP client with authentication.
func (p *Preprocessor) AuthenticatedClient(base *http.Client) *http.Client {
	middleware := NewClientMiddleware(p)
	return middleware.WrapClient(base)
}

// ContextMiddleware adds authentication to requests via context.
type ContextMiddleware struct {
	// handler is the authentication handler.
	handler *Handler

	// logger is the logger for middleware operations.
	logger *slog.Logger
}

// NewContextMiddleware creates a new ContextMiddleware.
func NewContextMiddleware(handler *Handler, logger *slog.Logger) *ContextMiddleware {
	if logger == nil {
		logger = handler.logger
	}
	return &ContextMiddleware{
		handler: handler,
		logger:  logger,
	}
}

// contextKey is a type for context keys.
type contextKey string

// Context keys.
const (
	// CredentialsIDKey is the context key for credentials ID.
	CredentialsIDKey contextKey = "auth_credentials_id"

	// CredentialsKey is the context key for credentials.
	CredentialsKey contextKey = "auth_credentials"
)

// WithCredentialsID adds a credentials ID to a context.
func WithCredentialsID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, CredentialsIDKey, id)
}

// WithCredentials adds credentials to a context.
func WithCredentials(ctx context.Context, credentials Credentials) context.Context {
	return context.WithValue(ctx, CredentialsKey, credentials)
}

// GetCredentialsFromContext gets credentials from a context.
func GetCredentialsFromContext(ctx context.Context) (Credentials, bool) {
	creds, ok := ctx.Value(CredentialsKey).(Credentials)
	return creds, ok
}

// GetCredentialsIDFromContext gets a credentials ID from a context.
func GetCredentialsIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(CredentialsIDKey).(string)
	return id, ok
}

// Middleware creates HTTP middleware that adds authentication to requests.
func (m *ContextMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to get credentials directly from context
		if creds, ok := GetCredentialsFromContext(r.Context()); ok {
			// Clone the request to avoid modifying the original
			reqCopy := r.Clone(r.Context())

			// Add authentication to the request
			if err := m.handler.AuthenticateRequest(reqCopy, creds); err != nil {
				m.logger.ErrorContext(r.Context(), "Failed to authenticate request with context credentials",
					slog.String("error", err.Error()),
				)
				http.Error(w, "Authentication error", http.StatusUnauthorized)
				return
			}

			// Call the next handler with the authenticated request
			next.ServeHTTP(w, reqCopy)
			return
		}

		// Try to get credentials ID from context
		if id, ok := GetCredentialsIDFromContext(r.Context()); ok {
			creds, err := m.handler.GetCredentials(id)
			if err != nil {
				m.logger.ErrorContext(r.Context(), "Failed to get credentials",
					slog.String("credentials_id", id),
					slog.String("error", err.Error()),
				)
				http.Error(w, "Authentication error", http.StatusUnauthorized)
				return
			}

			// Clone the request to avoid modifying the original
			reqCopy := r.Clone(r.Context())

			// Add authentication to the request
			if err := m.handler.AuthenticateRequest(reqCopy, creds); err != nil {
				m.logger.ErrorContext(r.Context(), "Failed to authenticate request",
					slog.String("credentials_id", id),
					slog.String("error", err.Error()),
				)
				http.Error(w, "Authentication error", http.StatusUnauthorized)
				return
			}

			// Call the next handler with the authenticated request
			next.ServeHTTP(w, reqCopy)
			return
		}

		// No authentication info found, proceed without authentication
		next.ServeHTTP(w, r)
	})
}
