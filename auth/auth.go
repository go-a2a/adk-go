// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package auth provides authentication capabilities for the Agent Development Kit (ADK).
// It supports various authentication schemes like OAuth2, API keys, etc. and
// provides tools for credential management and authentication flow handling.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"golang.org/x/oauth2"
)

// Common errors.
var (
	ErrAuthFailed            = errors.New("authentication failed")
	ErrCredentialsNotFound   = errors.New("credentials not found")
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrUnsupportedAuthScheme = errors.New("unsupported authentication scheme")
	ErrTokenExpired          = errors.New("token expired")
	ErrRefreshFailed         = errors.New("token refresh failed")
)

// Constants for auth scheme types.
const (
	SchemeTypeOAuth2 = "oauth2"
	SchemeTypeAPIKey = "api_key"
	SchemeTypeBasic  = "basic"
	SchemeTypeBearer = "bearer"
	SchemeTypeCustom = "custom"
	SchemeTypeNone   = "none"
)

// Config holds authentication configuration.
type Config struct {
	// SchemeType is the type of authentication scheme to use.
	SchemeType string

	// SchemeConfig is the configuration for the authentication scheme.
	SchemeConfig any

	// Scopes are the OAuth2 scopes to request.
	Scopes []string

	// TokenURL is the URL to get OAuth2 tokens from.
	TokenURL string

	// AuthURL is the URL to authorize OAuth2 requests.
	AuthURL string

	// RedirectURL is the callback URL for OAuth2 flow.
	RedirectURL string

	// ClientID is the OAuth2 client ID.
	ClientID string

	// ClientSecret is the OAuth2 client secret.
	ClientSecret string

	// Endpoint is the OAuth2 endpoint configuration.
	Endpoint oauth2.Endpoint

	// Logger for authentication operations.
	Logger *slog.Logger
}

// Option is a function that configures the authentication Config.
type Option func(*Config)

// WithSchemeType sets the authentication scheme type.
func WithSchemeType(schemeType string) Option {
	return func(c *Config) {
		c.SchemeType = schemeType
	}
}

// WithSchemeConfig sets the authentication scheme configuration.
func WithSchemeConfig(schemeConfig any) Option {
	return func(c *Config) {
		c.SchemeConfig = schemeConfig
	}
}

// WithOAuth2Scopes sets the OAuth2 scopes.
func WithOAuth2Scopes(scopes []string) Option {
	return func(c *Config) {
		c.Scopes = scopes
	}
}

// WithOAuth2Endpoint sets the OAuth2 endpoint.
func WithOAuth2Endpoint(endpoint oauth2.Endpoint) Option {
	return func(c *Config) {
		c.Endpoint = endpoint
	}
}

// WithOAuth2URLs sets the OAuth2 URLs.
func WithOAuth2URLs(authURL, tokenURL, redirectURL string) Option {
	return func(c *Config) {
		c.AuthURL = authURL
		c.TokenURL = tokenURL
		c.RedirectURL = redirectURL
	}
}

// WithOAuth2Credentials sets the OAuth2 client credentials.
func WithOAuth2Credentials(clientID, clientSecret string) Option {
	return func(c *Config) {
		c.ClientID = clientID
		c.ClientSecret = clientSecret
	}
}

// WithLogger sets the logger for authentication operations.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Config) {
		c.Logger = logger
	}
}

// NewConfig creates a new authentication configuration with the given options.
func NewConfig(opts ...Option) *Config {
	config := &Config{
		SchemeType: SchemeTypeNone,
		Scopes:     []string{},
		Logger:     slog.Default(),
	}

	for _, opt := range opts {
		opt(config)
	}

	return config
}

// Service is the interface for authentication services.
type Service interface {
	// Authenticate performs authentication with the provided credentials.
	Authenticate(ctx context.Context, credentials Credentials) (*AuthResponse, error)

	// RefreshCredentials refreshes the credentials if supported.
	RefreshCredentials(ctx context.Context, credentials Credentials) (Credentials, error)

	// SchemeType returns the type of authentication scheme.
	SchemeType() string

	// RequiresAuthentication checks if the service requires authentication.
	RequiresAuthentication() bool
}

// AuthResponse represents the response from an authentication request.
type AuthResponse struct {
	// AccessToken is the token to access protected resources.
	AccessToken string `json:"access_token,omitempty"`

	// RefreshToken is the token to refresh the access token.
	RefreshToken string `json:"refresh_token,omitempty"`

	// ExpiresAt is when the access token expires.
	ExpiresAt time.Time `json:"expires_at,omitzero"`

	// TokenType is the type of token, e.g., "Bearer".
	TokenType string `json:"token_type,omitempty"`

	// Credentials contains the updated credentials after authentication.
	Credentials Credentials `json:"-"`

	// RawResponse contains the raw, service-specific response data.
	RawResponse any `json:"-"`
}

// Credentials is the interface for authentication credentials.
type Credentials interface {
	// Type returns the type of the credentials.
	Type() string

	// IsExpired checks if the credentials have expired.
	IsExpired() bool

	// ToMap converts the credentials to a map.
	ToMap() map[string]any

	// FromMap updates the credentials from a map.
	FromMap(data map[string]any) error
}
