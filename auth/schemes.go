// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/oauth2"
)

// BaseService is the base authentication service implementation.
type BaseService struct {
	// schemeType is the type of authentication scheme.
	schemeType string

	// config is the authentication configuration.
	config *Config

	// logger is the logger for authentication operations.
	logger *slog.Logger
}

// SchemeType returns the type of authentication scheme.
func (s *BaseService) SchemeType() string {
	return s.schemeType
}

// RequiresAuthentication checks if the service requires authentication.
func (s *BaseService) RequiresAuthentication() bool {
	return s.schemeType != SchemeTypeNone
}

// NewBaseService creates a new BaseService.
func NewBaseService(schemeType string, config *Config) *BaseService {
	return &BaseService{
		schemeType: schemeType,
		config:     config,
		logger:     config.Logger,
	}
}

// NoneService is a service that doesn't require authentication.
type NoneService struct {
	BaseService
}

// NewNoneService creates a new NoneService.
func NewNoneService(config *Config) *NoneService {
	return &NoneService{
		BaseService: *NewBaseService(SchemeTypeNone, config),
	}
}

// Authenticate implements the Service interface.
func (s *NoneService) Authenticate(ctx context.Context, credentials Credentials) (*AuthResponse, error) {
	return &AuthResponse{
		Credentials: credentials,
	}, nil
}

// RefreshCredentials implements the Service interface.
func (s *NoneService) RefreshCredentials(ctx context.Context, credentials Credentials) (Credentials, error) {
	return credentials, nil
}

// OAuth2Service is a service that uses OAuth2 authentication.
type OAuth2Service struct {
	BaseService

	// oauth2Config is the OAuth2 configuration.
	oauth2Config *oauth2.Config
}

// NewOAuth2Service creates a new OAuth2Service.
func NewOAuth2Service(config *Config) *OAuth2Service {
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthURL,
			TokenURL: config.TokenURL,
		},
		RedirectURL: config.RedirectURL,
		Scopes:      config.Scopes,
	}

	if config.Endpoint.AuthURL != "" && config.Endpoint.TokenURL != "" {
		oauth2Config.Endpoint = config.Endpoint
	}

	return &OAuth2Service{
		BaseService:  *NewBaseService(SchemeTypeOAuth2, config),
		oauth2Config: oauth2Config,
	}
}

// Authenticate implements the Service interface.
func (s *OAuth2Service) Authenticate(ctx context.Context, credentials Credentials) (*AuthResponse, error) {
	s.logger.InfoContext(ctx, "Authenticating with OAuth2",
		slog.String("credentials_id", credentials.ToMap()["id"].(string)),
	)

	oauth2Creds, ok := credentials.(*OAuth2Credentials)
	if !ok {
		return nil, errors.New("credentials are not OAuth2Credentials")
	}

	// If credentials are expired, try to refresh them
	if oauth2Creds.IsExpired() {
		var token *oauth2.Token
		var err error

		// If we have a refresh token, use it
		if oauth2Creds.RefreshToken != "" {
			s.logger.InfoContext(ctx, "Refreshing OAuth2 token",
				slog.String("credentials_id", oauth2Creds.ToMap()["id"].(string)),
			)
			token, err = s.refreshToken(ctx, oauth2Creds.RefreshToken)
			if err != nil {
				return nil, fmt.Errorf("failed to refresh token: %w", err)
			}
		} else {
			return nil, ErrTokenExpired
		}

		// Update credentials with the new token
		oauth2Creds.FromToken(token)
	}

	return &AuthResponse{
		AccessToken:  oauth2Creds.AccessToken,
		RefreshToken: oauth2Creds.RefreshToken,
		ExpiresAt:    oauth2Creds.ExpiresAt,
		TokenType:    oauth2Creds.TokenType,
		Credentials:  oauth2Creds,
	}, nil
}

// RefreshCredentials implements the Service interface.
func (s *OAuth2Service) RefreshCredentials(ctx context.Context, credentials Credentials) (Credentials, error) {
	s.logger.InfoContext(ctx, "Refreshing OAuth2 credentials",
		slog.String("credentials_id", credentials.ToMap()["id"].(string)),
	)

	oauth2Creds, ok := credentials.(*OAuth2Credentials)
	if !ok {
		return nil, errors.New("credentials are not OAuth2Credentials")
	}

	if oauth2Creds.RefreshToken == "" {
		return nil, errors.New("no refresh token available")
	}

	token, err := s.refreshToken(ctx, oauth2Creds.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	// Update credentials with the new token
	oauth2Creds.FromToken(token)

	return oauth2Creds, nil
}

// refreshToken refreshes an OAuth2 token.
func (s *OAuth2Service) refreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	tokenSource := s.oauth2Config.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}

	// If the new token doesn't have a refresh token, preserve the old one
	if newToken.RefreshToken == "" {
		newToken.RefreshToken = refreshToken
	}

	return newToken, nil
}

// ExchangeCodeForToken exchanges an authorization code for a token.
func (s *OAuth2Service) ExchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error) {
	return s.oauth2Config.Exchange(ctx, code)
}

// AuthCodeURL returns a URL for OAuth2 authorization.
func (s *OAuth2Service) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return s.oauth2Config.AuthCodeURL(state, opts...)
}

// TokenSource returns an OAuth2 token source.
func (s *OAuth2Service) TokenSource(ctx context.Context, token *oauth2.Token) oauth2.TokenSource {
	return s.oauth2Config.TokenSource(ctx, token)
}

// APIKeyService is a service that uses API key authentication.
type APIKeyService struct {
	BaseService
}

// NewAPIKeyService creates a new APIKeyService.
func NewAPIKeyService(config *Config) *APIKeyService {
	return &APIKeyService{
		BaseService: *NewBaseService(SchemeTypeAPIKey, config),
	}
}

// Authenticate implements the Service interface.
func (s *APIKeyService) Authenticate(ctx context.Context, credentials Credentials) (*AuthResponse, error) {
	s.logger.InfoContext(ctx, "Authenticating with API key",
		slog.String("credentials_id", credentials.ToMap()["id"].(string)),
	)

	apiKeyCreds, ok := credentials.(*APIKeyCredentials)
	if !ok {
		return nil, errors.New("credentials are not APIKeyCredentials")
	}

	// API keys don't have a token response, so we just return the credentials
	return &AuthResponse{
		Credentials: apiKeyCreds,
	}, nil
}

// RefreshCredentials implements the Service interface.
func (s *APIKeyService) RefreshCredentials(ctx context.Context, credentials Credentials) (Credentials, error) {
	// API keys can't be refreshed
	return credentials, nil
}

// BasicAuthService is a service that uses basic authentication.
type BasicAuthService struct {
	BaseService
}

// NewBasicAuthService creates a new BasicAuthService.
func NewBasicAuthService(config *Config) *BasicAuthService {
	return &BasicAuthService{
		BaseService: *NewBaseService(SchemeTypeBasic, config),
	}
}

// Authenticate implements the Service interface.
func (s *BasicAuthService) Authenticate(ctx context.Context, credentials Credentials) (*AuthResponse, error) {
	s.logger.InfoContext(ctx, "Authenticating with basic auth",
		slog.String("credentials_id", credentials.ToMap()["id"].(string)),
	)

	basicCreds, ok := credentials.(*BasicAuthCredentials)
	if !ok {
		return nil, errors.New("credentials are not BasicAuthCredentials")
	}

	// Basic auth doesn't have a token response, so we just return the credentials
	return &AuthResponse{
		Credentials: basicCreds,
	}, nil
}

// RefreshCredentials implements the Service interface.
func (s *BasicAuthService) RefreshCredentials(ctx context.Context, credentials Credentials) (Credentials, error) {
	// Basic auth can't be refreshed
	return credentials, nil
}

// BearerTokenService is a service that uses bearer token authentication.
type BearerTokenService struct {
	BaseService
}

// NewBearerTokenService creates a new BearerTokenService.
func NewBearerTokenService(config *Config) *BearerTokenService {
	return &BearerTokenService{
		BaseService: *NewBaseService(SchemeTypeBearer, config),
	}
}

// Authenticate implements the Service interface.
func (s *BearerTokenService) Authenticate(ctx context.Context, credentials Credentials) (*AuthResponse, error) {
	s.logger.InfoContext(ctx, "Authenticating with bearer token",
		slog.String("credentials_id", credentials.ToMap()["id"].(string)),
	)

	tokenCreds, ok := credentials.(*BearerTokenCredentials)
	if !ok {
		return nil, errors.New("credentials are not BearerTokenCredentials")
	}

	// Bearer token doesn't have a token response, so we just return the credentials
	return &AuthResponse{
		AccessToken: tokenCreds.Token,
		TokenType:   "Bearer",
		Credentials: tokenCreds,
	}, nil
}

// RefreshCredentials implements the Service interface.
func (s *BearerTokenService) RefreshCredentials(ctx context.Context, credentials Credentials) (Credentials, error) {
	// Bearer tokens can't be refreshed
	return credentials, nil
}

// CreateAuthService creates an authentication service for the given scheme type.
func CreateAuthService(config *Config) (Service, error) {
	switch config.SchemeType {
	case SchemeTypeOAuth2:
		return NewOAuth2Service(config), nil
	case SchemeTypeAPIKey:
		return NewAPIKeyService(config), nil
	case SchemeTypeBasic:
		return NewBasicAuthService(config), nil
	case SchemeTypeBearer:
		return NewBearerTokenService(config), nil
	case SchemeTypeNone:
		return NewNoneService(config), nil
	default:
		return nil, ErrUnsupportedAuthScheme
	}
}

// BasicAuthHeader creates a basic auth header value.
func BasicAuthHeader(username, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

// WithExpiresAt sets the expiration time for OAuth2 credentials.
func WithExpiresAt(expiresIn time.Duration) func(*OAuth2Credentials) {
	return func(creds *OAuth2Credentials) {
		creds.ExpiresAt = time.Now().Add(expiresIn)
	}
}
