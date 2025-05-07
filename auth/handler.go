// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

// Handler manages authentication flows and credential storage.
type Handler struct {
	// config is the authentication configuration.
	config *Config

	// store is the credential store.
	store CredentialStore

	// services is a map of authentication services by scheme type.
	services map[string]Service

	// logger is the logger for authentication operations.
	logger *slog.Logger

	// mu is a mutex to protect concurrent access.
	mu sync.RWMutex
}

// HandlerOption is a function that configures the Handler.
type HandlerOption func(*Handler)

// WithCredentialStore sets the credential store for the Handler.
func WithCredentialStore(store CredentialStore) HandlerOption {
	return func(h *Handler) {
		h.store = store
	}
}

// WithAuthServices adds authentication services to the Handler.
func WithAuthServices(services ...Service) HandlerOption {
	return func(h *Handler) {
		for _, service := range services {
			h.services[service.SchemeType()] = service
		}
	}
}

// WithHandlerLogger sets the logger for the Handler.
func WithHandlerLogger(logger *slog.Logger) HandlerOption {
	return func(h *Handler) {
		h.logger = logger
	}
}

// NewHandler creates a new authentication Handler.
func NewHandler(config *Config, opts ...HandlerOption) *Handler {
	handler := &Handler{
		config:   config,
		store:    NewInMemoryCredentialStore(),
		services: make(map[string]Service),
		logger:   config.Logger,
	}

	for _, opt := range opts {
		opt(handler)
	}

	return handler
}

// GetCredentials retrieves credentials by ID.
func (h *Handler) GetCredentials(id string) (Credentials, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.store.GetCredentials(id)
}

// StoreCredentials stores credentials.
func (h *Handler) StoreCredentials(credentials Credentials) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.store.StoreCredentials(credentials)
}

// DeleteCredentials deletes credentials by ID.
func (h *Handler) DeleteCredentials(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.store.DeleteCredentials(id)
}

// ListCredentials lists all stored credentials.
func (h *Handler) ListCredentials() ([]Credentials, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.store.ListCredentials()
}

// GetService returns the authentication service for the given scheme type.
func (h *Handler) GetService(schemeType string) (Service, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	service, ok := h.services[schemeType]
	if !ok {
		return nil, ErrUnsupportedAuthScheme
	}

	return service, nil
}

// Authenticate performs authentication with the given credentials.
func (h *Handler) Authenticate(ctx context.Context, credentials Credentials) (*AuthResponse, error) {
	h.logger.InfoContext(ctx, "Authenticating",
		slog.String("scheme_type", credentials.Type()),
		slog.String("credentials_id", credentials.ToMap()["id"].(string)),
	)

	service, err := h.GetService(credentials.Type())
	if err != nil {
		return nil, err
	}

	resp, err := service.Authenticate(ctx, credentials)
	if err != nil {
		h.logger.ErrorContext(ctx, "Authentication failed",
			slog.String("scheme_type", credentials.Type()),
			slog.String("credentials_id", credentials.ToMap()["id"].(string)),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	// Store updated credentials
	if resp.Credentials != nil {
		if err := h.StoreCredentials(resp.Credentials); err != nil {
			h.logger.WarnContext(ctx, "Failed to store updated credentials",
				slog.String("scheme_type", credentials.Type()),
				slog.String("credentials_id", credentials.ToMap()["id"].(string)),
				slog.String("error", err.Error()),
			)
		}
	}

	h.logger.InfoContext(ctx, "Authentication successful",
		slog.String("scheme_type", credentials.Type()),
		slog.String("credentials_id", credentials.ToMap()["id"].(string)),
	)

	return resp, nil
}

// RefreshCredentials refreshes the given credentials.
func (h *Handler) RefreshCredentials(ctx context.Context, credentials Credentials) (Credentials, error) {
	h.logger.InfoContext(ctx, "Refreshing credentials",
		slog.String("scheme_type", credentials.Type()),
		slog.String("credentials_id", credentials.ToMap()["id"].(string)),
	)

	service, err := h.GetService(credentials.Type())
	if err != nil {
		return nil, err
	}

	refreshed, err := service.RefreshCredentials(ctx, credentials)
	if err != nil {
		h.logger.ErrorContext(ctx, "Credential refresh failed",
			slog.String("scheme_type", credentials.Type()),
			slog.String("credentials_id", credentials.ToMap()["id"].(string)),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	// Store updated credentials
	if err := h.StoreCredentials(refreshed); err != nil {
		h.logger.WarnContext(ctx, "Failed to store refreshed credentials",
			slog.String("scheme_type", refreshed.Type()),
			slog.String("credentials_id", refreshed.ToMap()["id"].(string)),
			slog.String("error", err.Error()),
		)
	}

	h.logger.InfoContext(ctx, "Credentials refreshed successfully",
		slog.String("scheme_type", refreshed.Type()),
		slog.String("credentials_id", refreshed.ToMap()["id"].(string)),
	)

	return refreshed, nil
}

// AuthenticateRequest adds authentication to an HTTP request.
func (h *Handler) AuthenticateRequest(req *http.Request, credentials Credentials) error {
	// Ensure credentials aren't expired, refresh if needed
	if credentials.IsExpired() {
		ctx := req.Context()
		refreshed, err := h.RefreshCredentials(ctx, credentials)
		if err != nil {
			return err
		}
		credentials = refreshed
	}

	// Apply authentication based on credentials type
	switch creds := credentials.(type) {
	case *OAuth2Credentials:
		// Add OAuth2 token to the request
		token := creds.ToToken()
		req.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))

	case *APIKeyCredentials:
		// Add API key to the request
		switch creds.KeyLocation {
		case "header":
			req.Header.Set(creds.KeyName, creds.APIKey)
		case "query":
			q := req.URL.Query()
			q.Add(creds.KeyName, creds.APIKey)
			req.URL.RawQuery = q.Encode()
		default:
			return errors.New("unsupported API key location: " + creds.KeyLocation)
		}

	case *BasicAuthCredentials:
		// Add basic auth to the request
		req.SetBasicAuth(creds.Username, creds.Password)

	case *BearerTokenCredentials:
		// Add bearer token to the request
		req.Header.Set("Authorization", "Bearer "+creds.Token)

	default:
		return errors.New("unsupported credentials type")
	}

	return nil
}

// CreateOAuth2Config creates an OAuth2 configuration from the Handler's config.
func (h *Handler) CreateOAuth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     h.config.ClientID,
		ClientSecret: h.config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  h.config.AuthURL,
			TokenURL: h.config.TokenURL,
		},
		RedirectURL: h.config.RedirectURL,
		Scopes:      h.config.Scopes,
	}
}

// ExchangeCodeForToken exchanges an OAuth2 authorization code for a token.
func (h *Handler) ExchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error) {
	oauth2Config := h.CreateOAuth2Config()
	return oauth2Config.Exchange(ctx, code)
}

// TokenSource returns an OAuth2 TokenSource for the given credentials.
func (h *Handler) TokenSource(ctx context.Context, credentials *OAuth2Credentials) oauth2.TokenSource {
	oauth2Config := h.CreateOAuth2Config()
	return oauth2Config.TokenSource(ctx, credentials.ToToken())
}

// NewOAuth2Client creates an HTTP client with OAuth2 authentication.
func (h *Handler) NewOAuth2Client(ctx context.Context, credentials *OAuth2Credentials) *http.Client {
	oauth2Config := h.CreateOAuth2Config()
	return oauth2.NewClient(ctx, oauth2Config.TokenSource(ctx, credentials.ToToken()))
}

// IsCredentialExpired checks if the given credentials have expired.
func (h *Handler) IsCredentialExpired(credentials Credentials) bool {
	return credentials.IsExpired()
}

// AuthInfo provides information about the authentication configuration.
type AuthInfo struct {
	// SchemeType is the type of authentication scheme.
	SchemeType string `json:"scheme_type"`

	// RequiresAuth indicates if authentication is required.
	RequiresAuth bool `json:"requires_auth"`

	// AuthURL is the authorization URL for OAuth2.
	AuthURL string `json:"auth_url,omitempty"`

	// TokenURL is the token URL for OAuth2.
	TokenURL string `json:"token_url,omitempty"`

	// RedirectURL is the redirect URL for OAuth2.
	RedirectURL string `json:"redirect_url,omitempty"`

	// Scopes are the OAuth2 scopes.
	Scopes []string `json:"scopes,omitempty"`

	// ClientID is the OAuth2 client ID.
	ClientID string `json:"client_id,omitempty"`
}

// GetAuthInfo returns information about the authentication configuration.
func (h *Handler) GetAuthInfo() *AuthInfo {
	info := &AuthInfo{
		SchemeType:   h.config.SchemeType,
		RequiresAuth: h.config.SchemeType != SchemeTypeNone,
	}

	if h.config.SchemeType == SchemeTypeOAuth2 {
		info.AuthURL = h.config.AuthURL
		info.TokenURL = h.config.TokenURL
		info.RedirectURL = h.config.RedirectURL
		info.Scopes = h.config.Scopes
		info.ClientID = h.config.ClientID
	}

	return info
}
