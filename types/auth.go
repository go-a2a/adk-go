// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

// AuthConfig is the configuration for the auth tool.
type AuthConfig struct {
	// SchemeType is the authentication scheme type.
	SchemeType string `json:"scheme_type"`

	// OAuth2 is the OAuth2 configuration.
	OAuth2 *OAuth2Config `json:"oauth2,omitempty"`

	// APIKey is the API key configuration.
	APIKey *APIKeyConfig `json:"api_key,omitempty"`

	// BasicAuth is the basic auth configuration.
	BasicAuth *BasicAuthConfig `json:"basic_auth,omitempty"`

	// BearerToken is the bearer token configuration.
	BearerToken *BearerTokenConfig `json:"bearer_token,omitempty"`
}

// OAuth2Config is the configuration for OAuth2 authentication.
type OAuth2Config struct {
	// ClientID is the OAuth2 client ID.
	ClientID string `json:"client_id"`

	// ClientSecret is the OAuth2 client secret.
	ClientSecret string `json:"client_secret"`

	// AuthURL is the OAuth2 authorization URL.
	AuthURL string `json:"auth_url"`

	// TokenURL is the OAuth2 token URL.
	TokenURL string `json:"token_url"`

	// RedirectURL is the OAuth2 redirect URL.
	RedirectURL string `json:"redirect_url"`

	// Scopes are the OAuth2 scopes.
	Scopes []string `json:"scopes"`
}

// APIKeyConfig is the configuration for API key authentication.
type APIKeyConfig struct {
	// Location is where to put the API key (header, query).
	Location string `json:"location"`

	// Name is the name of the parameter or header.
	Name string `json:"name"`
}

// BasicAuthConfig is the configuration for basic authentication.
type BasicAuthConfig struct {
	// Username is the basic auth username.
	Username string `json:"username,omitempty"`

	// Password is the basic auth password.
	Password string `json:"password,omitempty"`
}

// BearerTokenConfig is the configuration for bearer token authentication.
type BearerTokenConfig struct {
	// Token is the bearer token value.
	Token string `json:"token,omitempty"`
}
