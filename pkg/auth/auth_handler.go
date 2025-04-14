// Copyright 2025 The Go-A2A Authors
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

package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// AuthHandlerConfig represents the configuration for the AuthHandler.
type AuthHandlerConfig struct {
	// ClientID is the OAuth 2.0 client ID.
	ClientID string

	// ClientSecret is the OAuth 2.0 client secret.
	ClientSecret string

	// RedirectURI is the OAuth 2.0 redirect URI.
	RedirectURI string

	// Scopes is the list of OAuth 2.0 scopes.
	Scopes []string

	// TokenEndpoint is the OAuth 2.0 token endpoint.
	TokenEndpoint string
}

// AuthHandler manages authentication workflows.
type AuthHandler struct {
	config AuthHandlerConfig
}

// NewAuthHandler creates a new AuthHandler with the given configuration.
func NewAuthHandler(config AuthHandlerConfig) *AuthHandler {
	return &AuthHandler{
		config: config,
	}
}

// GenerateAuthURI generates an authorization URI for the given authentication scheme.
func (h *AuthHandler) GenerateAuthURI(scheme *AuthScheme, state string) (string, error) {
	if state == "" {
		randomBytes := make([]byte, 16)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("generating random state: %w", err)
		}
		state = base64.URLEncoding.EncodeToString(randomBytes)
	}

	switch scheme.GetSchemeType() {
	case SchemeTypeOAuth2:
		return h.generateOAuth2URI(scheme.OAuth2, state)
	case SchemeTypeOpenIDConnect:
		return h.generateOpenIDConnectURI(scheme.OpenIDConnect, state)
	default:
		return "", fmt.Errorf("unsupported authentication scheme type: %s", scheme.GetSchemeType())
	}
}

// generateOAuth2URI generates an authorization URI for OAuth 2.0.
func (h *AuthHandler) generateOAuth2URI(scheme *OAuth2Scheme, state string) (string, error) {
	if scheme.Flows.AuthorizationCode == nil {
		return "", fmt.Errorf("authorization code flow not configured")
	}

	flow := scheme.Flows.AuthorizationCode
	baseURL := flow.AuthorizationURL
	
	// Prepare query parameters
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", h.config.ClientID)
	params.Set("redirect_uri", h.config.RedirectURI)
	params.Set("state", state)
	
	if len(h.config.Scopes) > 0 {
		params.Set("scope", strings.Join(h.config.Scopes, " "))
	}

	// Build the URI
	if strings.Contains(baseURL, "?") {
		return baseURL + "&" + params.Encode(), nil
	}
	return baseURL + "?" + params.Encode(), nil
}

// generateOpenIDConnectURI generates an authorization URI for OpenID Connect.
func (h *AuthHandler) generateOpenIDConnectURI(scheme *OpenIDConnectScheme, state string) (string, error) {
	baseURL := scheme.OpenIDConfig.AuthorizationEndpoint
	
	// Prepare query parameters
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", h.config.ClientID)
	params.Set("redirect_uri", h.config.RedirectURI)
	params.Set("state", state)
	
	if len(h.config.Scopes) > 0 {
		params.Set("scope", strings.Join(h.config.Scopes, " "))
	}

	// Build the URI
	if strings.Contains(baseURL, "?") {
		return baseURL + "&" + params.Encode(), nil
	}
	return baseURL + "?" + params.Encode(), nil
}

// ExchangeAuthToken exchanges an authorization code for an access token.
func (h *AuthHandler) ExchangeAuthToken(ctx context.Context, code string, tokenEndpoint string) (*OAuth2Auth, error) {
	// Prepare the form data
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", h.config.ClientID)
	data.Set("client_secret", h.config.ClientSecret)
	data.Set("redirect_uri", h.config.RedirectURI)

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
		Scope        string `json:"scope,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	// Create the OAuth2 auth object
	return &OAuth2Auth{
		ClientID:     h.config.ClientID,
		ClientSecret: h.config.ClientSecret,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenURI:     tokenEndpoint,
		Scopes:       tokenResp.Scope,
	}, nil
}

// ParseAndStoreAuthResponse parses an authentication response and stores the credentials.
func (h *AuthHandler) ParseAndStoreAuthResponse(response string, authConfig *AuthConfig) error {
	// Parse the response URL
	responseURL, err := url.Parse(response)
	if err != nil {
		return fmt.Errorf("parsing response URL: %w", err)
	}

	// Extract the code
	code := responseURL.Query().Get("code")
	if code == "" {
		return fmt.Errorf("no authorization code found in response")
	}

	// Verify the state (would normally be compared with the original state)
	state := responseURL.Query().Get("state")
	if state == "" {
		return fmt.Errorf("no state found in response")
	}

	// Determine the token endpoint based on the auth scheme
	var tokenEndpoint string
	switch authConfig.AuthScheme.GetSchemeType() {
	case SchemeTypeOAuth2:
		if authConfig.AuthScheme.OAuth2.Flows.AuthorizationCode != nil {
			tokenEndpoint = authConfig.AuthScheme.OAuth2.Flows.AuthorizationCode.TokenURL
		} else {
			return fmt.Errorf("authorization code flow not configured")
		}
	case SchemeTypeOpenIDConnect:
		tokenEndpoint = authConfig.AuthScheme.OpenIDConnect.OpenIDConfig.TokenEndpoint
	default:
		return fmt.Errorf("unsupported authentication scheme type: %s", authConfig.AuthScheme.GetSchemeType())
	}

	// Exchange the code for an access token
	oauth2Auth, err := h.ExchangeAuthToken(context.Background(), code, tokenEndpoint)
	if err != nil {
		return fmt.Errorf("exchanging authorization code: %w", err)
	}

	// Create the exchanged auth credential
	authConfig.ExchangedAuthCredential = &AuthCredential{
		AuthType: CredentialTypeOAuth2,
		OAuth2:   oauth2Auth,
	}

	return nil
}