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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	googleOAuthTokenURL = "https://oauth2.googleapis.com/token"
	defaultScope        = "https://www.googleapis.com/auth/cloud-platform"
)

// GoogleAuthenticator implements the Authenticator interface for Google services.
type GoogleAuthenticator struct {
	credentials Credentials
	scopes      []string
	tokenMu     sync.Mutex
	token       string
	tokenExpiry time.Time
}

// NewGoogleAuthenticator creates a new GoogleAuthenticator with the given credentials.
func NewGoogleAuthenticator(credentials Credentials, scopes ...string) (*GoogleAuthenticator, error) {
	if credentials == nil {
		return nil, ErrInvalidCredentials
	}

	// Default to cloud platform scope if none provided
	if len(scopes) == 0 {
		scopes = []string{defaultScope}
	}

	return &GoogleAuthenticator{
		credentials: credentials,
		scopes:      scopes,
	}, nil
}

// NewGoogleAuthenticatorFromFile creates a new GoogleAuthenticator with credentials loaded from a file.
func NewGoogleAuthenticatorFromFile(filePath string, scopes ...string) (*GoogleAuthenticator, error) {
	creds, err := LoadCredentialsFromFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("loading credentials from file: %w", err)
	}

	return NewGoogleAuthenticator(creds, scopes...)
}

// Authenticate adds authentication information to the given request.
func (g *GoogleAuthenticator) Authenticate(ctx context.Context, req *http.Request) error {
	token, _, err := g.GetAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("getting access token: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// GetAccessToken returns a valid access token.
func (g *GoogleAuthenticator) GetAccessToken(ctx context.Context) (string, time.Time, error) {
	g.tokenMu.Lock()
	defer g.tokenMu.Unlock()

	// Check if token is still valid (with a 1-minute buffer)
	if g.token != "" && time.Now().Add(time.Minute).Before(g.tokenExpiry) {
		return g.token, g.tokenExpiry, nil
	}

	// Get new token based on credential type
	switch creds := g.credentials.(type) {
	case *ServiceAccountCredentials:
		return g.getServiceAccountToken(ctx, creds)
	case *OAuth2Auth:
		return g.getOAuth2Token(ctx, creds)
	case *APIKeyCredentials:
		// API keys don't have expiry and are used differently
		return creds.Key, time.Now().Add(24 * time.Hour), nil
	case *HTTPAuth:
		if creds.Token != "" {
			// Use the HTTP token as an access token if present
			return creds.Token, time.Now().Add(24 * time.Hour), nil
		}
		return "", time.Time{}, fmt.Errorf("HTTP authentication without token not supported")
	default:
		return "", time.Time{}, fmt.Errorf("unsupported credentials type: %s", creds.Type())
	}
}

// GetCredentials returns the credentials used by this authenticator.
func (g *GoogleAuthenticator) GetCredentials() Credentials {
	return g.credentials
}

// getServiceAccountToken obtains an access token using service account credentials.
func (g *GoogleAuthenticator) getServiceAccountToken(ctx context.Context, creds *ServiceAccountCredentials) (string, time.Time, error) {
	// Create signed JWT
	jwt, err := createSignedJWT(creds, g.scopes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating JWT: %w", err)
	}

	// Exchange JWT for access token
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", jwt)

	token, expiry, err := g.exchangeToken(ctx, data)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("exchanging token: %w", err)
	}

	g.token = token
	g.tokenExpiry = expiry
	return token, expiry, nil
}

// getOAuth2Token obtains an access token using OAuth2 credentials.
func (g *GoogleAuthenticator) getOAuth2Token(ctx context.Context, creds *OAuth2Auth) (string, time.Time, error) {
	// If we already have an access token, return it
	if creds.AccessToken != "" {
		// Since we don't know when this token expires, assume a short lifetime
		return creds.AccessToken, time.Now().Add(time.Hour), nil
	}

	// If we have a refresh token, use it to get a new access token
	if creds.RefreshToken != "" {
		data := url.Values{}
		data.Set("grant_type", "refresh_token")
		data.Set("refresh_token", creds.RefreshToken)

		if creds.ClientID != "" && creds.ClientSecret != "" {
			data.Set("client_id", creds.ClientID)
			data.Set("client_secret", creds.ClientSecret)
		}

		token, expiry, err := g.exchangeToken(ctx, data)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("refreshing token: %w", err)
		}

		g.token = token
		g.tokenExpiry = expiry
		return token, expiry, nil
	}

	// If we have client credentials, use the client credentials flow
	if creds.ClientID != "" && creds.ClientSecret != "" {
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", creds.ClientID)
		data.Set("client_secret", creds.ClientSecret)

		if creds.Scopes != "" {
			data.Set("scope", creds.Scopes)
		} else if len(g.scopes) > 0 {
			data.Set("scope", strings.Join(g.scopes, " "))
		}

		token, expiry, err := g.exchangeToken(ctx, data)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("using client credentials: %w", err)
		}

		g.token = token
		g.tokenExpiry = expiry
		return token, expiry, nil
	}

	return "", time.Time{}, fmt.Errorf("insufficient OAuth2 credentials")
}

// exchangeToken performs the HTTP request to exchange token information.
func (g *GoogleAuthenticator) exchangeToken(ctx context.Context, data url.Values) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", googleOAuthTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", time.Time{}, fmt.Errorf("parsing token response: %w", err)
	}

	expiryTime := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return tokenResp.AccessToken, expiryTime, nil
}

// Application Default Credentials (ADC) handling

// NewApplicationDefaultCredentials creates a new GoogleAuthenticator using
// Application Default Credentials (ADC).
func NewApplicationDefaultCredentials(ctx context.Context, scopes ...string) (*GoogleAuthenticator, error) {
	// Step 1: Check GOOGLE_APPLICATION_CREDENTIALS environment variable
	if credPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); credPath != "" {
		return NewGoogleAuthenticatorFromFile(credPath, scopes...)
	}

	// Step 2: Check for gcloud credentials in well-known location
	homeDir, err := os.UserHomeDir()
	if err == nil {
		credPath := filepath.Join(homeDir, ".config", "gcloud", "application_default_credentials.json")
		if _, err := os.Stat(credPath); err == nil {
			return NewGoogleAuthenticatorFromFile(credPath, scopes...)
		}
	}

	// Step 3: Check if running on GCP by trying to get credentials from the metadata server
	if auth, err := newGCPMetadataAuthenticator(scopes...); err == nil {
		slog.Info("Using GCP metadata server for authentication")
		return auth, nil
	}

	return nil, fmt.Errorf("application default credentials not found")
}
