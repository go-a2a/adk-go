// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	defaultScope = "https://www.googleapis.com/auth/cloud-platform"
)

// GoogleAuthenticator implements the Authenticator interface for Google services.
type GoogleAuthenticator struct {
	credentials Credentials
	scopes      []string
	tokenMu     sync.Mutex
	token       string
	tokenExpiry time.Time
	tokenSource oauth2.TokenSource
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

	auth := &GoogleAuthenticator{
		credentials: credentials,
		scopes:      scopes,
	}

	// Create token source based on credential type
	ts, err := auth.createTokenSource(context.Background())
	if err != nil {
		return nil, fmt.Errorf("creating token source: %w", err)
	}
	auth.tokenSource = ts

	return auth, nil
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

	// Get token from token source
	if g.tokenSource != nil {
		token, err := g.tokenSource.Token()
		if err != nil {
			return "", time.Time{}, fmt.Errorf("getting token from token source: %w", err)
		}
		g.token = token.AccessToken
		g.tokenExpiry = token.Expiry
		return token.AccessToken, token.Expiry, nil
	}

	// Fallback to manually getting a token based on credential type
	switch creds := g.credentials.(type) {
	case *GCPMetadataCredentials:
		return creds.getAccessToken(ctx)
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

// createTokenSource creates an oauth2.TokenSource based on the credential type.
func (g *GoogleAuthenticator) createTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	switch creds := g.credentials.(type) {
	case *ServiceAccountCredentials:
		return getJWTTokenSource(creds, g.scopes)
	case *OAuth2Auth:
		return g.createOAuth2TokenSource(ctx, creds)
	case *GCPMetadataCredentials:
		return creds.tokenSource, nil
	case *APIKeyCredentials:
		// API keys are used as access tokens
		return oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: creds.Key,
			Expiry:      time.Now().Add(24 * time.Hour),
		}), nil
	case *HTTPAuth:
		// HTTP auth tokens are used as access tokens if present
		if creds.Token != "" {
			return oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: creds.Token,
				Expiry:      time.Now().Add(24 * time.Hour),
			}), nil
		}
		// Otherwise use a placeholder
		return oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: "placeholder",
			Expiry:      time.Now().Add(24 * time.Hour),
		}), nil
	default:
		return nil, fmt.Errorf("unsupported credentials type for token source: %s", creds.Type())
	}
}

// createOAuth2TokenSource creates a token source for OAuth2 credentials.
func (g *GoogleAuthenticator) createOAuth2TokenSource(ctx context.Context, creds *OAuth2Auth) (oauth2.TokenSource, error) {
	// If we have an access token, use it
	if creds.AccessToken != "" {
		return oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: creds.AccessToken,
			Expiry:      time.Now().Add(time.Hour), // Assume short lifetime
		}), nil
	}

	// If we have a refresh token, use it with a config
	if creds.RefreshToken != "" {
		config := &oauth2.Config{
			ClientID:     creds.ClientID,
			ClientSecret: creds.ClientSecret,
			Endpoint:     google.Endpoint,
			RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		}

		if creds.Scopes != "" {
			config.Scopes = strings.Split(creds.Scopes, " ")
		} else if len(g.scopes) > 0 {
			config.Scopes = g.scopes
		}

		token := &oauth2.Token{
			RefreshToken: creds.RefreshToken,
		}

		return config.TokenSource(ctx, token), nil
	}

	// If we have client credentials, use the client credentials flow
	if creds.ClientID != "" && creds.ClientSecret != "" {
		config := &oauth2.Config{
			ClientID:     creds.ClientID,
			ClientSecret: creds.ClientSecret,
			Endpoint:     google.Endpoint,
			RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		}

		if creds.Scopes != "" {
			config.Scopes = strings.Split(creds.Scopes, " ")
		} else if len(g.scopes) > 0 {
			config.Scopes = g.scopes
		}

		return config.TokenSource(ctx, nil), nil
	}

	return nil, fmt.Errorf("insufficient OAuth2 credentials")
}

// Application Default Credentials (ADC) handling

// NewApplicationDefaultCredentials creates a new GoogleAuthenticator using
// Application Default Credentials (ADC).
func NewApplicationDefaultCredentials(ctx context.Context, scopes ...string) (*GoogleAuthenticator, error) {
	// Use the Google Cloud SDK's DefaultTokenSource which implements ADC
	tokenSource, err := google.DefaultTokenSource(ctx, scopes...)
	if err != nil {
		// If DefaultTokenSource fails, fall back to manual implementation
		return fallbackADC(ctx, scopes...)
	}

	// Verify token source works by fetching a token
	_, err = tokenSource.Token()
	if err != nil {
		return fallbackADC(ctx, scopes...)
	}

	// Create credentials from token source
	creds := &GCPMetadataCredentials{
		tokenSource: tokenSource,
	}

	return &GoogleAuthenticator{
		credentials: creds,
		scopes:      scopes,
		tokenSource: tokenSource,
	}, nil
}

// fallbackADC implements a manual ADC lookup as a fallback.
func fallbackADC(ctx context.Context, scopes ...string) (*GoogleAuthenticator, error) {
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
