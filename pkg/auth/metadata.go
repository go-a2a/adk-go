// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GCPMetadataCredentials represents credentials obtained from the GCP metadata server.
type GCPMetadataCredentials struct {
	tokenSource oauth2.TokenSource
}

// Type returns the type of these credentials.
func (g *GCPMetadataCredentials) Type() string {
	return "gcp_metadata"
}

// newGCPMetadataAuthenticator creates a new authenticator that uses the GCP metadata server.
func newGCPMetadataAuthenticator(scopes ...string) (*GoogleAuthenticator, error) {
	// Check if the code is running on GCP and try to get a token source
	tokenSource, err := google.DefaultTokenSource(context.Background(), scopes...)
	if err != nil {
		return nil, fmt.Errorf("getting default token source: %w", err)
	}

	// Check if token source is valid by trying to get a token
	_, err = tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("validating token source: %w", err)
	}

	creds := &GCPMetadataCredentials{
		tokenSource: tokenSource,
	}

	return &GoogleAuthenticator{
		credentials: creds,
		scopes:      scopes,
		tokenSource: tokenSource,
	}, nil
}

// getAccessToken gets a token from the GCP metadata server.
func (g *GCPMetadataCredentials) getAccessToken(ctx context.Context) (string, time.Time, error) {
	token, err := g.tokenSource.Token()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("getting token from metadata server: %w", err)
	}

	return token.AccessToken, token.Expiry, nil
}
