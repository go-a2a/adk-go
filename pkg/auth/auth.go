// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

// Package auth provides authentication mechanisms for interacting with external services.
package auth

import (
	"context"
	"net/http"
	"time"
)

// Credentials represents authentication credentials for various services.
type Credentials interface {
	// Type returns the type of these credentials.
	Type() string
}

// Authenticator is the interface for objects that can authenticate requests.
type Authenticator interface {
	// Authenticate adds authentication information to the given request.
	Authenticate(ctx context.Context, req *http.Request) error

	// GetAccessToken returns a valid access token.
	GetAccessToken(ctx context.Context) (string, time.Time, error)

	// GetCredentials returns the credentials used by this authenticator.
	GetCredentials() Credentials
}

// TokenProvider is the interface for objects that can provide access tokens.
type TokenProvider interface {
	// GetAccessToken returns a valid access token and its expiration time.
	GetAccessToken(ctx context.Context) (token string, expiry time.Time, err error)
}
