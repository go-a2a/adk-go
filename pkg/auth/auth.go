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
