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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestServiceAccountCredentials(t *testing.T) {
	creds := &ServiceAccountCredentials{
		Type:        "service_account",
		ProjectID:   "test-project",
		PrivateKeyID: "test-key-id",
		PrivateKey:  "test-key",
		ClientEmail: "test@example.com",
	}

	if got, want := creds.Type(), "service_account"; got != want {
		t.Errorf("creds.Type() = %q, want %q", got, want)
	}
}

func TestAPIKeyCredentials(t *testing.T) {
	creds := &APIKeyCredentials{
		Key: "test-api-key",
	}

	if got, want := creds.Type(), "api_key"; got != want {
		t.Errorf("creds.Type() = %q, want %q", got, want)
	}
}

func TestOAuth2Auth(t *testing.T) {
	creds := &OAuth2Auth{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RefreshToken: "test-refresh-token",
	}

	if got, want := creds.Type(), "oauth2"; got != want {
		t.Errorf("creds.Type() = %q, want %q", got, want)
	}
}

func TestHTTPAuth(t *testing.T) {
	creds := &HTTPAuth{
		Scheme:   "basic",
		Username: "user",
		Password: "pass",
	}

	if got, want := creds.Type(), "http"; got != want {
		t.Errorf("creds.Type() = %q, want %q", got, want)
	}
}

func TestExpandPath(t *testing.T) {
	// Test home directory expansion
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get user home directory: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{
			name:    "home directory",
			path:    "~/test.json",
			want:    filepath.Join(homeDir, "test.json"),
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "no expansion needed",
			path:    "/absolute/path/test.json",
			want:    "/absolute/path/test.json",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expandPath(tc.path)
			if (err != nil) != tc.wantErr {
				t.Errorf("expandPath() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if err == nil && got != tc.want {
				t.Errorf("expandPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGoogleAuthenticator_Authenticate(t *testing.T) {
	// Create a mock server to simulate the token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "test-token",
			"expires_in": 3600,
			"token_type": "Bearer"
		}`))
	}))
	defer server.Close()

	// Create a GoogleAuthenticator with mock credentials
	creds := &APIKeyCredentials{Key: "test-api-key"}
	auth, err := NewGoogleAuthenticator(creds)
	if err != nil {
		t.Fatalf("NewGoogleAuthenticator() error = %v", err)
	}

	// Create a request to authenticate
	req, err := http.NewRequest("GET", "https://example.com/api", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	// Authenticate the request
	ctx := context.Background()
	err = auth.Authenticate(ctx, req)
	if err != nil {
		t.Fatalf("auth.Authenticate() error = %v", err)
	}

	// Check that the Authorization header was added
	gotAuth := req.Header.Get("Authorization")
	wantAuth := "Bearer test-api-key" // For APIKeyCredentials, we just use the key directly
	if gotAuth != wantAuth {
		t.Errorf("req.Header.Get(\"Authorization\") = %q, want %q", gotAuth, wantAuth)
	}
}

func TestNewGoogleAuthenticator(t *testing.T) {
	tests := []struct {
		name        string
		credentials Credentials
		scopes      []string
		wantScopes  []string
		wantErr     bool
	}{
		{
			name:        "nil credentials",
			credentials: nil,
			scopes:      nil,
			wantScopes:  nil,
			wantErr:     true,
		},
		{
			name:        "valid credentials no scopes",
			credentials: &APIKeyCredentials{Key: "test-key"},
			scopes:      nil,
			wantScopes:  []string{defaultScope},
			wantErr:     false,
		},
		{
			name:        "valid credentials with scopes",
			credentials: &APIKeyCredentials{Key: "test-key"},
			scopes:      []string{"scope1", "scope2"},
			wantScopes:  []string{"scope1", "scope2"},
			wantErr:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewGoogleAuthenticator(tc.credentials, tc.scopes...)
			if (err != nil) != tc.wantErr {
				t.Errorf("NewGoogleAuthenticator() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff(tc.wantScopes, got.scopes); diff != "" {
				t.Errorf("NewGoogleAuthenticator() scopes mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tc.credentials, got.GetCredentials()); diff != "" {
				t.Errorf("NewGoogleAuthenticator() credentials mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGoogleAuthenticator_GetAccessToken(t *testing.T) {
	// This test is simplified and doesn't actually make real API calls

	// Test with API key credentials (simplest case)
	t.Run("APIKeyCredentials", func(t *testing.T) {
		creds := &APIKeyCredentials{Key: "test-api-key"}
		auth, err := NewGoogleAuthenticator(creds)
		if err != nil {
			t.Fatalf("NewGoogleAuthenticator() error = %v", err)
		}

		token, expiry, err := auth.GetAccessToken(context.Background())
		if err != nil {
			t.Fatalf("auth.GetAccessToken() error = %v", err)
		}

		if token != "test-api-key" {
			t.Errorf("auth.GetAccessToken() token = %q, want %q", token, "test-api-key")
		}

		// Check that expiry is about 24 hours in the future
		expectedExpiry := time.Now().Add(24 * time.Hour)
		if expiry.Sub(expectedExpiry) < -time.Minute || expiry.Sub(expectedExpiry) > time.Minute {
			t.Errorf("auth.GetAccessToken() expiry = %v, want approximately %v", expiry, expectedExpiry)
		}
	})

	// Note: Testing with service account or OAuth2 credentials would be more complex
	// and would require mocking the token exchange process
}

func TestAuthSchemeGetSchemeType(t *testing.T) {
	tests := []struct {
		name    string
		scheme  AuthScheme
		want    AuthSchemeType
	}{
		{
			name: "APIKey scheme",
			scheme: AuthScheme{
				APIKey: &APIKeyScheme{
					Type: SchemeTypeAPIKey,
					Name: "api_key",
					In:   LocationHeader,
				},
			},
			want: SchemeTypeAPIKey,
		},
		{
			name: "HTTP scheme",
			scheme: AuthScheme{
				HTTP: &HTTPScheme{
					Type:   SchemeTypeHTTP,
					Scheme: "basic",
				},
			},
			want: SchemeTypeHTTP,
		},
		{
			name: "OAuth2 scheme",
			scheme: AuthScheme{
				OAuth2: &OAuth2Scheme{
					Type: SchemeTypeOAuth2,
					Flows: OAuthFlows{},
				},
			},
			want: SchemeTypeOAuth2,
		},
		{
			name: "OpenIDConnect scheme",
			scheme: AuthScheme{
				OpenIDConnect: &OpenIDConnectScheme{
					Type: SchemeTypeOpenIDConnect,
					OpenIDConfig: OpenIDConfig{
						Issuer: "https://example.com",
					},
				},
			},
			want: SchemeTypeOpenIDConnect,
		},
		{
			name:   "Empty scheme",
			scheme: AuthScheme{},
			want:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.scheme.GetSchemeType()
			if got != tc.want {
				t.Errorf("GetSchemeType() = %v, want %v", got, tc.want)
			}
		})
	}
}