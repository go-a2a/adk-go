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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Common errors returned by the auth package.
var (
	ErrCredentialsNotFound = errors.New("credentials not found")
	ErrInvalidCredentials  = errors.New("invalid credentials")
)

// AuthCredentialType represents the type of authentication credentials.
type AuthCredentialType string

// Predefined authentication credential types.
const (
	CredentialTypeAPIKey         AuthCredentialType = "api_key"
	CredentialTypeHTTP           AuthCredentialType = "http"
	CredentialTypeOAuth2         AuthCredentialType = "oauth2"
	CredentialTypeOpenIDConnect  AuthCredentialType = "oidc"
	CredentialTypeServiceAccount AuthCredentialType = "service_account"
)

// HTTPAuth represents HTTP authentication credentials.
type HTTPAuth struct {
	Scheme     string `json:"scheme"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Token      string `json:"token,omitempty"`
	BearerOnly bool   `json:"bearer_only,omitempty"`
}

// Type returns the type of these credentials.
func (h *HTTPAuth) Type() string {
	return string(CredentialTypeHTTP)
}

// APIKeyCredentials represents API key credentials.
type APIKeyCredentials struct {
	Key string `json:"api_key"`
}

// Type returns the type of these credentials.
func (a *APIKeyCredentials) Type() string {
	return string(CredentialTypeAPIKey)
}

// OAuth2Auth represents OAuth 2.0 authentication credentials.
type OAuth2Auth struct {
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenURI     string `json:"token_uri,omitempty"`
	Scopes       string `json:"scopes,omitempty"`
}

// Type returns the type of these credentials.
func (o *OAuth2Auth) Type() string {
	return string(CredentialTypeOAuth2)
}

// ServiceAccountCredentials represents service account credentials.
type ServiceAccountCredentials struct {
	Type                string `json:"type"`
	ProjectID           string `json:"project_id"`
	PrivateKeyID        string `json:"private_key_id"`
	PrivateKey          string `json:"private_key"`
	ClientEmail         string `json:"client_email"`
	ClientID            string `json:"client_id"`
	AuthURI             string `json:"auth_uri"`
	TokenURI            string `json:"token_uri"`
	AuthProviderCertURL string `json:"auth_provider_x509_cert_url"`
	ClientCertURL       string `json:"client_x509_cert_url"`
}

// Type returns the type of these credentials.
func (s *ServiceAccountCredentials) Type() string {
	return string(CredentialTypeServiceAccount)
}

// AuthCredential is a composite type that can hold any type of authentication credentials.
type AuthCredential struct {
	AuthType       AuthCredentialType         `json:"auth_type"`
	APIKey         string                     `json:"api_key,omitempty"`
	HTTP           *HTTPAuth                  `json:"http,omitempty"`
	OAuth2         *OAuth2Auth                `json:"oauth2,omitempty"`
	ServiceAccount *ServiceAccountCredentials `json:"service_account,omitempty"`
}

// Type returns the type of these credentials.
func (a *AuthCredential) Type() string {
	return string(a.AuthType)
}

// GetCredentials returns the appropriate credentials based on the auth type.
func (a *AuthCredential) GetCredentials() (Credentials, error) {
	switch a.AuthType {
	case CredentialTypeAPIKey:
		return &APIKeyCredentials{Key: a.APIKey}, nil
	case CredentialTypeHTTP:
		if a.HTTP == nil {
			return nil, fmt.Errorf("HTTP auth credentials not provided")
		}
		return a.HTTP, nil
	case CredentialTypeOAuth2:
		if a.OAuth2 == nil {
			return nil, fmt.Errorf("OAuth2 credentials not provided")
		}
		return a.OAuth2, nil
	case CredentialTypeServiceAccount:
		if a.ServiceAccount == nil {
			return nil, fmt.Errorf("service account credentials not provided")
		}
		return a.ServiceAccount, nil
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", a.AuthType)
	}
}

// LoadCredentialsFromFile loads credentials from a JSON file.
func LoadCredentialsFromFile(filePath string) (Credentials, error) {
	expandedPath, err := expandPath(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to expand path: %w", err)
	}

	data, err := os.ReadFile(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}

	return LoadCredentialsFromJSON(data)
}

// LoadCredentialsFromJSON loads credentials from JSON data.
func LoadCredentialsFromJSON(data []byte) (Credentials, error) {
	var typeInfo struct {
		Type string `json:"type"`
	}

	if err := json.Unmarshal(data, &typeInfo); err != nil {
		// If we can't determine the type, try treating it as an API key
		return &APIKeyCredentials{Key: string(data)}, nil
	}

	switch AuthCredentialType(typeInfo.Type) {
	case CredentialTypeServiceAccount:
		var creds ServiceAccountCredentials
		if err := json.Unmarshal(data, &creds); err != nil {
			return nil, fmt.Errorf("failed to parse service account credentials: %w", err)
		}
		return &creds, nil

	case CredentialTypeOAuth2:
		var creds OAuth2Auth
		if err := json.Unmarshal(data, &creds); err != nil {
			return nil, fmt.Errorf("failed to parse OAuth2 credentials: %w", err)
		}
		return &creds, nil

	case CredentialTypeHTTP:
		var creds HTTPAuth
		if err := json.Unmarshal(data, &creds); err != nil {
			return nil, fmt.Errorf("failed to parse HTTP credentials: %w", err)
		}
		return &creds, nil

	case CredentialTypeAPIKey:
		var creds struct {
			APIKey string `json:"api_key"`
		}
		if err := json.Unmarshal(data, &creds); err != nil {
			return nil, fmt.Errorf("failed to parse API key: %w", err)
		}
		return &APIKeyCredentials{Key: creds.APIKey}, nil

	default:
		// Try to parse as a generic AuthCredential
		var authCred AuthCredential
		if err := json.Unmarshal(data, &authCred); err != nil {
			return nil, fmt.Errorf("failed to parse credentials: %w", err)
		}
		return authCred.GetCredentials()
	}
}

// expandPath expands the tilde and environment variables in the given path.
func expandPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty path")
	}

	// Handle tilde expansion
	if path[0] == '~' && (len(path) == 1 || path[1] == '/') {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		path = filepath.Join(homeDir, path[1:])
	}

	// Handle environment variable expansion
	return os.ExpandEnv(path), nil
}
