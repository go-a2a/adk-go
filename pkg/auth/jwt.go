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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

// createJWTConfig creates a JWT configuration for service account authentication.
func createJWTConfig(creds *ServiceAccountCredentials, scopes []string) (*jwt.Config, error) {
	// Check if the private key is valid
	_, err := parsePrivateKey(creds.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	config := &jwt.Config{
		Email:      creds.ClientEmail,
		PrivateKey: []byte(creds.PrivateKey),
		Subject:    creds.ClientEmail,
		TokenURL:   creds.TokenURI,
		Scopes:     scopes,
	}

	return config, nil
}

// getJWTTokenSource creates a token source from service account credentials.
func getJWTTokenSource(creds *ServiceAccountCredentials, scopes []string) (oauth2.TokenSource, error) {
	config, err := createJWTConfig(creds, scopes)
	if err != nil {
		return nil, fmt.Errorf("creating JWT config: %w", err)
	}

	return config.TokenSource(context.Background()), nil
}

// parsePrivateKey parses a PEM encoded private key.
func parsePrivateKey(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("private key is not in PKCS1 or PKCS8 format")
		}
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}

	return rsaKey, nil
}

// tokenSourceToPair converts an oauth2.TokenSource to a token string and expiry time.
func tokenSourceToPair(ctx context.Context, ts oauth2.TokenSource) (string, time.Time, error) {
	token, err := ts.Token()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("getting token: %w", err)
	}

	return token.AccessToken, token.Expiry, nil
}
