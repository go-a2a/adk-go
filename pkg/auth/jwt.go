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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// createSignedJWT creates a signed JWT for service account authentication.
func createSignedJWT(creds *ServiceAccountCredentials, scopes []string) (string, error) {
	// Parse the private key
	privateKey, err := parsePrivateKey(creds.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Create the JWT header
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": creds.PrivateKeyID,
	}

	// Create the JWT claim set
	now := time.Now()
	exp := now.Add(time.Hour)
	claims := map[string]any{
		"iss": creds.ClientEmail,
		"sub": creds.ClientEmail,
		"scope": strings.Join(scopes, " "),
		"aud": creds.TokenURI,
		"exp": exp.Unix(),
		"iat": now.Unix(),
	}

	// Encode header and claims
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to encode JWT header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to encode JWT claims: %w", err)
	}

	// Create signature input (base64url-encoded header + "." + base64url-encoded claims)
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerEncoded + "." + claimsEncoded

	// Create signature
	hashed := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Encode signature
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	// Create complete JWT
	jwt := signingInput + "." + signatureEncoded
	return jwt, nil
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