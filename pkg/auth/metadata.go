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
	"net/http"
	"sync"
	"time"
)

// DefaultGCPMetadataHost is the host where the GCP metadata server runs.
const DefaultGCPMetadataHost = "metadata.google.internal"

// GCPMetadataCredentials represents credentials obtained from the GCP metadata server.
type GCPMetadataCredentials struct {
	metadataURL string
}

// Type returns the type of these credentials.
func (g *GCPMetadataCredentials) Type() string {
	return "gcp_metadata"
}

// GCPMetadataAuthenticator uses the GCP metadata server for authentication.
type GCPMetadataAuthenticator struct {
	credentials *GCPMetadataCredentials
	scopes      []string
	tokenMu     sync.Mutex
	token       string
	tokenExpiry time.Time
}

// newGCPMetadataAuthenticator creates a new authenticator that uses the GCP metadata server.
func newGCPMetadataAuthenticator(scopes ...string) (*GoogleAuthenticator, error) {
	// Check if metadata server is available
	if !isRunningOnGCP() {
		return nil, fmt.Errorf("not running on GCP")
	}

	creds := &GCPMetadataCredentials{
		metadataURL: fmt.Sprintf("http://%s/computeMetadata/v1/instance/service-accounts/default/token", DefaultGCPMetadataHost),
	}

	return &GoogleAuthenticator{
		credentials: creds,
		scopes:      scopes,
	}, nil
}

// isRunningOnGCP checks if the code is running on GCP by making a request to the metadata server.
func isRunningOnGCP() bool {
	client := &http.Client{
		Timeout: 500 * time.Millisecond,
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", DefaultGCPMetadataHost), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// GetAccessToken fetches a token from the GCP metadata server.
func (g *GCPMetadataCredentials) getAccessToken(ctx context.Context) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", g.metadataURL, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating request: %w", err)
	}

	// Required header for metadata server requests
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("metadata server returned status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("reading response body: %w", err)
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