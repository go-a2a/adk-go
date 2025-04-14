// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package auth

// AuthConfig represents the authentication configuration for a function call.
type AuthConfig struct {
	// AuthScheme describes the authentication scheme used.
	AuthScheme *AuthScheme `json:"auth_scheme"`

	// RawAuthCredential contains the initial authentication credentials provided.
	RawAuthCredential *AuthCredential `json:"raw_auth_credential,omitempty"`

	// ExchangedAuthCredential contains the processed authentication credentials.
	ExchangedAuthCredential *AuthCredential `json:"exchanged_auth_credential,omitempty"`
}

// AuthToolArguments represents the arguments for an authentication request.
type AuthToolArguments struct {
	// FunctionCallID is a unique identifier for the function call.
	FunctionCallID string `json:"function_call_id"`

	// AuthConfig contains the authentication configuration.
	AuthConfig *AuthConfig `json:"auth_config"`
}
