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