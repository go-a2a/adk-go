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

// AuthSchemeType represents the type of authentication scheme.
type AuthSchemeType string

// Predefined authentication scheme types.
const (
	SchemeTypeAPIKey        AuthSchemeType = "apiKey"
	SchemeTypeHTTP          AuthSchemeType = "http"
	SchemeTypeOAuth2        AuthSchemeType = "oauth2"
	SchemeTypeOpenIDConnect AuthSchemeType = "openIdConnect"
)

// AuthLocation represents the location of an authentication parameter.
type AuthLocation string

// Predefined authentication parameter locations.
const (
	LocationQuery  AuthLocation = "query"
	LocationHeader AuthLocation = "header"
	LocationCookie AuthLocation = "cookie"
)

// OAuthFlowType represents the type of OAuth 2.0 flow.
type OAuthFlowType string

// Predefined OAuth 2.0 flow types.
const (
	FlowTypeImplicit          OAuthFlowType = "implicit"
	FlowTypePassword          OAuthFlowType = "password"
	FlowTypeClientCredentials OAuthFlowType = "clientCredentials"
	FlowTypeAuthorizationCode OAuthFlowType = "authorizationCode"
)

// OAuthFlow represents an OAuth 2.0 flow configuration.
type OAuthFlow struct {
	AuthorizationURL string            `json:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl,omitempty"`
	RefreshURL       string            `json:"refreshUrl,omitempty"`
	Scopes           map[string]string `json:"scopes,omitempty"`
}

// OAuthFlows represents the configured OAuth flows for an OAuth security scheme.
type OAuthFlows struct {
	Implicit          *OAuthFlow `json:"implicit,omitempty"`
	Password          *OAuthFlow `json:"password,omitempty"`
	ClientCredentials *OAuthFlow `json:"clientCredentials,omitempty"`
	AuthorizationCode *OAuthFlow `json:"authorizationCode,omitempty"`
}

// APIKeyScheme represents an API key authentication scheme.
type APIKeyScheme struct {
	Type        AuthSchemeType `json:"type"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	In          AuthLocation   `json:"in"`
}

// HTTPScheme represents an HTTP authentication scheme.
type HTTPScheme struct {
	Type        AuthSchemeType `json:"type"`
	Description string         `json:"description,omitempty"`
	Scheme      string         `json:"scheme"`
	BearerOnly  bool           `json:"bearerOnly,omitempty"`
}

// OAuth2Scheme represents an OAuth 2.0 authentication scheme.
type OAuth2Scheme struct {
	Type        AuthSchemeType `json:"type"`
	Description string         `json:"description,omitempty"`
	Flows       OAuthFlows     `json:"flows"`
}

// OpenIDConnectScheme represents an OpenID Connect authentication scheme.
type OpenIDConnectScheme struct {
	Type         AuthSchemeType `json:"type"`
	Description  string         `json:"description,omitempty"`
	OpenIDConfig OpenIDConfig   `json:"openIdConfig"`
}

// OpenIDConfig represents the configuration for OpenID Connect.
type OpenIDConfig struct {
	Issuer                 string         `json:"issuer"`
	AuthorizationEndpoint  string         `json:"authorization_endpoint"`
	TokenEndpoint          string         `json:"token_endpoint"`
	UserInfoEndpoint       string         `json:"userinfo_endpoint,omitempty"`
	JwksURI                string         `json:"jwks_uri,omitempty"`
	RegistrationEndpoint   string         `json:"registration_endpoint,omitempty"`
	RevocationEndpoint     string         `json:"revocation_endpoint,omitempty"`
	TokenIntrospectionURI  string         `json:"token_introspection_uri,omitempty"`
	ScopesSupported        []string       `json:"scopes_supported,omitempty"`
	ResponseTypesSupported []string       `json:"response_types_supported,omitempty"`
	GrantTypesSupported    []string       `json:"grant_types_supported,omitempty"`
	Additional             map[string]any `json:"-"`
}

// AuthScheme represents an authentication scheme (union of all scheme types).
type AuthScheme struct {
	// Exactly one of these fields should be set
	APIKey        *APIKeyScheme        `json:"apiKey,omitempty"`
	HTTP          *HTTPScheme          `json:"http,omitempty"`
	OAuth2        *OAuth2Scheme        `json:"oauth2,omitempty"`
	OpenIDConnect *OpenIDConnectScheme `json:"openIdConnect,omitempty"`
}

// GetSchemeType returns the type of the authentication scheme.
func (a *AuthScheme) GetSchemeType() AuthSchemeType {
	switch {
	case a.APIKey != nil:
		return SchemeTypeAPIKey
	case a.HTTP != nil:
		return SchemeTypeHTTP
	case a.OAuth2 != nil:
		return SchemeTypeOAuth2
	case a.OpenIDConnect != nil:
		return SchemeTypeOpenIDConnect
	default:
		return ""
	}
}
