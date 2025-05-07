// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"time"

	"golang.org/x/oauth2"
)

// BaseCredentials represents the base functionality for all credential types.
type BaseCredentials struct {
	// ID is a unique identifier for these credentials.
	ID string `json:"id"`

	// Name is a human-readable name for these credentials.
	Name string `json:"name"`

	// CreatedAt is when these credentials were created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when these credentials were last updated.
	UpdatedAt time.Time `json:"updated_at"`

	// ExpiresAt is when these credentials expire, if applicable.
	ExpiresAt time.Time `json:"expires_at,omitzero"`

	// Data contains credential-specific data.
	Data map[string]any `json:"data,omitempty"`
}

// NewBaseCredentials creates a new BaseCredentials.
func NewBaseCredentials(id, name string) *BaseCredentials {
	now := time.Now()
	return &BaseCredentials{
		ID:        id,
		Name:      name,
		CreatedAt: now,
		UpdatedAt: now,
		Data:      make(map[string]any),
	}
}

// IsExpired checks if the credentials have expired.
func (c *BaseCredentials) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// ToMap converts the credentials to a map.
func (c *BaseCredentials) ToMap() map[string]any {
	return map[string]any{
		"id":         c.ID,
		"name":       c.Name,
		"created_at": c.CreatedAt,
		"updated_at": c.UpdatedAt,
		"expires_at": c.ExpiresAt,
		"data":       c.Data,
	}
}

// FromMap updates the credentials from a map.
func (c *BaseCredentials) FromMap(data map[string]any) error {
	if id, ok := data["id"].(string); ok {
		c.ID = id
	}
	if name, ok := data["name"].(string); ok {
		c.Name = name
	}
	if createdAt, ok := data["created_at"].(time.Time); ok {
		c.CreatedAt = createdAt
	}
	if updatedAt, ok := data["updated_at"].(time.Time); ok {
		c.UpdatedAt = updatedAt
	}
	if expiresAt, ok := data["expires_at"].(time.Time); ok {
		c.ExpiresAt = expiresAt
	}
	if credData, ok := data["data"].(map[string]any); ok {
		c.Data = credData
	}
	return nil
}

// OAuth2Credentials represents OAuth2 credentials.
type OAuth2Credentials struct {
	BaseCredentials

	// AccessToken is the token to access protected resources.
	AccessToken string `json:"access_token"`

	// RefreshToken is the token to refresh the access token.
	RefreshToken string `json:"refresh_token,omitempty"`

	// TokenType is the type of token, e.g., "Bearer".
	TokenType string `json:"token_type,omitempty"`

	// Scopes are the OAuth2 scopes granted to these credentials.
	Scopes []string `json:"scopes,omitempty"`
}

// Type returns the type of the credentials.
func (c *OAuth2Credentials) Type() string {
	return SchemeTypeOAuth2
}

// ToMap converts the credentials to a map.
func (c *OAuth2Credentials) ToMap() map[string]any {
	baseMap := c.BaseCredentials.ToMap()
	baseMap["access_token"] = c.AccessToken
	baseMap["refresh_token"] = c.RefreshToken
	baseMap["token_type"] = c.TokenType
	baseMap["scopes"] = c.Scopes
	return baseMap
}

// FromMap updates the credentials from a map.
func (c *OAuth2Credentials) FromMap(data map[string]any) error {
	if err := c.BaseCredentials.FromMap(data); err != nil {
		return err
	}
	if accessToken, ok := data["access_token"].(string); ok {
		c.AccessToken = accessToken
	}
	if refreshToken, ok := data["refresh_token"].(string); ok {
		c.RefreshToken = refreshToken
	}
	if tokenType, ok := data["token_type"].(string); ok {
		c.TokenType = tokenType
	}
	if scopes, ok := data["scopes"].([]string); ok {
		c.Scopes = scopes
	} else if scopesAny, ok := data["scopes"].([]any); ok {
		c.Scopes = make([]string, len(scopesAny))
		for i, s := range scopesAny {
			if str, ok := s.(string); ok {
				c.Scopes[i] = str
			}
		}
	}
	return nil
}

// ToToken converts OAuth2Credentials to an oauth2.Token.
func (c *OAuth2Credentials) ToToken() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  c.AccessToken,
		RefreshToken: c.RefreshToken,
		TokenType:    c.TokenType,
		Expiry:       c.ExpiresAt,
	}
}

// FromToken updates OAuth2Credentials from an oauth2.Token.
func (c *OAuth2Credentials) FromToken(token *oauth2.Token) {
	c.AccessToken = token.AccessToken
	c.RefreshToken = token.RefreshToken
	c.TokenType = token.TokenType
	c.ExpiresAt = token.Expiry
	c.UpdatedAt = time.Now()
}

// NewOAuth2Credentials creates new OAuth2 credentials.
func NewOAuth2Credentials(id, name string) *OAuth2Credentials {
	return &OAuth2Credentials{
		BaseCredentials: *NewBaseCredentials(id, name),
		Scopes:          []string{},
	}
}

// APIKeyCredentials represents API key credentials.
type APIKeyCredentials struct {
	BaseCredentials

	// APIKey is the API key.
	APIKey string `json:"api_key"`

	// KeyLocation indicates where to put the API key (header, query, etc.).
	KeyLocation string `json:"key_location,omitempty"`

	// KeyName is the name of the parameter or header for the API key.
	KeyName string `json:"key_name,omitempty"`
}

// Type returns the type of the credentials.
func (c *APIKeyCredentials) Type() string {
	return SchemeTypeAPIKey
}

// ToMap converts the credentials to a map.
func (c *APIKeyCredentials) ToMap() map[string]any {
	baseMap := c.BaseCredentials.ToMap()
	baseMap["api_key"] = c.APIKey
	baseMap["key_location"] = c.KeyLocation
	baseMap["key_name"] = c.KeyName
	return baseMap
}

// FromMap updates the credentials from a map.
func (c *APIKeyCredentials) FromMap(data map[string]any) error {
	if err := c.BaseCredentials.FromMap(data); err != nil {
		return err
	}
	if apiKey, ok := data["api_key"].(string); ok {
		c.APIKey = apiKey
	}
	if keyLocation, ok := data["key_location"].(string); ok {
		c.KeyLocation = keyLocation
	}
	if keyName, ok := data["key_name"].(string); ok {
		c.KeyName = keyName
	}
	return nil
}

// NewAPIKeyCredentials creates new API key credentials.
func NewAPIKeyCredentials(id, name, apiKey string) *APIKeyCredentials {
	return &APIKeyCredentials{
		BaseCredentials: *NewBaseCredentials(id, name),
		APIKey:          apiKey,
		KeyLocation:     "header",
		KeyName:         "X-API-Key",
	}
}

// BasicAuthCredentials represents basic authentication credentials.
type BasicAuthCredentials struct {
	BaseCredentials

	// Username is the username for basic auth.
	Username string `json:"username"`

	// Password is the password for basic auth.
	Password string `json:"password"`
}

// Type returns the type of the credentials.
func (c *BasicAuthCredentials) Type() string {
	return SchemeTypeBasic
}

// ToMap converts the credentials to a map.
func (c *BasicAuthCredentials) ToMap() map[string]any {
	baseMap := c.BaseCredentials.ToMap()
	baseMap["username"] = c.Username
	baseMap["password"] = c.Password
	return baseMap
}

// FromMap updates the credentials from a map.
func (c *BasicAuthCredentials) FromMap(data map[string]any) error {
	if err := c.BaseCredentials.FromMap(data); err != nil {
		return err
	}
	if username, ok := data["username"].(string); ok {
		c.Username = username
	}
	if password, ok := data["password"].(string); ok {
		c.Password = password
	}
	return nil
}

// NewBasicAuthCredentials creates new basic auth credentials.
func NewBasicAuthCredentials(id, name, username, password string) *BasicAuthCredentials {
	return &BasicAuthCredentials{
		BaseCredentials: *NewBaseCredentials(id, name),
		Username:        username,
		Password:        password,
	}
}

// BearerTokenCredentials represents bearer token credentials.
type BearerTokenCredentials struct {
	BaseCredentials

	// Token is the bearer token.
	Token string `json:"token"`
}

// Type returns the type of the credentials.
func (c *BearerTokenCredentials) Type() string {
	return SchemeTypeBearer
}

// ToMap converts the credentials to a map.
func (c *BearerTokenCredentials) ToMap() map[string]any {
	baseMap := c.BaseCredentials.ToMap()
	baseMap["token"] = c.Token
	return baseMap
}

// FromMap updates the credentials from a map.
func (c *BearerTokenCredentials) FromMap(data map[string]any) error {
	if err := c.BaseCredentials.FromMap(data); err != nil {
		return err
	}
	if token, ok := data["token"].(string); ok {
		c.Token = token
	}
	return nil
}

// NewBearerTokenCredentials creates new bearer token credentials.
func NewBearerTokenCredentials(id, name, token string) *BearerTokenCredentials {
	return &BearerTokenCredentials{
		BaseCredentials: *NewBaseCredentials(id, name),
		Token:           token,
	}
}

// CredentialStore is an interface for storing and retrieving credentials.
type CredentialStore interface {
	// GetCredentials retrieves credentials by ID.
	GetCredentials(id string) (Credentials, error)

	// StoreCredentials stores credentials.
	StoreCredentials(credentials Credentials) error

	// DeleteCredentials deletes credentials by ID.
	DeleteCredentials(id string) error

	// ListCredentials lists all stored credentials.
	ListCredentials() ([]Credentials, error)
}

// InMemoryCredentialStore is an in-memory implementation of CredentialStore.
type InMemoryCredentialStore struct {
	credentials map[string]Credentials
}

// NewInMemoryCredentialStore creates a new in-memory credential store.
func NewInMemoryCredentialStore() *InMemoryCredentialStore {
	return &InMemoryCredentialStore{
		credentials: make(map[string]Credentials),
	}
}

// GetCredentials retrieves credentials by ID.
func (s *InMemoryCredentialStore) GetCredentials(id string) (Credentials, error) {
	cred, ok := s.credentials[id]
	if !ok {
		return nil, ErrCredentialsNotFound
	}
	return cred, nil
}

// StoreCredentials stores credentials.
func (s *InMemoryCredentialStore) StoreCredentials(credentials Credentials) error {
	id := credentials.ToMap()["id"].(string)
	s.credentials[id] = credentials
	return nil
}

// DeleteCredentials deletes credentials by ID.
func (s *InMemoryCredentialStore) DeleteCredentials(id string) error {
	if _, ok := s.credentials[id]; !ok {
		return ErrCredentialsNotFound
	}
	delete(s.credentials, id)
	return nil
}

// ListCredentials lists all stored credentials.
func (s *InMemoryCredentialStore) ListCredentials() ([]Credentials, error) {
	creds := make([]Credentials, 0, len(s.credentials))
	for _, cred := range s.credentials {
		creds = append(creds, cred)
	}
	return creds, nil
}

// SerializeCredentials serializes credentials to JSON.
func SerializeCredentials(creds Credentials) ([]byte, error) {
	return json.Marshal(creds.ToMap())
}

// DeserializeCredentials deserializes credentials from JSON based on the scheme type.
func DeserializeCredentials(data []byte) (Credentials, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	schemeType, ok := raw["data"].(map[string]any)["scheme_type"].(string)
	if !ok {
		return nil, ErrInvalidCredentials
	}

	var creds Credentials
	switch schemeType {
	case SchemeTypeOAuth2:
		creds = NewOAuth2Credentials("", "")
	case SchemeTypeAPIKey:
		creds = NewAPIKeyCredentials("", "", "")
	case SchemeTypeBasic:
		creds = NewBasicAuthCredentials("", "", "", "")
	case SchemeTypeBearer:
		creds = NewBearerTokenCredentials("", "", "")
	default:
		return nil, ErrUnsupportedAuthScheme
	}

	if err := creds.FromMap(raw); err != nil {
		return nil, err
	}

	return creds, nil
}
