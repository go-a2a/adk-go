// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/tool/tools"
	"github.com/go-a2a/adk-go/types"
)

const (
	// AuthToolName is the name of the auth tool.
	AuthToolName = "auth"

	// AuthToolDescription is the description of the auth tool.
	AuthToolDescription = "Manage authentication for services."
)

// Tool provides authentication functionality as a tool.
type Tool struct {
	// handler is the authentication handler.
	handler *Handler

	// logger is the logger for tool operations.
	logger *slog.Logger

	// name is the name of the tool.
	name string

	// description is the description of the tool.
	description string

	// authHandlerMap maps user app keys to auth handlers.
	authHandlerMap map[string]*Handler
}

// ToolOption is a function that configures the Tool.
type ToolOption func(*Tool)

// WithToolName sets the name of the Tool.
func WithToolName(name string) ToolOption {
	return func(t *Tool) {
		t.name = name
	}
}

// WithToolDescription sets the description of the Tool.
func WithToolDescription(description string) ToolOption {
	return func(t *Tool) {
		t.description = description
	}
}

// WithToolLogger sets the logger for the Tool.
func WithToolLogger(logger *slog.Logger) ToolOption {
	return func(t *Tool) {
		t.logger = logger
	}
}

// NewTool creates a new auth Tool.
func NewTool(handler *Handler, opts ...ToolOption) *Tool {
	tool := &Tool{
		handler:        handler,
		logger:         handler.logger,
		name:           AuthToolName,
		description:    AuthToolDescription,
		authHandlerMap: make(map[string]*Handler),
	}

	for _, opt := range opts {
		opt(tool)
	}

	return tool
}

// Name returns the name of the tool.
func (t *Tool) Name() string {
	return t.name
}

// Description returns the description of the tool.
func (t *Tool) Description() string {
	return t.description
}

// InputSchema returns the JSON schema for the tool's input.
func (t *Tool) InputSchema() *genai.Schema {
	return &genai.Schema{
		Type: "object",
		Properties: map[string]*genai.Schema{
			"operation": {
				Type:        "string",
				Description: "Authentication operation to perform.",
				Enum:        []string{"get_auth_info", "authenticate", "refresh", "list_credentials", "get_credential", "store_credential", "delete_credential"},
			},
			"auth_type": {
				Type:        "string",
				Description: "Authentication type (used for authentication operations).",
				Enum:        []string{"oauth2", "api_key", "basic", "bearer", "none"},
			},
			"credential_id": {
				Type:        "string",
				Description: "ID of the credential to operate on.",
			},
			"credential_name": {
				Type:        "string",
				Description: "Name of the credential (used when creating credentials).",
			},
			"oauth2": {
				Type:        "object",
				Description: "OAuth2 specific parameters.",
				Properties: map[string]*genai.Schema{
					"access_token": {
						Type:        "string",
						Description: "OAuth2 access token.",
					},
					"refresh_token": {
						Type:        "string",
						Description: "OAuth2 refresh token.",
					},
					"expires_in": {
						Type:        "integer",
						Description: "OAuth2 token expiration time in seconds.",
					},
					"token_type": {
						Type:        "string",
						Description: "OAuth2 token type.",
					},
					"scopes": {
						Type:        "array",
						Description: "OAuth2 scopes.",
						Items: &genai.Schema{
							Type: "string",
						},
					},
					"auth_code": {
						Type:        "string",
						Description: "OAuth2 authorization code (used for code exchange).",
					},
				},
			},
			"api_key": {
				Type:        "object",
				Description: "API key specific parameters.",
				Properties: map[string]*genai.Schema{
					"key": {
						Type:        "string",
						Description: "API key value.",
					},
					"location": {
						Type:        "string",
						Description: "API key location (header, query).",
						Enum:        []string{"header", "query"},
					},
					"name": {
						Type:        "string",
						Description: "API key parameter name.",
					},
				},
			},
			"basic_auth": {
				Type:        "object",
				Description: "Basic auth specific parameters.",
				Properties: map[string]*genai.Schema{
					"username": {
						Type:        "string",
						Description: "Basic auth username.",
					},
					"password": {
						Type:        "string",
						Description: "Basic auth password.",
					},
				},
			},
			"bearer_token": {
				Type:        "object",
				Description: "Bearer token specific parameters.",
				Properties: map[string]*genai.Schema{
					"token": {
						Type:        "string",
						Description: "Bearer token value.",
					},
				},
			},
		},
		Required: []string{"operation"},
	}
}

// Execute runs the auth operation.
func (t *Tool) Execute(ctx context.Context, params map[string]any) (any, error) {
	// Get the operation to perform
	operation, ok := params["operation"].(string)
	if !ok {
		return nil, errors.New("operation parameter is required")
	}

	t.logger.InfoContext(ctx, "Executing auth tool",
		slog.String("operation", operation),
	)

	// Get the auth handler to use
	handler := t.handler

	// Check if there's a specific handler for this app
	if userID, ok := ctx.Value("user_id").(string); ok {
		if appName, ok := ctx.Value("app_name").(string); ok {
			key := appName + ":" + userID
			if h, ok := t.authHandlerMap[key]; ok {
				handler = h
			}
		}
	}

	switch operation {
	case "get_auth_info":
		return t.getAuthInfo(handler)
	case "authenticate":
		return t.authenticate(ctx, handler, params)
	case "refresh":
		return t.refreshCredentials(ctx, handler, params)
	case "list_credentials":
		return t.listCredentials(handler)
	case "get_credential":
		return t.getCredential(handler, params)
	case "store_credential":
		return t.storeCredential(ctx, handler, params)
	case "delete_credential":
		return t.deleteCredential(handler, params)
	default:
		return nil, fmt.Errorf("unsupported operation: %s", operation)
	}
}

// getAuthInfo returns information about the authentication configuration.
func (t *Tool) getAuthInfo(handler *Handler) (any, error) {
	info := handler.GetAuthInfo()
	return info, nil
}

// authenticate performs authentication with the provided credentials.
func (t *Tool) authenticate(ctx context.Context, handler *Handler, params map[string]any) (any, error) {
	// Get the auth type
	authType, ok := params["auth_type"].(string)
	if !ok {
		return nil, errors.New("auth_type parameter is required")
	}

	var credentials Credentials

	// Check if we have a credential ID
	if credID, ok := params["credential_id"].(string); ok {
		// Get existing credentials
		var err error
		credentials, err = handler.GetCredentials(credID)
		if err != nil {
			t.logger.WarnContext(ctx, "Credential not found, creating new one",
				slog.String("credential_id", credID),
				slog.String("auth_type", authType),
			)
			// Create new credentials with this ID
			credentials = t.createCredentials(ctx, authType, credID, params)
		}
	} else {
		// Create new credentials
		credID := uuid.New().String()
		credentials = t.createCredentials(ctx, authType, credID, params)
	}

	// Authenticate with the credentials
	response, err := handler.Authenticate(ctx, credentials)
	if err != nil {
		return nil, err
	}

	// Return the response
	return map[string]any{
		"status":          "success",
		"credential_id":   credentials.ToMap()["id"],
		"credential_name": credentials.ToMap()["name"],
		"auth_type":       credentials.Type(),
		"access_token":    response.AccessToken,
		"refresh_token":   response.RefreshToken,
		"expires_at":      response.ExpiresAt.Format(time.RFC3339),
		"token_type":      response.TokenType,
	}, nil
}

// refreshCredentials refreshes the provided credentials.
func (t *Tool) refreshCredentials(ctx context.Context, handler *Handler, params map[string]any) (any, error) {
	// Get the credential ID
	credID, ok := params["credential_id"].(string)
	if !ok {
		return nil, errors.New("credential_id parameter is required")
	}

	// Get the credentials
	credentials, err := handler.GetCredentials(credID)
	if err != nil {
		return nil, err
	}

	// Refresh the credentials
	refreshed, err := handler.RefreshCredentials(ctx, credentials)
	if err != nil {
		return nil, err
	}

	// Convert to map for response
	credMap := refreshed.ToMap()

	// Return the refreshed credentials
	return map[string]any{
		"status":          "success",
		"credential_id":   credMap["id"],
		"credential_name": credMap["name"],
		"auth_type":       refreshed.Type(),
		"expires_at":      credMap["expires_at"],
	}, nil
}

// listCredentials lists all stored credentials.
func (t *Tool) listCredentials(handler *Handler) (any, error) {
	credentials, err := handler.ListCredentials()
	if err != nil {
		return nil, err
	}

	// Convert credentials to map
	var result []map[string]any
	for _, cred := range credentials {
		credMap := cred.ToMap()
		credMap["auth_type"] = cred.Type()
		result = append(result, credMap)
	}

	return map[string]any{
		"status":      "success",
		"credentials": result,
	}, nil
}

// getCredential retrieves a credential by ID.
func (t *Tool) getCredential(handler *Handler, params map[string]any) (any, error) {
	// Get the credential ID
	credID, ok := params["credential_id"].(string)
	if !ok {
		return nil, errors.New("credential_id parameter is required")
	}

	// Get the credentials
	credentials, err := handler.GetCredentials(credID)
	if err != nil {
		return nil, err
	}

	// Convert to map for response
	credMap := credentials.ToMap()
	credMap["auth_type"] = credentials.Type()

	// Clean sensitive data for response
	if _, ok := credentials.(*OAuth2Credentials); ok {
		credMap["access_token"] = "****"
		credMap["refresh_token"] = "****"
	} else if _, ok := credentials.(*APIKeyCredentials); ok {
		credMap["api_key"] = "****"
	} else if _, ok := credentials.(*BasicAuthCredentials); ok {
		credMap["password"] = "****"
	} else if _, ok := credentials.(*BearerTokenCredentials); ok {
		credMap["token"] = "****"
	}

	return map[string]any{
		"status":     "success",
		"credential": credMap,
	}, nil
}

// storeCredential stores a credential.
func (t *Tool) storeCredential(ctx context.Context, handler *Handler, params map[string]any) (any, error) {
	// Get the auth type
	authType, ok := params["auth_type"].(string)
	if !ok {
		return nil, errors.New("auth_type parameter is required")
	}

	// Generate credential ID if not provided
	credID := uuid.New().String()
	if id, ok := params["credential_id"].(string); ok && id != "" {
		credID = id
	}

	// Create credentials
	credentials := t.createCredentials(ctx, authType, credID, params)

	// Store the credentials
	if err := handler.StoreCredentials(credentials); err != nil {
		return nil, err
	}

	// Convert to map for response
	credMap := credentials.ToMap()
	credMap["auth_type"] = credentials.Type()

	return map[string]any{
		"status":     "success",
		"credential": credMap,
	}, nil
}

// deleteCredential deletes a credential by ID.
func (t *Tool) deleteCredential(handler *Handler, params map[string]any) (any, error) {
	// Get the credential ID
	credID, ok := params["credential_id"].(string)
	if !ok {
		return nil, errors.New("credential_id parameter is required")
	}

	// Delete the credentials
	if err := handler.DeleteCredentials(credID); err != nil {
		return nil, err
	}

	return map[string]any{
		"status":        "success",
		"credential_id": credID,
	}, nil
}

// createCredentials creates credentials based on the auth type and parameters.
func (t *Tool) createCredentials(ctx context.Context, authType, credID string, params map[string]any) Credentials {
	credName := "Default Credential"
	if name, ok := params["credential_name"].(string); ok && name != "" {
		credName = name
	}

	switch authType {
	case SchemeTypeOAuth2:
		return t.createOAuth2Credentials(credID, credName, params)
	case SchemeTypeAPIKey:
		return t.createAPIKeyCredentials(credID, credName, params)
	case SchemeTypeBasic:
		return t.createBasicAuthCredentials(credID, credName, params)
	case SchemeTypeBearer:
		return t.createBearerTokenCredentials(credID, credName, params)
	default:
		t.logger.WarnContext(ctx, "Unsupported auth type, using OAuth2",
			slog.String("auth_type", authType),
		)
		return t.createOAuth2Credentials(credID, credName, params)
	}
}

// createOAuth2Credentials creates OAuth2 credentials from parameters.
func (t *Tool) createOAuth2Credentials(credID, credName string, params map[string]any) *OAuth2Credentials {
	creds := NewOAuth2Credentials(credID, credName)

	// Extract OAuth2 specific parameters
	if oauth2Params, ok := params["oauth2"].(map[string]any); ok {
		if accessToken, ok := oauth2Params["access_token"].(string); ok {
			creds.AccessToken = accessToken
		}
		if refreshToken, ok := oauth2Params["refresh_token"].(string); ok {
			creds.RefreshToken = refreshToken
		}
		if tokenType, ok := oauth2Params["token_type"].(string); ok {
			creds.TokenType = tokenType
		} else {
			creds.TokenType = "Bearer" // Default
		}
		if expiresIn, ok := oauth2Params["expires_in"].(float64); ok {
			creds.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
		}
		if scopes, ok := oauth2Params["scopes"].([]string); ok {
			creds.Scopes = scopes
		} else if scopesAny, ok := oauth2Params["scopes"].([]any); ok {
			creds.Scopes = make([]string, len(scopesAny))
			for i, s := range scopesAny {
				if str, ok := s.(string); ok {
					creds.Scopes[i] = str
				}
			}
		}
	}

	return creds
}

// createAPIKeyCredentials creates API key credentials from parameters.
func (t *Tool) createAPIKeyCredentials(credID, credName string, params map[string]any) *APIKeyCredentials {
	creds := NewAPIKeyCredentials(credID, credName, "")

	// Extract API key specific parameters
	if apiKeyParams, ok := params["api_key"].(map[string]any); ok {
		if key, ok := apiKeyParams["key"].(string); ok {
			creds.APIKey = key
		}
		if location, ok := apiKeyParams["location"].(string); ok {
			creds.KeyLocation = location
		}
		if name, ok := apiKeyParams["name"].(string); ok {
			creds.KeyName = name
		}
	}

	return creds
}

// createBasicAuthCredentials creates basic auth credentials from parameters.
func (t *Tool) createBasicAuthCredentials(credID, credName string, params map[string]any) *BasicAuthCredentials {
	creds := NewBasicAuthCredentials(credID, credName, "", "")

	// Extract basic auth specific parameters
	if basicAuthParams, ok := params["basic_auth"].(map[string]any); ok {
		if username, ok := basicAuthParams["username"].(string); ok {
			creds.Username = username
		}
		if password, ok := basicAuthParams["password"].(string); ok {
			creds.Password = password
		}
	}

	return creds
}

// createBearerTokenCredentials creates bearer token credentials from parameters.
func (t *Tool) createBearerTokenCredentials(credID, credName string, params map[string]any) *BearerTokenCredentials {
	creds := NewBearerTokenCredentials(credID, credName, "")

	// Extract bearer token specific parameters
	if bearerTokenParams, ok := params["bearer_token"].(map[string]any); ok {
		if token, ok := bearerTokenParams["token"].(string); ok {
			creds.Token = token
		}
	}

	return creds
}

// RegisterAuthTool registers the auth tool with an agent.
func RegisterAuthTool(agent types.Agent, handler *Handler) error {
	// Create the auth tool
	authTool := NewTool(handler)

	// Convert to a generic tool
	genericTool := tools.NewAgent(
		authTool.Name(),
		authTool.Description(),
		tools.WithInputSchema(authTool.InputSchema()),
		tools.WithToolExecuteFunc(authTool.Execute),
	)

	// Get the reflection value of the agent
	agentValue := fmt.Sprintf("%v", agent)

	// Add the tool to the agent using reflection
	var err error
	if value, ok := agent.(interface{ AddTool(types.Tool) error }); ok {
		err = value.AddTool(genericTool)
	} else {
		err = fmt.Errorf("unable to add auth tool to agent: %v", agentValue)
	}

	return err
}

// Callback is a function that's called during auth events.
type Callback func(ctx context.Context, event string, data map[string]any) error

// ProcessAuthConfig processes an auth configuration from an event.
func ProcessAuthConfig(ctx context.Context, data map[string]any, callback Callback) (*types.AuthConfig, error) {
	// Convert data to JSON for easier processing
	jsonData, err := sonic.ConfigFastest.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Parse the auth config
	var authConfig types.AuthConfig
	if err := sonic.ConfigFastest.Unmarshal(jsonData, &authConfig); err != nil {
		return nil, err
	}

	// Validate the auth config
	if authConfig.SchemeType == "" {
		return nil, errors.New("scheme_type is required")
	}

	// Validate scheme-specific config
	switch authConfig.SchemeType {
	case SchemeTypeOAuth2:
		if authConfig.OAuth2 == nil {
			return nil, errors.New("oauth2 config is required for OAuth2 scheme")
		}
		if authConfig.OAuth2.ClientID == "" {
			return nil, errors.New("client_id is required for OAuth2 scheme")
		}
		if authConfig.OAuth2.TokenURL == "" {
			return nil, errors.New("token_url is required for OAuth2 scheme")
		}
	case SchemeTypeAPIKey:
		if authConfig.APIKey == nil {
			return nil, errors.New("api_key config is required for API key scheme")
		}
		if authConfig.APIKey.Name == "" {
			return nil, errors.New("name is required for API key scheme")
		}
	case SchemeTypeBasic:
		if authConfig.BasicAuth == nil {
			return nil, errors.New("basic_auth config is required for basic auth scheme")
		}
	case SchemeTypeBearer:
		if authConfig.BearerToken == nil {
			return nil, errors.New("bearer_token config is required for bearer token scheme")
		}
	case SchemeTypeNone:
		// No specific config needed
	default:
		return nil, fmt.Errorf("unsupported scheme type: %s", authConfig.SchemeType)
	}

	// Call the callback if provided
	if callback != nil {
		if err := callback(ctx, "auth_config_processed", map[string]any{
			"auth_config": authConfig,
		}); err != nil {
			return nil, err
		}
	}

	return &authConfig, nil
}

// CreateAuthHandler creates an auth handler from an auth config.
func CreateAuthHandler(authConfig *types.AuthConfig, logger *slog.Logger) (*Handler, error) {
	// Create the auth config
	config := NewConfig(
		WithSchemeType(authConfig.SchemeType),
		WithLogger(logger),
	)

	// Configure based on scheme type
	switch authConfig.SchemeType {
	case SchemeTypeOAuth2:
		config = NewConfig(
			WithSchemeType(SchemeTypeOAuth2),
			WithOAuth2Credentials(
				authConfig.OAuth2.ClientID,
				authConfig.OAuth2.ClientSecret,
			),
			WithOAuth2URLs(
				authConfig.OAuth2.AuthURL,
				authConfig.OAuth2.TokenURL,
				authConfig.OAuth2.RedirectURL,
			),
			WithOAuth2Scopes(authConfig.OAuth2.Scopes),
			WithLogger(logger),
		)
	case SchemeTypeAPIKey:
		config = NewConfig(
			WithSchemeType(SchemeTypeAPIKey),
			WithSchemeConfig(map[string]string{
				"location": authConfig.APIKey.Location,
				"name":     authConfig.APIKey.Name,
			}),
			WithLogger(logger),
		)
	case SchemeTypeBasic:
		config = NewConfig(
			WithSchemeType(SchemeTypeBasic),
			WithSchemeConfig(map[string]string{
				"username": authConfig.BasicAuth.Username,
				"password": authConfig.BasicAuth.Password,
			}),
			WithLogger(logger),
		)
	case SchemeTypeBearer:
		config = NewConfig(
			WithSchemeType(SchemeTypeBearer),
			WithSchemeConfig(map[string]string{
				"token": authConfig.BearerToken.Token,
			}),
			WithLogger(logger),
		)
	case SchemeTypeNone:
		// No specific config needed
	}

	// Create the auth service
	service, err := CreateAuthService(config)
	if err != nil {
		return nil, err
	}

	// Create the auth handler
	handler := NewHandler(config, WithAuthServices(service))

	return handler, nil
}
