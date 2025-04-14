// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/observability"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// OpenAPIParams contains parameters for an OpenAPI operation.
type OpenAPIParams struct {
	URL     string          `json:"url"`
	Method  string          `json:"method"`
	Path    string          `json:"path"`
	Headers json.RawMessage `json:"headers,omitempty"`
	Query   json.RawMessage `json:"query,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
}

// NewOpenAPITool creates a new OpenAPI tool that can interact with REST APIs.
func NewOpenAPITool() *tool.BaseTool {
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "The base URL of the API",
			},
			"method": map[string]any{
				"type":        "string",
				"description": "HTTP method (GET, POST, PUT, DELETE, etc.)",
				"enum":        []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
			},
			"path": map[string]any{
				"type":        "string",
				"description": "API endpoint path to append to the base URL",
			},
			"headers": map[string]any{
				"type":        "object",
				"description": "HTTP headers to include with the request",
			},
			"query": map[string]any{
				"type":        "object",
				"description": "Query parameters to include with the request",
			},
			"body": map[string]any{
				"type":        "object",
				"description": "Request body (for POST, PUT, PATCH requests)",
			},
		},
		"required": []string{"url", "method", "path"},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		// Parse parameters
		var params OpenAPIParams
		if err := json.Unmarshal(args, &params); err != nil {
			return "", fmt.Errorf("failed to parse OpenAPI parameters: %w", err)
		}

		// Validate parameters
		if params.URL == "" || params.Method == "" || params.Path == "" {
			return "", fmt.Errorf("url, method, and path are required")
		}

		// Normalize method to uppercase
		params.Method = strings.ToUpper(params.Method)

		// Validate method
		validMethods := map[string]bool{
			"GET":    true,
			"POST":   true,
			"PUT":    true,
			"DELETE": true,
			"PATCH":  true,
		}
		if !validMethods[params.Method] {
			return "", fmt.Errorf("invalid HTTP method: %s", params.Method)
		}

		// Construct full URL (ensure proper joining of URL and path)
		fullURL := params.URL
		if !strings.HasSuffix(params.URL, "/") && !strings.HasPrefix(params.Path, "/") {
			fullURL += "/"
		} else if strings.HasSuffix(params.URL, "/") && strings.HasPrefix(params.Path, "/") {
			fullURL = fullURL[:len(fullURL)-1]
		}
		fullURL += params.Path

		// Create request with query parameters if provided
		var reqBody io.Reader
		if params.Body != nil && (params.Method == "POST" || params.Method == "PUT" || params.Method == "PATCH") {
			reqBody = bytes.NewBuffer(params.Body)
		}

		// Create HTTP request
		req, err := http.NewRequestWithContext(ctx, params.Method, fullURL, reqBody)
		if err != nil {
			return "", fmt.Errorf("failed to create HTTP request: %w", err)
		}

		// Add headers
		if params.Headers != nil {
			var headers map[string]string
			if err := json.Unmarshal(params.Headers, &headers); err != nil {
				return "", fmt.Errorf("failed to parse headers: %w", err)
			}
			for key, value := range headers {
				req.Header.Set(key, value)
			}
		}

		// Set default Content-Type if not provided and body exists
		if params.Body != nil && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}

		// Add query parameters
		if params.Query != nil {
			var queryParams map[string]string
			if err := json.Unmarshal(params.Query, &queryParams); err != nil {
				return "", fmt.Errorf("failed to parse query parameters: %w", err)
			}
			q := req.URL.Query()
			for key, value := range queryParams {
				q.Add(key, value)
			}
			req.URL.RawQuery = q.Encode()
		}

		// Execute request
		client := &http.Client{
			Timeout: 30 * time.Second,
		}

		logger := observability.Logger(ctx)
		logger.Debug("Sending OpenAPI request",
			slog.String("method", params.Method),
			slog.String("url", fullURL),
		)

		startTime := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("API request failed: %w", err)
		}
		defer resp.Body.Close()

		duration := time.Since(startTime)
		logger.Debug("Received OpenAPI response",
			slog.String("method", params.Method),
			slog.String("url", fullURL),
			slog.Int("status", resp.StatusCode),
			slog.Duration("duration", duration),
		)

		// Read response body
		respBodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
		if err != nil {
			return "", fmt.Errorf("failed to read API response: %w", err)
		}

		// Format response
		var respBody any
		if err := json.Unmarshal(respBodyBytes, &respBody); err != nil {
			// Not valid JSON, return as string
			return fmt.Sprintf("Status: %d\nHeaders: %v\nBody: %s", 
				resp.StatusCode, 
				resp.Header, 
				string(respBodyBytes),
			), nil
		}

		// Valid JSON, format it
		prettyJSON, err := json.MarshalIndent(respBody, "", "  ")
		if err != nil {
			return string(respBodyBytes), nil
		}

		return fmt.Sprintf("Status: %d\nHeaders: %v\nBody: %s", 
			resp.StatusCode, 
			resp.Header, 
			string(prettyJSON),
		), nil
	}

	return tool.NewBaseTool(
		"openapi",
		"Makes HTTP requests to OpenAPI/REST endpoints. Use this to interact with REST APIs.",
		paramSchema,
		executeFn,
	)
}