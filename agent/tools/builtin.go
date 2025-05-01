// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-a2a/adk-go/internal/jsonschema"
)

// NewHttpTool creates a new HTTP tool for making web requests.
func NewHttpTool() Tool {
	inputSchema := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"url": {
				Type:        "string",
				Description: "The URL to request",
			},
			"method": {
				Type:        "string",
				Description: "The HTTP method to use",
				Enum:        []any{"GET", "POST", "PUT", "DELETE", "PATCH"},
				Default:     "GET",
			},
			"headers": {
				Type:        "object",
				Description: "HTTP headers to include in the request",
				AdditionalProperties: &jsonschema.Schema{
					Type: "string",
				},
			},
			"body": {
				Type:        "string",
				Description: "The request body for POST/PUT/PATCH requests",
			},
			"timeout": {
				Type:        "number",
				Description: "Request timeout in seconds",
				Default:     30.0,
			},
		},
		Required: []string{"url"},
	}

	outputSchema := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"status": {
				Type:        "number",
				Description: "HTTP status code",
			},
			"headers": {
				Type:        "object",
				Description: "Response headers",
				AdditionalProperties: &jsonschema.Schema{
					Type: "string",
				},
			},
			"body": {
				Type:        "string",
				Description: "Response body",
			},
			"error": {
				Type:        "string",
				Description: "Error message, if any",
			},
		},
		Required: []string{"status"},
	}

	executeFn := func(ctx context.Context, params map[string]any) (any, error) {
		url, _ := params["url"].(string)
		method, _ := params["method"].(string)
		if method == "" {
			method = "GET"
		}

		headers, _ := params["headers"].(map[string]any)
		body, _ := params["body"].(string)
		timeout, _ := params["timeout"].(float64)
		if timeout == 0 {
			timeout = 30
		}

		client := &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		}

		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return map[string]any{
				"status": 0,
				"error":  err.Error(),
			}, nil
		}

		if body != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
			req.Body = ioutil.NopCloser(strings.NewReader(body))
		}

		for k, v := range headers {
			if strVal, ok := v.(string); ok {
				req.Header.Set(k, strVal)
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			return map[string]any{
				"status": 0,
				"error":  err.Error(),
			}, nil
		}
		defer resp.Body.Close()

		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return map[string]any{
				"status": resp.StatusCode,
				"error":  fmt.Sprintf("Error reading response body: %v", err),
			}, nil
		}

		respHeaders := make(map[string]any)
		for k, v := range resp.Header {
			if len(v) > 0 {
				respHeaders[k] = v[0]
			}
		}

		return map[string]any{
			"status":  resp.StatusCode,
			"headers": respHeaders,
			"body":    string(respBody),
		}, nil
	}

	return NewBaseTool(
		WithName("http_request"),
		WithDescription("Make HTTP requests to external services"),
		WithInputSchema(inputSchema),
		WithOutputSchema(outputSchema),
		WithExecuteFunc(executeFn),
	)
}

// NewFileTool creates a new tool for file operations.
func NewFileTool() Tool {
	inputSchema := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"operation": {
				Type:        "string",
				Description: "The file operation to perform",
				Enum:        []any{"read", "write", "append", "list", "exists", "delete"},
			},
			"path": {
				Type:        "string",
				Description: "The file or directory path",
			},
			"content": {
				Type:        "string",
				Description: "The content to write (for write/append operations)",
			},
		},
		Required: []string{"operation", "path"},
	}

	outputSchema := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"success": {
				Type:        "boolean",
				Description: "Whether the operation was successful",
			},
			"content": {
				Type:        "string",
				Description: "File content (for read operations) or directory listing (for list operations)",
			},
			"exists": {
				Type:        "boolean",
				Description: "Whether the file exists (for exists operations)",
			},
			"error": {
				Type:        "string",
				Description: "Error message, if any",
			},
		},
		Required: []string{"success"},
	}

	executeFn := func(ctx context.Context, params map[string]any) (any, error) {
		operation, _ := params["operation"].(string)
		path, _ := params["path"].(string)
		content, _ := params["content"].(string)

		switch operation {
		case "read":
			data, err := os.ReadFile(path)
			if err != nil {
				return map[string]any{
					"success": false,
					"error":   err.Error(),
				}, nil
			}
			return map[string]any{
				"success": true,
				"content": string(data),
			}, nil

		case "write":
			err := os.WriteFile(path, []byte(content), 0644)
			if err != nil {
				return map[string]any{
					"success": false,
					"error":   err.Error(),
				}, nil
			}
			return map[string]any{
				"success": true,
			}, nil

		case "append":
			f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return map[string]any{
					"success": false,
					"error":   err.Error(),
				}, nil
			}
			defer f.Close()
			if _, err := f.WriteString(content); err != nil {
				return map[string]any{
					"success": false,
					"error":   err.Error(),
				}, nil
			}
			return map[string]any{
				"success": true,
			}, nil

		case "list":
			files, err := os.ReadDir(path)
			if err != nil {
				return map[string]any{
					"success": false,
					"error":   err.Error(),
				}, nil
			}
			fileNames := make([]string, 0, len(files))
			for _, file := range files {
				fileNames = append(fileNames, file.Name())
			}
			return map[string]any{
				"success": true,
				"content": strings.Join(fileNames, "\n"),
			}, nil

		case "exists":
			_, err := os.Stat(path)
			exists := !os.IsNotExist(err)
			return map[string]any{
				"success": true,
				"exists":  exists,
			}, nil

		case "delete":
			err := os.Remove(path)
			if err != nil {
				return map[string]any{
					"success": false,
					"error":   err.Error(),
				}, nil
			}
			return map[string]any{
				"success": true,
			}, nil

		default:
			return map[string]any{
				"success": false,
				"error":   fmt.Sprintf("Unknown operation: %s", operation),
			}, nil
		}
	}

	return NewBaseTool(
		WithName("file"),
		WithDescription("Perform file operations like reading, writing, and listing directories"),
		WithInputSchema(inputSchema),
		WithOutputSchema(outputSchema),
		WithExecuteFunc(executeFn),
	)
}

// NewDateTimeTool creates a tool for date and time operations.
func NewDateTimeTool() Tool {
	inputSchema := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"format": {
				Type:        "string",
				Description: "Output format (RFC3339, ISO8601, UNIX, or custom Go time format)",
				Default:     "RFC3339",
			},
			"timezone": {
				Type:        "string",
				Description: "Timezone to use (default is UTC)",
				Default:     "UTC",
			},
		},
	}

	outputSchema := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"now": {
				Type:        "string",
				Description: "Current time in the requested format",
			},
			"unix": {
				Type:        "number",
				Description: "Current time as UNIX timestamp",
			},
			"day": {
				Type:        "number",
				Description: "Current day of the month",
			},
			"month": {
				Type:        "number",
				Description: "Current month",
			},
			"year": {
				Type:        "number",
				Description: "Current year",
			},
			"hour": {
				Type:        "number",
				Description: "Current hour",
			},
			"minute": {
				Type:        "number",
				Description: "Current minute",
			},
			"second": {
				Type:        "number",
				Description: "Current second",
			},
			"weekday": {
				Type:        "string",
				Description: "Current day of the week",
			},
		},
		Required: []string{"now", "unix"},
	}

	executeFn := func(ctx context.Context, params map[string]any) (any, error) {
		format, _ := params["format"].(string)
		if format == "" {
			format = "RFC3339"
		}

		timezone, _ := params["timezone"].(string)
		if timezone == "" {
			timezone = "UTC"
		}

		loc, err := time.LoadLocation(timezone)
		if err != nil {
			loc = time.UTC
		}

		now := time.Now().In(loc)

		var formattedTime string
		switch format {
		case "RFC3339":
			formattedTime = now.Format(time.RFC3339)
		case "ISO8601":
			formattedTime = now.Format("2006-01-02T15:04:05Z07:00")
		case "UNIX":
			formattedTime = fmt.Sprintf("%d", now.Unix())
		default:
			formattedTime = now.Format(format)
		}

		return map[string]any{
			"now":     formattedTime,
			"unix":    now.Unix(),
			"day":     now.Day(),
			"month":   int(now.Month()),
			"year":    now.Year(),
			"hour":    now.Hour(),
			"minute":  now.Minute(),
			"second":  now.Second(),
			"weekday": now.Weekday().String(),
		}, nil
	}

	return NewBaseTool(
		WithName("datetime"),
		WithDescription("Get current date and time information"),
		WithInputSchema(inputSchema),
		WithOutputSchema(outputSchema),
		WithExecuteFunc(executeFn),
	)
}

