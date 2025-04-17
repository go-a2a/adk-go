// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"go.opentelemetry.io/otel/attribute"

	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/observability"
	"github.com/go-a2a/adk-go/tool"
)

// WebPageParams defines the parameters for loading a web page.
type WebPageParams struct {
	URL     string `json:"url"`
	Timeout int    `json:"timeout,omitempty"` // Timeout in seconds
}

// cacheEntry represents a cached web page.
type cacheEntry struct {
	content   string
	timestamp time.Time
}

// webPageCache provides a simple cache for web pages.
type webPageCache struct {
	mu       sync.RWMutex
	entries  map[string]cacheEntry
	ttl      time.Duration // Time to live for cache entries
	maxSize  int           // Maximum number of entries in the cache
	capacity int           // Maximum size in bytes of all cached content
	size     int           // Current size in bytes of all cached content
}

// newWebPageCache creates a new web page cache.
func newWebPageCache(ttl time.Duration, maxSize int, capacity int) *webPageCache {
	return &webPageCache{
		entries:  make(map[string]cacheEntry),
		ttl:      ttl,
		maxSize:  maxSize,
		capacity: capacity,
	}
}

// Get retrieves a value from the cache.
func (c *webPageCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return "", false
	}

	// Check if entry is expired
	if time.Since(entry.timestamp) > c.ttl {
		return "", false
	}

	return entry.content, true
}

// Set adds a value to the cache.
func (c *webPageCache) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	valueSize := len(value)

	// Check if adding this item would exceed capacity
	if c.size+valueSize > c.capacity {
		c.evict(valueSize)
	}

	// If we still can't fit it, don't cache
	if valueSize > c.capacity {
		return
	}

	// Remove old entry if exists
	if oldEntry, exists := c.entries[key]; exists {
		c.size -= len(oldEntry.content)
	}

	// Add new entry
	c.entries[key] = cacheEntry{
		content:   value,
		timestamp: time.Now(),
	}
	c.size += valueSize

	// If we have too many entries, evict the oldest
	if len(c.entries) > c.maxSize {
		c.evictOldest()
	}
}

// evict removes entries to make room for the specified size.
func (c *webPageCache) evict(sizeNeeded int) {
	// Sort entries by timestamp
	type keyTimestamp struct {
		key       string
		timestamp time.Time
	}

	entries := make([]keyTimestamp, 0, len(c.entries))
	for k, v := range c.entries {
		entries = append(entries, keyTimestamp{k, v.timestamp})
	}

	// Sort by timestamp (oldest first)
	for i := 0; i < len(entries) && c.size+sizeNeeded > c.capacity; i++ {
		key := entries[i].key
		c.size -= len(c.entries[key].content)
		delete(c.entries, key)
	}
}

// evictOldest removes the oldest entry.
func (c *webPageCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	// Find the oldest entry
	first := true
	for k, v := range c.entries {
		if first || v.timestamp.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.timestamp
			first = false
		}
	}

	// Remove it
	if oldestKey != "" {
		c.size -= len(c.entries[oldestKey].content)
		delete(c.entries, oldestKey)
	}
}

// clean removes expired entries.
func (c *webPageCache) clean() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, v := range c.entries {
		if now.Sub(v.timestamp) > c.ttl {
			c.size -= len(v.content)
			delete(c.entries, k)
		}
	}
}

// Global cache for web pages
var globalWebPageCache = newWebPageCache(15*time.Minute, 100, 10*1024*1024) // 15 min TTL, 100 entries, 10MB capacity

// Start a background goroutine to clean expired entries
func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			globalWebPageCache.clean()
		}
	}()
}

// NewLoadWebPageTool creates a new tool for loading web pages.
func NewLoadWebPageTool() *tool.BaseTool {
	// Define parameter schema in JSON Schema format
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "The URL to fetch",
			},
			"timeout": map[string]any{
				"type":        "integer",
				"description": "Timeout in seconds (default: 30)",
				"default":     30,
			},
		},
		"required": []string{"url"},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		// Start span for load_web_page
		ctx, span := observability.StartSpan(ctx, "tool.load_web_page")
		defer span.End()

		// Parse the arguments
		var params WebPageParams
		if err := sonic.ConfigFastest.Unmarshal(args, &params); err != nil {
			observability.Error(ctx, err, "Failed to parse web page parameters")
			return "", fmt.Errorf("failed to parse web page parameters: %w", err)
		}

		// Add URL to span attributes
		span.SetAttributes(attribute.String("url", params.URL))

		logger := observability.Logger(ctx)
		logger.Debug("Loading web page", slog.String("url", params.URL))

		// Validate URL
		parsedURL, err := url.Parse(params.URL)
		if err != nil {
			observability.Error(ctx, err, "invalid URL", slog.String("url", params.URL))
			return "", fmt.Errorf("invalid URL: %w", err)
		}

		// Only allow HTTP and HTTPS URLs
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			err := fmt.Errorf("only HTTP and HTTPS URLs are supported")
			observability.Error(ctx, err, "Unsupported URL scheme",
				slog.String("url", params.URL),
				slog.String("scheme", parsedURL.Scheme),
			)
			return "", err
		}

		// Check cache first
		if content, found := globalWebPageCache.Get(params.URL); found {
			logger.Debug("Retrieved web page from cache",
				slog.String("url", params.URL),
				slog.Int("content_length", len(content)),
			)

			span.SetAttributes(
				attribute.Bool("cache_hit", true),
				attribute.Int("content_length", len(content)),
			)

			observability.RecordLatency(ctx, 0*time.Millisecond,
				attribute.String("tool", "load_web_page"),
				attribute.Bool("cache_hit", true),
			)

			return content, nil
		}

		// Set timeout
		timeout := 30
		if params.Timeout > 0 && params.Timeout <= 120 {
			timeout = params.Timeout
		}
		span.SetAttributes(attribute.Int("timeout", timeout))

		// Create HTTP client with timeout
		client := &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		}

		// Start time for measuring request duration
		startTime := time.Now()

		// Create a new request
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, params.URL, nil)
		if err != nil {
			observability.Error(ctx, err, "Failed to create HTTP request", slog.String("url", params.URL))
			return "", fmt.Errorf("failed to create HTTP request: %w", err)
		}

		// Set a user agent
		req.Header.Set("User-Agent", "ADK-Go Web Page Tool/1.0")

		// Send the request
		resp, err := client.Do(req)
		if err != nil {
			observability.Error(ctx, err, "Failed to fetch URL", slog.String("url", params.URL))
			return "", fmt.Errorf("failed to fetch URL: %w", err)
		}
		defer resp.Body.Close()

		// Record time taken
		duration := time.Since(startTime)
		span.SetAttributes(
			attribute.Int64("duration_ms", duration.Milliseconds()),
			attribute.Int("status_code", resp.StatusCode),
		)

		observability.RecordLatency(ctx, duration,
			attribute.String("tool", "load_web_page"),
			attribute.Bool("cache_hit", false),
			attribute.Int("status_code", resp.StatusCode),
		)

		// Check if the response was successful
		if resp.StatusCode != http.StatusOK {
			err := fmt.Errorf("server returned status code %d", resp.StatusCode)
			observability.Error(ctx, err, "HTTP request failed",
				slog.String("url", params.URL),
				slog.Int("status_code", resp.StatusCode),
			)
			return "", err
		}

		// Read the response body with a maximum size limit
		maxSize := 5 * 1024 * 1024 // 5MB
		limitedReader := io.LimitReader(resp.Body, int64(maxSize))
		body, err := io.ReadAll(limitedReader)
		if err != nil {
			observability.Error(ctx, err, "Failed to read response body", slog.String("url", params.URL))
			return "", fmt.Errorf("failed to read response body: %w", err)
		}

		span.SetAttributes(attribute.Int("content_length", len(body)))

		// Process content based on content type
		contentType := resp.Header.Get("Content-Type")
		span.SetAttributes(attribute.String("content_type", contentType))

		var result string

		// Simple HTML processing - in a real implementation, you would use a proper HTML parser
		if strings.Contains(contentType, "text/html") {
			// Extract title
			title := extractTitle(string(body))

			// Create a simple summary
			result = fmt.Sprintf("Fetched web page from %s\n\nTitle: %s\n\nContent Type: %s\nSize: %d bytes\nFetch Time: %d ms\n\nContent Preview:\n%.2000s...",
				params.URL,
				title,
				contentType,
				len(body),
				duration.Milliseconds(),
				string(body),
			)
		} else {
			// For non-HTML content
			result = fmt.Sprintf("Fetched content from %s\n\nContent Type: %s\nSize: %d bytes\nFetch Time: %d ms\n\nContent Preview:\n%.2000s...",
				params.URL,
				contentType,
				len(body),
				duration.Milliseconds(),
				string(body),
			)
		}

		// Cache the result
		globalWebPageCache.Set(params.URL, result)

		logger.Debug("Web page loaded successfully",
			slog.String("url", params.URL),
			slog.String("content_type", contentType),
			slog.Int("content_length", len(body)),
			slog.Duration("duration", duration),
		)

		return result, nil
	}

	return tool.NewBaseTool(
		"load_web_page",
		"Loads content from a web page. Use this when you need to retrieve information from a specific website.",
		paramSchema,
		executeFn,
	)
}

// extractTitle attempts to extract the title from HTML content.
func extractTitle(html string) string {
	titleStart := strings.Index(strings.ToLower(html), "<title>")
	if titleStart == -1 {
		return "No title found"
	}

	titleStart += 7 // Length of "<title>"
	titleEnd := strings.Index(strings.ToLower(html[titleStart:]), "</title>")
	if titleEnd == -1 {
		return "Incomplete title"
	}

	return strings.TrimSpace(html[titleStart : titleStart+titleEnd])
}
