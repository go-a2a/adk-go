// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package contentcaching

import (
	"time"

	"google.golang.org/genai"
)

// CacheState represents the state of a cached content entry.
type CacheState string

const (
	// CacheStateUnspecified indicates the cache state is not specified.
	CacheStateUnspecified CacheState = "CACHE_STATE_UNSPECIFIED"

	// CacheStateActive indicates the cache is active and usable.
	CacheStateActive CacheState = "ACTIVE"

	// CacheStateExpired indicates the cache has expired.
	CacheStateExpired CacheState = "EXPIRED"

	// CacheStateError indicates the cache is in an error state.
	CacheStateError CacheState = "ERROR"
)

// CachedContent represents a cached content entry in Vertex AI.
//
// CachedContent allows models to reuse previously processed content,
// reducing token usage and improving performance for large content scenarios.
type CachedContent struct {
	// Name is the resource name of the cached content.
	// Format: projects/{project}/locations/{location}/cachedContents/{cached_content}
	Name string `json:"name,omitempty"`

	// DisplayName is the user-provided display name for the cached content.
	DisplayName string `json:"display_name,omitempty"`

	// Model is the name of the model for which this content is cached.
	// Must be a model that supports content caching (e.g., "gemini-2.0-flash-001").
	Model string `json:"model,omitempty"`

	// SystemInstruction is the system instruction for the cached content.
	SystemInstruction *genai.Content `json:"system_instruction,omitempty"`

	// Contents are the content pieces that are cached.
	Contents []*genai.Content `json:"contents,omitempty"`

	// Tools are the tools available to the model when using this cached content.
	Tools []*genai.Tool `json:"tools,omitempty"`

	// ToolConfig is the tool configuration for the cached content.
	ToolConfig *genai.ToolConfig `json:"tool_config,omitempty"`

	// CreateTime is the timestamp when the cached content was created.
	CreateTime time.Time `json:"create_time,omitempty"`

	// UpdateTime is the timestamp when the cached content was last updated.
	UpdateTime time.Time `json:"update_time,omitempty"`

	// ExpireTime is the timestamp when the cached content will expire.
	ExpireTime time.Time `json:"expire_time,omitempty"`

	// State is the current state of the cached content.
	State CacheState `json:"state,omitempty"`

	// UsageMetadata contains usage statistics for the cached content.
	UsageMetadata *CacheUsageMetadata `json:"usage_metadata,omitempty"`
}

// CacheUsageMetadata contains usage statistics for cached content.
type CacheUsageMetadata struct {
	// TotalTokenCount is the total number of tokens in the cached content.
	TotalTokenCount int32 `json:"total_token_count,omitempty"`

	// VideoDurationSeconds is the duration of video content in seconds (if applicable).
	VideoDurationSeconds float64 `json:"video_duration_seconds,omitempty"`

	// AudioDurationSeconds is the duration of audio content in seconds (if applicable).
	AudioDurationSeconds float64 `json:"audio_duration_seconds,omitempty"`
}

// CacheConfig contains configuration options for creating cached content.
type CacheConfig struct {
	// DisplayName is the user-provided display name for the cached content.
	DisplayName string `json:"display_name,omitempty"`

	// Model is the name of the model for which to cache content.
	// Must be a model that supports content caching.
	Model string `json:"model,omitempty"`

	// TTL is the time-to-live for the cached content.
	// The cached content will expire after this duration.
	TTL time.Duration `json:"ttl,omitempty"`

	// SystemInstruction is the system instruction to cache along with the content.
	SystemInstruction *genai.Content `json:"system_instruction,omitempty"`

	// Tools are the tools to cache along with the content.
	Tools []*genai.Tool `json:"tools,omitempty"`

	// ToolConfig is the tool configuration to cache along with the content.
	ToolConfig *genai.ToolConfig `json:"tool_config,omitempty"`
}

// CreateCacheRequest represents a request to create cached content.
type CreateCacheRequest struct {
	// Parent is the parent resource where the cached content will be created.
	// Format: projects/{project}/locations/{location}
	Parent string `json:"parent,omitempty"`

	// CachedContent is the cached content to create.
	CachedContent *CachedContent `json:"cached_content,omitempty"`
}

// GetCacheRequest represents a request to get cached content.
type GetCacheRequest struct {
	// Name is the resource name of the cached content to retrieve.
	// Format: projects/{project}/locations/{location}/cachedContents/{cached_content}
	Name string `json:"name,omitempty"`
}

// ListCacheRequest represents a request to list cached content.
type ListCacheRequest struct {
	// Parent is the parent resource to list cached content from.
	// Format: projects/{project}/locations/{location}
	Parent string `json:"parent,omitempty"`

	// PageSize is the maximum number of cached content entries to return.
	PageSize int32 `json:"page_size,omitempty"`

	// PageToken is the token for retrieving the next page of results.
	PageToken string `json:"page_token,omitempty"`
}

// ListCacheResponse represents a response containing cached content entries.
type ListCacheResponse struct {
	// CachedContents are the cached content entries.
	CachedContents []*CachedContent `json:"cached_contents,omitempty"`

	// NextPageToken is the token for retrieving the next page of results.
	NextPageToken string `json:"next_page_token,omitempty"`
}

// UpdateCacheRequest represents a request to update cached content.
type UpdateCacheRequest struct {
	// CachedContent is the cached content to update.
	CachedContent *CachedContent `json:"cached_content,omitempty"`

	// UpdateMask specifies the fields to update.
	UpdateMask []string `json:"update_mask,omitempty"`
}

// DeleteCacheRequest represents a request to delete cached content.
type DeleteCacheRequest struct {
	// Name is the resource name of the cached content to delete.
	// Format: projects/{project}/locations/{location}/cachedContents/{cached_content}
	Name string `json:"name,omitempty"`
}

// ListCacheOptions provides options for listing cached content.
type ListCacheOptions struct {
	// PageSize is the maximum number of cached content entries to return per page.
	PageSize int32 `json:"page_size,omitempty"`

	// PageToken is the token for retrieving a specific page of results.
	PageToken string `json:"page_token,omitempty"`

	// Filter is an optional filter expression for cached content.
	Filter string `json:"filter,omitempty"`

	// OrderBy is an optional field for ordering the results.
	OrderBy string `json:"order_by,omitempty"`
}

// Supported models for content caching.
const (
	// ModelGemini20Flash001 is the Gemini 2.0 Flash model with content caching support.
	ModelGemini20Flash001 = "gemini-2.0-flash-001"

	// ModelGemini20Pro001 is the Gemini 2.0 Pro model with content caching support.
	ModelGemini20Pro001 = "gemini-2.0-pro-001"
)

// IsSupportedModel checks if a model supports content caching.
func IsSupportedModel(modelName string) bool {
	switch modelName {
	case ModelGemini20Flash001, ModelGemini20Pro001:
		return true
	default:
		return false
	}
}

// GetSupportedModels returns a list of all models that support content caching.
func GetSupportedModels() []string {
	return []string{
		ModelGemini20Flash001,
		ModelGemini20Pro001,
	}
}
