// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package examplestore

import (
	"fmt"
	"time"
)

// StoreState represents the state of an Example Store.
type StoreState string

const (
	StoreStateUnspecified StoreState = "STORE_STATE_UNSPECIFIED"
	StoreStateActive      StoreState = "ACTIVE"
	StoreStateCreating    StoreState = "CREATING"
	StoreStateError       StoreState = "ERROR"
	StoreStateDeleting    StoreState = "DELETING"
)

// ExampleState represents the state of an example within a store.
type ExampleState string

const (
	ExampleStateUnspecified ExampleState = "EXAMPLE_STATE_UNSPECIFIED"
	ExampleStateActive      ExampleState = "ACTIVE"
	ExampleStateProcessing  ExampleState = "PROCESSING"
	ExampleStateError       ExampleState = "ERROR"
)

// StoreConfig represents the configuration for an Example Store.
type StoreConfig struct {
	// EmbeddingModel is the embedding model used to determine example relevance.
	// Examples: "text-embedding-005", "text-multilingual-embedding-002"
	EmbeddingModel string `json:"embedding_model,omitempty"`

	// DisplayName is the human-readable display name of the store.
	DisplayName string `json:"display_name,omitempty"`

	// Description is the description of the store.
	Description string `json:"description,omitempty"`
}

// Store represents an Example Store instance.
type Store struct {
	// Name is the resource name of the store.
	// Format: projects/{project}/locations/{location}/exampleStores/{example_store}
	Name string `json:"name,omitempty"`

	// DisplayName is the human-readable display name of the store.
	DisplayName string `json:"display_name,omitempty"`

	// Description is the description of the store.
	Description string `json:"description,omitempty"`

	// Config is the configuration of the store.
	Config *StoreConfig `json:"config,omitempty"`

	// CreateTime is the timestamp when the store was created.
	CreateTime *time.Time `json:"create_time,omitempty"`

	// UpdateTime is the timestamp when the store was last updated.
	UpdateTime *time.Time `json:"update_time,omitempty"`

	// State is the current state of the store.
	State StoreState `json:"state,omitempty"`

	// ExampleCount is the number of examples in the store.
	ExampleCount int64 `json:"example_count,omitempty"`
}

// Content represents input or output content for an example.
type Content struct {
	// Text is the text content.
	Text string `json:"text,omitempty"`

	// Metadata contains additional metadata about the content.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Example represents an example with input and output content.
type Example struct {
	// Input is the input content for the example.
	Input *Content `json:"input,omitempty"`

	// Output is the output content for the example.
	Output *Content `json:"output,omitempty"`

	// DisplayName is the human-readable display name of the example.
	DisplayName string `json:"display_name,omitempty"`

	// Metadata contains additional metadata about the example.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// StoredExample represents an example that has been stored in an Example Store.
type StoredExample struct {
	// Name is the resource name of the example.
	// Format: projects/{project}/locations/{location}/exampleStores/{example_store}/examples/{example}
	Name string `json:"name,omitempty"`

	// DisplayName is the human-readable display name of the example.
	DisplayName string `json:"display_name,omitempty"`

	// Input is the input content for the example.
	Input *Content `json:"input,omitempty"`

	// Output is the output content for the example.
	Output *Content `json:"output,omitempty"`

	// Metadata contains additional metadata about the example.
	Metadata map[string]any `json:"metadata,omitempty"`

	// CreateTime is the timestamp when the example was created.
	CreateTime *time.Time `json:"create_time,omitempty"`

	// UpdateTime is the timestamp when the example was last updated.
	UpdateTime *time.Time `json:"update_time,omitempty"`

	// State is the current state of the example.
	State ExampleState `json:"state,omitempty"`

	// EmbeddingVector is the embedding vector for the example (internal use).
	EmbeddingVector []float32 `json:"embedding_vector,omitempty"`
}

// SearchQuery represents a query for searching examples.
type SearchQuery struct {
	// Text is the query text.
	Text string `json:"text,omitempty"`

	// TopK is the number of top similar examples to retrieve.
	TopK int32 `json:"top_k,omitempty"`

	// SimilarityThreshold is the minimum similarity threshold.
	SimilarityThreshold float64 `json:"similarity_threshold,omitempty"`

	// Metadata filters for examples.
	MetadataFilters map[string]any `json:"metadata_filters,omitempty"`
}

// SearchResult represents a search result containing a relevant example.
type SearchResult struct {
	// Example is the retrieved example.
	Example *StoredExample `json:"example,omitempty"`

	// SimilarityScore is the similarity score between query and example.
	SimilarityScore float64 `json:"similarity_score,omitempty"`

	// Distance is the vector distance (lower means more similar).
	Distance float64 `json:"distance,omitempty"`
}

// SearchResponse represents the response from a search query.
type SearchResponse struct {
	// Results are the search results.
	Results []*SearchResult `json:"results,omitempty"`

	// QueryEmbedding is the embedding vector for the query (internal use).
	QueryEmbedding []float32 `json:"query_embedding,omitempty"`
}

// CreateStoreRequest represents a request to create an Example Store.
type CreateStoreRequest struct {
	// Parent is the parent resource name.
	// Format: projects/{project}/locations/{location}
	Parent string `json:"parent,omitempty"`

	// Store is the store to create.
	Store *Store `json:"store,omitempty"`

	// StoreId is the ID to use for the store.
	StoreId string `json:"store_id,omitempty"`
}

// ListStoresRequest represents a request to list Example Stores.
type ListStoresRequest struct {
	// Parent is the parent resource name.
	// Format: projects/{project}/locations/{location}
	Parent string `json:"parent,omitempty"`

	// PageSize is the maximum number of stores to return.
	PageSize int32 `json:"page_size,omitempty"`

	// PageToken is the token for pagination.
	PageToken string `json:"page_token,omitempty"`

	// Filter is the filter expression for stores.
	Filter string `json:"filter,omitempty"`
}

// ListStoresResponse represents the response from listing stores.
type ListStoresResponse struct {
	// Stores are the Example Stores.
	Stores []*Store `json:"stores,omitempty"`

	// NextPageToken is the token for the next page.
	NextPageToken string `json:"next_page_token,omitempty"`
}

// GetStoreRequest represents a request to get an Example Store.
type GetStoreRequest struct {
	// Name is the resource name of the store.
	// Format: projects/{project}/locations/{location}/exampleStores/{example_store}
	Name string `json:"name,omitempty"`
}

// DeleteStoreRequest represents a request to delete an Example Store.
type DeleteStoreRequest struct {
	// Name is the resource name of the store.
	// Format: projects/{project}/locations/{location}/exampleStores/{example_store}
	Name string `json:"name,omitempty"`

	// Force indicates whether to forcefully delete the store.
	Force bool `json:"force,omitempty"`
}

// UploadExamplesRequest represents a request to upload examples to a store.
type UploadExamplesRequest struct {
	// Parent is the parent store name.
	// Format: projects/{project}/locations/{location}/exampleStores/{example_store}
	Parent string `json:"parent,omitempty"`

	// Examples are the examples to upload (maximum 5 per request).
	Examples []*Example `json:"examples,omitempty"`
}

// UploadExamplesResponse represents the response from uploading examples.
type UploadExamplesResponse struct {
	// Examples are the uploaded examples.
	Examples []*StoredExample `json:"examples,omitempty"`
}

// ListExamplesRequest represents a request to list examples in a store.
type ListExamplesRequest struct {
	// Parent is the parent store name.
	// Format: projects/{project}/locations/{location}/exampleStores/{example_store}
	Parent string `json:"parent,omitempty"`

	// PageSize is the maximum number of examples to return.
	PageSize int32 `json:"page_size,omitempty"`

	// PageToken is the token for pagination.
	PageToken string `json:"page_token,omitempty"`

	// Filter is the filter expression for examples.
	Filter string `json:"filter,omitempty"`
}

// ListExamplesResponse represents the response from listing examples.
type ListExamplesResponse struct {
	// Examples are the stored examples.
	Examples []*StoredExample `json:"examples,omitempty"`

	// NextPageToken is the token for the next page.
	NextPageToken string `json:"next_page_token,omitempty"`
}

// DeleteExampleRequest represents a request to delete an example.
type DeleteExampleRequest struct {
	// Name is the resource name of the example.
	// Format: projects/{project}/locations/{location}/exampleStores/{example_store}/examples/{example}
	Name string `json:"name,omitempty"`
}

// SearchExamplesRequest represents a request to search examples.
type SearchExamplesRequest struct {
	// Parent is the parent store name.
	// Format: projects/{project}/locations/{location}/exampleStores/{example_store}
	Parent string `json:"parent,omitempty"`

	// Query is the search query.
	Query *SearchQuery `json:"query,omitempty"`
}

// BatchUploadExamplesRequest represents a request to batch upload examples.
type BatchUploadExamplesRequest struct {
	// Parent is the parent store name.
	// Format: projects/{project}/locations/{location}/exampleStores/{example_store}
	Parent string `json:"parent,omitempty"`

	// Requests are the upload requests (each with max 5 examples).
	Requests []*UploadExamplesRequest `json:"requests,omitempty"`
}

// BatchUploadExamplesResponse represents the response from batch uploading examples.
type BatchUploadExamplesResponse struct {
	// Responses are the upload responses.
	Responses []*UploadExamplesResponse `json:"responses,omitempty"`
}

// BatchDeleteExamplesRequest represents a request to batch delete examples.
type BatchDeleteExamplesRequest struct {
	// Names are the resource names of the examples to delete.
	Names []string `json:"names,omitempty"`
}

// ExampleStoreStats represents statistics about an Example Store.
type ExampleStoreStats struct {
	// TotalExamples is the total number of examples in the store.
	TotalExamples int64 `json:"total_examples,omitempty"`

	// TotalSize is the total size of all examples in bytes.
	TotalSize int64 `json:"total_size,omitempty"`

	// LastExampleUpload is the timestamp of the last example upload.
	LastExampleUpload *time.Time `json:"last_example_upload,omitempty"`

	// AverageInputLength is the average length of input content.
	AverageInputLength float64 `json:"average_input_length,omitempty"`

	// AverageOutputLength is the average length of output content.
	AverageOutputLength float64 `json:"average_output_length,omitempty"`

	// MetadataKeys are the unique metadata keys found in examples.
	MetadataKeys []string `json:"metadata_keys,omitempty"`
}

// Constants for the Example Store service.
const (
	// MaxExamplesPerUpload is the maximum number of examples per upload request.
	MaxExamplesPerUpload = 5

	// MaxStoresPerProject is the maximum number of stores per project/location.
	MaxStoresPerProject = 50

	// SupportedRegion is the currently supported region for Example Stores.
	SupportedRegion = "us-central1"

	// DefaultEmbeddingModel is the default embedding model.
	DefaultEmbeddingModel = "text-embedding-005"

	// DefaultTopK is the default number of results to return in searches.
	DefaultTopK = 10

	// DefaultSimilarityThreshold is the default similarity threshold.
	DefaultSimilarityThreshold = 0.7
)

// EmbeddingModels contains the list of supported embedding models.
var EmbeddingModels = []string{
	"text-embedding-005",
	"text-multilingual-embedding-002",
	"textembedding-gecko",
	"textembedding-gecko-multilingual",
}

// ValidateStoreConfig validates a store configuration.
func (c *StoreConfig) Validate() error {
	if c.EmbeddingModel == "" {
		c.EmbeddingModel = DefaultEmbeddingModel
	}

	// Validate embedding model
	validModel := false
	for _, model := range EmbeddingModels {
		if c.EmbeddingModel == model {
			validModel = true
			break
		}
	}
	if !validModel {
		return fmt.Errorf("unsupported embedding model: %s", c.EmbeddingModel)
	}

	if c.DisplayName == "" {
		return fmt.Errorf("display name is required")
	}

	return nil
}

// ValidateExamples validates a slice of examples for upload.
func ValidateExamples(examples []*Example) error {
	if len(examples) == 0 {
		return fmt.Errorf("at least one example is required")
	}

	if len(examples) > MaxExamplesPerUpload {
		return fmt.Errorf("maximum %d examples per upload, got %d", MaxExamplesPerUpload, len(examples))
	}

	for i, example := range examples {
		if err := example.Validate(); err != nil {
			return fmt.Errorf("example %d: %w", i, err)
		}
	}

	return nil
}

// Validate validates an example.
func (e *Example) Validate() error {
	if e.Input == nil {
		return fmt.Errorf("input is required")
	}

	if e.Input.Text == "" {
		return fmt.Errorf("input text is required")
	}

	if e.Output == nil {
		return fmt.Errorf("output is required")
	}

	if e.Output.Text == "" {
		return fmt.Errorf("output text is required")
	}

	return nil
}

// Validate validates a search query.
func (q *SearchQuery) Validate() error {
	if q.Text == "" {
		return fmt.Errorf("query text is required")
	}

	if q.TopK <= 0 {
		q.TopK = DefaultTopK
	}

	if q.SimilarityThreshold < 0 || q.SimilarityThreshold > 1 {
		q.SimilarityThreshold = DefaultSimilarityThreshold
	}

	return nil
}
