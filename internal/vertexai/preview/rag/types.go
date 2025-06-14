// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package rag

import (
	"time"
)

// CorpusState represents the state of a RAG corpus.
type CorpusState string

const (
	CorpusStateUnspecified CorpusState = "CORPUS_STATE_UNSPECIFIED"
	CorpusStateActive      CorpusState = "ACTIVE"
	CorpusStateError       CorpusState = "ERROR"
)

// FileState represents the state of a RAG file.
type FileState string

const (
	FileStateUnspecified FileState = "FILE_STATE_UNSPECIFIED"
	FileStateActive      FileState = "ACTIVE"
	FileStateError       FileState = "ERROR"
)

// EmbeddingModelConfig represents the configuration for the embedding model.
type EmbeddingModelConfig struct {
	// PublisherModel is the name of the publisher model for embeddings.
	// Example: "publishers/google/models/text-embedding-005"
	PublisherModel string `json:"publisher_model,omitempty"`

	// Endpoint is the custom endpoint for the embedding model.
	Endpoint string `json:"endpoint,omitempty"`

	// Model is the model name when using a custom endpoint.
	Model string `json:"model,omitempty"`
}

// VectorDbConfig represents the configuration for vector database backend.
type VectorDbConfig struct {
	// RagEmbeddingModelConfig is the embedding model configuration.
	RagEmbeddingModelConfig *EmbeddingModelConfig `json:"rag_embedding_model_config,omitempty"`

	// RagManagedDb is the configuration for managed vector database.
	RagManagedDb *RagManagedDbConfig `json:"rag_managed_db,omitempty"`

	// WeaviateConfig is the configuration for Weaviate vector database.
	WeaviateConfig *WeaviateConfig `json:"weaviate_config,omitempty"`

	// PineconeConfig is the configuration for Pinecone vector database.
	PineconeConfig *PineconeConfig `json:"pinecone_config,omitempty"`

	// VertexVectorSearch is the configuration for Vertex Vector Search.
	VertexVectorSearch *VertexVectorSearchConfig `json:"vertex_vector_search,omitempty"`
}

// RagManagedDbConfig represents the configuration for managed RAG database.
type RagManagedDbConfig struct {
	// RetrievalConfig is the configuration for retrieval.
	RetrievalConfig *RetrievalConfig `json:"retrieval_config,omitempty"`
}

// RetrievalConfig represents the configuration for retrieval operations.
type RetrievalConfig struct {
	// TopK is the number of top results to return.
	TopK int32 `json:"top_k,omitempty"`

	// MaxDistance is the maximum distance threshold for similarity.
	MaxDistance float64 `json:"max_distance,omitempty"`
}

// WeaviateConfig represents the configuration for Weaviate vector database.
type WeaviateConfig struct {
	// HttpEndpoint is the HTTP endpoint of the Weaviate instance.
	HttpEndpoint string `json:"http_endpoint,omitempty"`

	// CollectionName is the name of the collection in Weaviate.
	CollectionName string `json:"collection_name,omitempty"`
}

// PineconeConfig represents the configuration for Pinecone vector database.
type PineconeConfig struct {
	// IndexName is the name of the Pinecone index.
	IndexName string `json:"index_name,omitempty"`
}

// VertexVectorSearchConfig represents the configuration for Vertex Vector Search.
type VertexVectorSearchConfig struct {
	// IndexEndpoint is the endpoint of the Vector Search index.
	IndexEndpoint string `json:"index_endpoint,omitempty"`

	// Index is the name of the Vector Search index.
	Index string `json:"index,omitempty"`
}

// Corpus represents a RAG corpus.
type Corpus struct {
	// Name is the resource name of the corpus.
	// Format: projects/{project}/locations/{location}/ragCorpora/{rag_corpus}
	Name string `json:"name,omitempty"`

	// DisplayName is the human-readable display name of the corpus.
	DisplayName string `json:"display_name,omitempty"`

	// Description is the description of the corpus.
	Description string `json:"description,omitempty"`

	// BackendConfig is the backend configuration for the corpus.
	BackendConfig *VectorDbConfig `json:"backend_config,omitempty"`

	// CreateTime is the timestamp when the corpus was created.
	CreateTime *time.Time `json:"create_time,omitempty"`

	// UpdateTime is the timestamp when the corpus was last updated.
	UpdateTime *time.Time `json:"update_time,omitempty"`

	// State is the current state of the corpus.
	State CorpusState `json:"state,omitempty"`
}

// RagFile represents a file in a RAG corpus.
type RagFile struct {
	// Name is the resource name of the file.
	// Format: projects/{project}/locations/{location}/ragCorpora/{rag_corpus}/ragFiles/{rag_file}
	Name string `json:"name,omitempty"`

	// DisplayName is the human-readable display name of the file.
	DisplayName string `json:"display_name,omitempty"`

	// Description is the description of the file.
	Description string `json:"description,omitempty"`

	// RagFileSource is the source of the file.
	RagFileSource *RagFileSource `json:"rag_file_source,omitempty"`

	// CreateTime is the timestamp when the file was created.
	CreateTime *time.Time `json:"create_time,omitempty"`

	// UpdateTime is the timestamp when the file was last updated.
	UpdateTime *time.Time `json:"update_time,omitempty"`

	// State is the current state of the file.
	State FileState `json:"state,omitempty"`

	// SizeBytes is the size of the file in bytes.
	SizeBytes int64 `json:"size_bytes,omitempty"`

	// RagFileType is the type of the RAG file.
	RagFileType string `json:"rag_file_type,omitempty"`
}

// RagFileSource represents the source of a RAG file.
type RagFileSource struct {
	// GcsSource is the Google Cloud Storage source.
	GcsSource *GcsSource `json:"gcs_source,omitempty"`

	// GoogleDriveSource is the Google Drive source.
	GoogleDriveSource *GoogleDriveSource `json:"google_drive_source,omitempty"`

	// DirectUploadSource is the direct upload source.
	DirectUploadSource *DirectUploadSource `json:"direct_upload_source,omitempty"`
}

// GcsSource represents a Google Cloud Storage source.
type GcsSource struct {
	// Uris are the Cloud Storage URIs.
	Uris []string `json:"uris,omitempty"`
}

// GoogleDriveSource represents a Google Drive source.
type GoogleDriveSource struct {
	// ResourceIds are the Google Drive resource IDs.
	ResourceIds []string `json:"resource_ids,omitempty"`
}

// DirectUploadSource represents a direct upload source.
type DirectUploadSource struct{}

// ImportFilesRequest represents a request to import files into a corpus.
type ImportFilesRequest struct {
	// Parent is the name of the corpus to import files into.
	// Format: projects/{project}/locations/{location}/ragCorpora/{rag_corpus}
	Parent string `json:"parent,omitempty"`

	// ImportFilesConfig is the configuration for importing files.
	ImportFilesConfig *ImportFilesConfig `json:"import_files_config,omitempty"`
}

// ImportFilesConfig represents the configuration for importing files.
type ImportFilesConfig struct {
	// GcsSource is the Google Cloud Storage source.
	GcsSource *GcsSource `json:"gcs_source,omitempty"`

	// GoogleDriveSource is the Google Drive source.
	GoogleDriveSource *GoogleDriveSource `json:"google_drive_source,omitempty"`

	// ChunkSize is the chunk size for processing files.
	ChunkSize int32 `json:"chunk_size,omitempty"`

	// ChunkOverlap is the overlap between chunks.
	ChunkOverlap int32 `json:"chunk_overlap,omitempty"`

	// MaxEmbeddingRequestsPerMin is the maximum embedding requests per minute.
	MaxEmbeddingRequestsPerMin int32 `json:"max_embedding_requests_per_min,omitempty"`
}

// RetrievalQuery represents a query for retrieving documents from a corpus.
type RetrievalQuery struct {
	// Text is the query text.
	Text string `json:"text,omitempty"`

	// SimilarityTopK is the number of top similar documents to retrieve.
	SimilarityTopK int32 `json:"similarity_top_k,omitempty"`

	// VectorDistanceThreshold is the distance threshold for similarity.
	VectorDistanceThreshold float64 `json:"vector_distance_threshold,omitempty"`
}

// RetrievedDocument represents a retrieved document from a corpus.
type RetrievedDocument struct {
	// Id is the document ID.
	Id string `json:"id,omitempty"`

	// Content is the document content.
	Content string `json:"content,omitempty"`

	// Distance is the similarity distance.
	Distance float64 `json:"distance,omitempty"`

	// Metadata contains additional metadata about the document.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// RetrievalResponse represents the response from a retrieval query.
type RetrievalResponse struct {
	// Documents are the retrieved documents.
	Documents []*RetrievedDocument `json:"documents,omitempty"`
}

// CreateCorpusRequest represents a request to create a corpus.
type CreateCorpusRequest struct {
	// Parent is the parent resource name.
	// Format: projects/{project}/locations/{location}
	Parent string `json:"parent,omitempty"`

	// Corpus is the corpus to create.
	Corpus *Corpus `json:"corpus,omitempty"`
}

// ListCorporaRequest represents a request to list corpora.
type ListCorporaRequest struct {
	// Parent is the parent resource name.
	// Format: projects/{project}/locations/{location}
	Parent string `json:"parent,omitempty"`

	// PageSize is the maximum number of corpora to return.
	PageSize int32 `json:"page_size,omitempty"`

	// PageToken is the token for pagination.
	PageToken string `json:"page_token,omitempty"`
}

// ListCorporaResponse represents the response from listing corpora.
type ListCorporaResponse struct {
	// RagCorpora are the RAG corpora.
	RagCorpora []*Corpus `json:"rag_corpora,omitempty"`

	// NextPageToken is the token for the next page.
	NextPageToken string `json:"next_page_token,omitempty"`
}

// GetCorpusRequest represents a request to get a corpus.
type GetCorpusRequest struct {
	// Name is the resource name of the corpus.
	// Format: projects/{project}/locations/{location}/ragCorpora/{rag_corpus}
	Name string `json:"name,omitempty"`
}

// DeleteCorpusRequest represents a request to delete a corpus.
type DeleteCorpusRequest struct {
	// Name is the resource name of the corpus.
	// Format: projects/{project}/locations/{location}/ragCorpora/{rag_corpus}
	Name string `json:"name,omitempty"`

	// Force indicates whether to forcefully delete the corpus.
	Force bool `json:"force,omitempty"`
}

// ListFilesRequest represents a request to list files in a corpus.
type ListFilesRequest struct {
	// Parent is the parent corpus name.
	// Format: projects/{project}/locations/{location}/ragCorpora/{rag_corpus}
	Parent string `json:"parent,omitempty"`

	// PageSize is the maximum number of files to return.
	PageSize int32 `json:"page_size,omitempty"`

	// PageToken is the token for pagination.
	PageToken string `json:"page_token,omitempty"`
}

// ListFilesResponse represents the response from listing files.
type ListFilesResponse struct {
	// RagFiles are the RAG files.
	RagFiles []*RagFile `json:"rag_files,omitempty"`

	// NextPageToken is the token for the next page.
	NextPageToken string `json:"next_page_token,omitempty"`
}

// DeleteFileRequest represents a request to delete a file.
type DeleteFileRequest struct {
	// Name is the resource name of the file.
	// Format: projects/{project}/locations/{location}/ragCorpora/{rag_corpus}/ragFiles/{rag_file}
	Name string `json:"name,omitempty"`
}

// UploadFileRequest represents a request to upload a file.
type UploadFileRequest struct {
	// Parent is the parent corpus name.
	// Format: projects/{project}/locations/{location}/ragCorpora/{rag_corpus}
	Parent string `json:"parent,omitempty"`

	// RagFile is the file to upload.
	RagFile *RagFile `json:"rag_file,omitempty"`

	// UploadRagFileConfig is the configuration for uploading the file.
	UploadRagFileConfig *UploadRagFileConfig `json:"upload_rag_file_config,omitempty"`
}

// UploadRagFileConfig represents the configuration for uploading a RAG file.
type UploadRagFileConfig struct {
	// ChunkSize is the chunk size for processing the file.
	ChunkSize int32 `json:"chunk_size,omitempty"`

	// ChunkOverlap is the overlap between chunks.
	ChunkOverlap int32 `json:"chunk_overlap,omitempty"`

	// MaxEmbeddingRequestsPerMin is the maximum embedding requests per minute.
	MaxEmbeddingRequestsPerMin int32 `json:"max_embedding_requests_per_min,omitempty"`
}
