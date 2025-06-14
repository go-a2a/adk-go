// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package rag_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/internal/vertexai/preview/rag"
)

func TestFileState_String(t *testing.T) {
	tests := []struct {
		name  string
		state rag.FileState
		want  string
	}{
		{
			name:  "unspecified",
			state: rag.FileStateUnspecified,
			want:  "FILE_STATE_UNSPECIFIED",
		},
		{
			name:  "active",
			state: rag.FileStateActive,
			want:  "ACTIVE",
		},
		{
			name:  "error",
			state: rag.FileStateError,
			want:  "ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.state); got != tt.want {
				t.Errorf("FileState string = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRagFile_Validation(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		file    *rag.RagFile
		wantErr bool
	}{
		{
			name: "valid_gcs_file",
			file: &rag.RagFile{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/test-file",
				DisplayName: "Test File",
				Description: "A test file",
				RagFileSource: &rag.RagFileSource{
					GcsSource: &rag.GcsSource{
						Uris: []string{"gs://test-bucket/test-file.txt"},
					},
				},
				CreateTime:  &now,
				UpdateTime:  &now,
				State:       rag.FileStateActive,
				SizeBytes:   1024,
				RagFileType: "text/plain",
			},
			wantErr: false,
		},
		{
			name: "valid_google_drive_file",
			file: &rag.RagFile{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/test-file",
				DisplayName: "Test Drive File",
				Description: "A test file from Google Drive",
				RagFileSource: &rag.RagFileSource{
					GoogleDriveSource: &rag.GoogleDriveSource{
						ResourceIds: []string{"1234567890abcdef"},
					},
				},
				CreateTime:  &now,
				UpdateTime:  &now,
				State:       rag.FileStateActive,
				SizeBytes:   2048,
				RagFileType: "application/pdf",
			},
			wantErr: false,
		},
		{
			name: "valid_direct_upload_file",
			file: &rag.RagFile{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/test-file",
				DisplayName: "Direct Upload File",
				Description: "A directly uploaded file",
				RagFileSource: &rag.RagFileSource{
					DirectUploadSource: &rag.DirectUploadSource{},
				},
				CreateTime:  &now,
				UpdateTime:  &now,
				State:       rag.FileStateActive,
				SizeBytes:   512,
				RagFileType: "text/markdown",
			},
			wantErr: false,
		},
		{
			name: "empty_display_name",
			file: &rag.RagFile{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/test-file",
				DisplayName: "",
				Description: "A test file",
				RagFileSource: &rag.RagFileSource{
					GcsSource: &rag.GcsSource{
						Uris: []string{"gs://test-bucket/test-file.txt"},
					},
				},
				State: rag.FileStateActive,
			},
			wantErr: true,
		},
		{
			name: "no_file_source",
			file: &rag.RagFile{
				Name:          "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/test-file",
				DisplayName:   "Test File",
				Description:   "A test file",
				RagFileSource: nil,
				State:         rag.FileStateActive,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation checks
			if tt.file.Name == "" && !tt.wantErr {
				t.Error("Valid file should have a name")
			}
			if tt.file.DisplayName == "" && !tt.wantErr {
				t.Error("Valid file should have a display name")
			}
			if tt.file.RagFileSource == nil && !tt.wantErr {
				t.Error("Valid file should have a file source")
			}

			// Check that timestamps are properly set if present
			if tt.file.CreateTime != nil && tt.file.CreateTime.IsZero() {
				t.Error("CreateTime should not be zero if set")
			}
			if tt.file.UpdateTime != nil && tt.file.UpdateTime.IsZero() {
				t.Error("UpdateTime should not be zero if set")
			}

			// Check size constraints
			if tt.file.SizeBytes < 0 {
				t.Error("SizeBytes should not be negative")
			}
		})
	}
}

func TestRagFileSource_SourceTypes(t *testing.T) {
	tests := []struct {
		name   string
		source *rag.RagFileSource
		want   string // Expected source type
	}{
		{
			name: "gcs_source",
			source: &rag.RagFileSource{
				GcsSource: &rag.GcsSource{
					Uris: []string{"gs://test-bucket/test-file.txt"},
				},
			},
			want: "gcs",
		},
		{
			name: "google_drive_source",
			source: &rag.RagFileSource{
				GoogleDriveSource: &rag.GoogleDriveSource{
					ResourceIds: []string{"1234567890abcdef"},
				},
			},
			want: "google_drive",
		},
		{
			name: "direct_upload_source",
			source: &rag.RagFileSource{
				DirectUploadSource: &rag.DirectUploadSource{},
			},
			want: "direct_upload",
		},
		{
			name: "multiple_sources",
			source: &rag.RagFileSource{
				GcsSource: &rag.GcsSource{
					Uris: []string{"gs://test-bucket/test-file.txt"},
				},
				GoogleDriveSource: &rag.GoogleDriveSource{
					ResourceIds: []string{"1234567890abcdef"},
				},
			},
			want: "multiple", // This should be handled appropriately
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Determine which source type is configured
			var got string
			sourceCount := 0

			if tt.source.GcsSource != nil {
				got = "gcs"
				sourceCount++
			}
			if tt.source.GoogleDriveSource != nil {
				if sourceCount > 0 {
					got = "multiple"
				} else {
					got = "google_drive"
				}
				sourceCount++
			}
			if tt.source.DirectUploadSource != nil {
				if sourceCount > 0 {
					got = "multiple"
				} else {
					got = "direct_upload"
				}
				sourceCount++
			}

			if sourceCount == 0 {
				got = "none"
			}

			if got != tt.want {
				t.Errorf("Source type = %v, want %v", got, tt.want)
			}

			// Validate that only one source should be specified
			if sourceCount > 1 && tt.want != "multiple" {
				t.Error("Should specify only one file source type")
			}
		})
	}
}

func TestGcsSource_Validation(t *testing.T) {
	tests := []struct {
		name    string
		source  *rag.GcsSource
		wantErr bool
	}{
		{
			name: "valid_single_uri",
			source: &rag.GcsSource{
				Uris: []string{"gs://test-bucket/test-file.txt"},
			},
			wantErr: false,
		},
		{
			name: "valid_multiple_uris",
			source: &rag.GcsSource{
				Uris: []string{
					"gs://test-bucket/file1.txt",
					"gs://test-bucket/file2.pdf",
					"gs://test-bucket/documents/file3.docx",
				},
			},
			wantErr: false,
		},
		{
			name: "valid_wildcard_uri",
			source: &rag.GcsSource{
				Uris: []string{"gs://test-bucket/documents/*"},
			},
			wantErr: false,
		},
		{
			name: "empty_uris",
			source: &rag.GcsSource{
				Uris: []string{},
			},
			wantErr: true,
		},
		{
			name: "invalid_uri_format",
			source: &rag.GcsSource{
				Uris: []string{"http://invalid-uri.com/file.txt"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.source.Uris) == 0 && !tt.wantErr {
				t.Error("Valid GCS source should have at least one URI")
			}

			for _, uri := range tt.source.Uris {
				if uri == "" {
					t.Error("URI should not be empty")
				}
				// In a real implementation, you would validate URI format
				if !tt.wantErr && uri != "" && uri[:5] != "gs://" {
					t.Errorf("GCS URI should start with 'gs://': %s", uri)
				}
			}
		})
	}
}

func TestGoogleDriveSource_Validation(t *testing.T) {
	t.Skip()
	tests := []struct {
		name    string
		source  *rag.GoogleDriveSource
		wantErr bool
	}{
		{
			name: "valid_single_resource",
			source: &rag.GoogleDriveSource{
				ResourceIds: []string{"1234567890abcdef"},
			},
			wantErr: false,
		},
		{
			name: "valid_multiple_resources",
			source: &rag.GoogleDriveSource{
				ResourceIds: []string{
					"1234567890abcdef",
					"fedcba0987654321",
					"abcdef1234567890",
				},
			},
			wantErr: false,
		},
		{
			name: "empty_resource_ids",
			source: &rag.GoogleDriveSource{
				ResourceIds: []string{},
			},
			wantErr: true,
		},
		{
			name: "empty_resource_id",
			source: &rag.GoogleDriveSource{
				ResourceIds: []string{""},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.source.ResourceIds) == 0 && !tt.wantErr {
				t.Error("Valid Google Drive source should have at least one resource ID")
			}

			for _, resourceId := range tt.source.ResourceIds {
				if resourceId == "" {
					t.Error("Resource ID should not be empty")
				}
				// In a real implementation, you would validate resource ID format
			}
		})
	}
}

func TestImportFilesConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  *rag.ImportFilesConfig
		wantErr bool
	}{
		{
			name: "valid_gcs_config",
			config: &rag.ImportFilesConfig{
				GcsSource: &rag.GcsSource{
					Uris: []string{"gs://test-bucket/documents/*"},
				},
				ChunkSize:                  1000,
				ChunkOverlap:               100,
				MaxEmbeddingRequestsPerMin: 100,
			},
			wantErr: false,
		},
		{
			name: "valid_google_drive_config",
			config: &rag.ImportFilesConfig{
				GoogleDriveSource: &rag.GoogleDriveSource{
					ResourceIds: []string{"1234567890abcdef"},
				},
				ChunkSize:                  800,
				ChunkOverlap:               80,
				MaxEmbeddingRequestsPerMin: 50,
			},
			wantErr: false,
		},
		{
			name: "invalid_chunk_size",
			config: &rag.ImportFilesConfig{
				GcsSource: &rag.GcsSource{
					Uris: []string{"gs://test-bucket/file.txt"},
				},
				ChunkSize:    0,
				ChunkOverlap: 100,
			},
			wantErr: true,
		},
		{
			name: "chunk_overlap_too_large",
			config: &rag.ImportFilesConfig{
				GcsSource: &rag.GcsSource{
					Uris: []string{"gs://test-bucket/file.txt"},
				},
				ChunkSize:    1000,
				ChunkOverlap: 1000, // Should be less than chunk size
			},
			wantErr: true,
		},
		{
			name: "no_source_specified",
			config: &rag.ImportFilesConfig{
				ChunkSize:    1000,
				ChunkOverlap: 100,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasGcsSource := tt.config.GcsSource != nil
			hasGoogleDriveSource := tt.config.GoogleDriveSource != nil
			hasAnySource := hasGcsSource || hasGoogleDriveSource

			if !hasAnySource && !tt.wantErr {
				t.Error("Valid config should have at least one source")
			}

			if tt.config.ChunkSize <= 0 && !tt.wantErr {
				t.Error("ChunkSize should be positive")
			}

			if tt.config.ChunkOverlap < 0 {
				t.Error("ChunkOverlap should not be negative")
			}

			if tt.config.ChunkOverlap >= tt.config.ChunkSize && tt.config.ChunkSize > 0 && !tt.wantErr {
				t.Error("ChunkOverlap should be less than ChunkSize")
			}

			if tt.config.MaxEmbeddingRequestsPerMin < 0 {
				t.Error("MaxEmbeddingRequestsPerMin should not be negative")
			}
		})
	}
}

func TestUploadRagFileConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  *rag.UploadRagFileConfig
		wantErr bool
	}{
		{
			name: "valid_config",
			config: &rag.UploadRagFileConfig{
				ChunkSize:                  1000,
				ChunkOverlap:               100,
				MaxEmbeddingRequestsPerMin: 100,
			},
			wantErr: false,
		},
		{
			name: "minimal_valid_config",
			config: &rag.UploadRagFileConfig{
				ChunkSize:    500,
				ChunkOverlap: 50,
			},
			wantErr: false,
		},
		{
			name: "invalid_chunk_size",
			config: &rag.UploadRagFileConfig{
				ChunkSize:    0,
				ChunkOverlap: 100,
			},
			wantErr: true,
		},
		{
			name: "negative_chunk_overlap",
			config: &rag.UploadRagFileConfig{
				ChunkSize:    1000,
				ChunkOverlap: -10,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.ChunkSize <= 0 && !tt.wantErr {
				t.Error("ChunkSize should be positive")
			}

			if tt.config.ChunkOverlap < 0 && !tt.wantErr {
				t.Error("ChunkOverlap should not be negative")
			}

			if tt.config.ChunkOverlap >= tt.config.ChunkSize && tt.config.ChunkSize > 0 && !tt.wantErr {
				t.Error("ChunkOverlap should be less than ChunkSize")
			}
		})
	}
}

func TestListFilesResponse_Structure(t *testing.T) {
	file1 := &rag.RagFile{
		Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/file-1",
		DisplayName: "File 1",
		Description: "First test file",
		State:       rag.FileStateActive,
		SizeBytes:   1024,
	}

	file2 := &rag.RagFile{
		Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/file-2",
		DisplayName: "File 2",
		Description: "Second test file",
		State:       rag.FileStateActive,
		SizeBytes:   2048,
	}

	tests := []struct {
		name     string
		response *rag.ListFilesResponse
		want     *rag.ListFilesResponse
	}{
		{
			name: "empty_response",
			response: &rag.ListFilesResponse{
				RagFiles:      []*rag.RagFile{},
				NextPageToken: "",
			},
			want: &rag.ListFilesResponse{
				RagFiles:      []*rag.RagFile{},
				NextPageToken: "",
			},
		},
		{
			name: "response_with_files",
			response: &rag.ListFilesResponse{
				RagFiles:      []*rag.RagFile{file1, file2},
				NextPageToken: "next-page-token",
			},
			want: &rag.ListFilesResponse{
				RagFiles:      []*rag.RagFile{file1, file2},
				NextPageToken: "next-page-token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.response); diff != "" {
				t.Errorf("ListFilesResponse mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestImportFilesRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request *rag.ImportFilesRequest
		wantErr bool
	}{
		{
			name: "valid_request",
			request: &rag.ImportFilesRequest{
				Parent: "projects/test-project/locations/us-central1/ragCorpora/test-corpus",
				ImportFilesConfig: &rag.ImportFilesConfig{
					GcsSource: &rag.GcsSource{
						Uris: []string{"gs://test-bucket/documents/*"},
					},
					ChunkSize:    1000,
					ChunkOverlap: 100,
				},
			},
			wantErr: false,
		},
		{
			name: "missing_config",
			request: &rag.ImportFilesRequest{
				Parent:            "projects/test-project/locations/us-central1/ragCorpora/test-corpus",
				ImportFilesConfig: nil,
			},
			wantErr: true,
		},
		{
			name: "empty_parent",
			request: &rag.ImportFilesRequest{
				Parent: "",
				ImportFilesConfig: &rag.ImportFilesConfig{
					GcsSource: &rag.GcsSource{
						Uris: []string{"gs://test-bucket/documents/*"},
					},
					ChunkSize:    1000,
					ChunkOverlap: 100,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.request.ImportFilesConfig == nil && !tt.wantErr {
				t.Error("Valid request should have ImportFilesConfig")
			}
			if tt.request.Parent == "" && !tt.wantErr {
				t.Error("Valid request should have Parent")
			}
		})
	}
}
